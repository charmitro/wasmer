use super::*;
use crate::wasi_exports_generic;
use crate::wasi_snapshot_preview1_exports;
use crate::wasi_unstable_exports;
use crate::wasix_exports_32;
use crate::wasix_exports_64;
use crate::WasiEnvBuilder;
use crate::WasiVersion;
use crate::{generate_import_object_from_env, syscalls::*};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Instrument;
use wasmer::imports;
use wasmer::namespace;
use wasmer::AsEngineRef;
use wasmer::AsStoreRef;
use wasmer::FromToNativeWasmType;
use wasmer::FunctionEnv;
use wasmer::Imports;
use wasmer::Table;
use wasmer_types::ExportType;
use wasmer_types::TableType;
use wasmer_types::Type;
use wasmer_wasix_types::wasi::DlFlags;
use wasmer_wasix_types::wasi::DlHandle;

/// Opens a dynamic library from the filesystem.
///
/// # Parameters
/// - `ctx`: The WASI environment context
/// - `path_ptr`: Pointer to the path string in WASM memory
/// - `path_len`: Length of the path string
/// - `flags`: Dynamic linking flags (currently only RTLD_NOW is supported)
/// - `handle_ptr`: Pointer to store the returned handle
///
/// # Returns
/// - `Errno::Success`: The library was successfully loaded
/// - `Errno::Inval`: Invalid parameters were provided
/// - Other `Errno` values for various errors
#[instrument(level = "trace", skip_all, ret)]
pub fn dlopen<'a, M: MemorySize + 'static>(
    mut ctx: FunctionEnvMut<WasiEnv>,
    path_ptr: WasmPtr<u8, M>,
    path_len: M::Offset,
    flags: i32,
    handle_ptr: WasmPtr<DlHandle, M>,
) -> Result<Errno, WasiError> {
    wasi_try_ok!(WasiEnv::process_signals_and_exit(&mut ctx)?);
    ctx = wasi_try_ok!(maybe_backoff::<M>(ctx)?);
    ctx = wasi_try_ok!(maybe_snapshot::<M>(ctx)?);
    let dl_flags = DlFlags::from_native(flags);
    if dl_flags != DlFlags::Now {
        println!(
            "dlopen: Only RTLD_NOW is supported, received: {:?}",
            dl_flags
        );
        return Ok(Errno::Notsup);
    }

    // Extract the path
    let path = {
        let env = ctx.data();
        let memory = unsafe { env.memory_view(&ctx) };
        match path_ptr.read_utf8_string(&memory, path_len) {
            Ok(p) => p,
            Err(e) => {
                println!("Failed to read path: {:?}", e);
                return Ok(Errno::Inval);
            }
        }
    };

    // Load the module
    let wasm_bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Errno::Io),
    };

    let handle = {
        let ctx_ref = ctx.as_ref();
        let (mut env, mut store) = ctx.data_and_store_mut();

        let module = match Module::from_binary(store.engine(), &wasm_bytes) {
            Ok(m) => m,
            Err(_) => return Ok(Errno::Inval),
        };

        // Create imports
        let exports_wasi_generic = wasi_exports_generic(&mut store, &ctx_ref);
        let exports_wasi_unstable = wasi_unstable_exports(&mut store, &ctx_ref);
        let exports_wasi_snapshot_preview1 = wasi_snapshot_preview1_exports(&mut store, &ctx_ref);
        let exports_wasix_32v1 = wasix_exports_32(&mut store, &ctx_ref);
        let exports_wasix_64v1 = wasix_exports_64(&mut store, &ctx_ref);

        let wasi_imports = imports! {
            "wasi" => exports_wasi_generic,
            "wasi_unstable" => exports_wasi_unstable,
            "wasi_snapshot_preview1" => exports_wasi_snapshot_preview1,
            "wasix_32v1" => exports_wasix_32v1,
            "wasix_64v1" => exports_wasix_64v1,
        };

        // Create the instance with WASI imports
        let instance = match Instance::new(&mut store, &module, &wasi_imports) {
            Ok(i) => i,
            Err(_) => return Ok(Errno::Inval),
        };

        // Add module without running constructors yet
        let dl_state = &env.state.dl;
        let handle = dl_state.add_module(instance.clone());

        // If constructors exist on `instance`, switch to that and run them.
        if let Ok(ctors) = instance.exports.get_function("__wasm_call_ctors") {
            let env_inner = match env.try_inner_mut() {
                Some(inner) => inner,
                None => return Ok(Errno::Inval),
            };
            let mut original_handles = env_inner.clone();

            // Get the new memory and create temporary handles for constructor execution
            let new_memory = match instance.exports.get_memory("memory") {
                Ok(m) => m.clone(),
                Err(_) => return Ok(Errno::Inval),
            };

            // Create temporary handles for constructor execution
            let temp_handles =
                WasiInstanceHandles::new(new_memory.clone(), &mut store, instance.clone());

            // Switch to temporary handles, run constructors, then restore original
            env.set_inner(temp_handles);
            if let Err(_) = ctors.call(&mut store, &[]) {
                return Ok(Errno::Inval);
            }

            env.set_inner(original_handles);
        };

        handle
    };

    // Write handle back to WASM after all mutable borrows are dropped
    let env = ctx.data();
    let memory = unsafe { env.memory_view(&ctx) };
    if let Err(_) = handle_ptr.write(&memory, handle) {
        return Ok(Errno::Inval);
    }

    Ok(Errno::Success)
}

/// Looks up a symbol in a loaded dynamic library.
///
/// # Parameters
/// - `ctx`: The WASI environment context
/// - `handle`: Handle to the loaded library
/// - `symbol_ptr`: Pointer to the symbol name string
/// - `symbol_len`: Length of the symbol name
/// - `ret_ptr`: Pointer to store the returned symbol value
///
/// # Returns
/// - `Errno::Success`: The symbol was found and returned
/// - `Errno::Inval`: Invalid parameters or symbol not found
#[instrument(level = "trace", skip_all, ret)]
pub fn dlsym<'a, M: MemorySize + 'static>(
    mut ctx: FunctionEnvMut<WasiEnv>,
    handle: DlHandle,
    symbol_ptr: WasmPtr<u8, M>,
    symbol_len: M::Offset,
    ret_ptr: WasmPtr<u64, M>,
) -> Result<Errno, Errno> {
    // Print inner instance of ctx
    let env = ctx.data();
    let inner = env.try_inner().ok_or(Errno::Inval)?;

    let value = {
        let (env, mut store) = ctx.data_and_store_mut();
        let dl_state = &env.state.dl;
        let symbol = {
            let memory = unsafe { env.memory_view(&store) };
            symbol_ptr
                .read_utf8_string(&memory, symbol_len)
                .map_err(|e| {
                    println!("Failed to read symbol name: {:?}", e);
                    Errno::Inval
                })?
        };

        // First try to get as a global
        if let Some(offset) = dl_state.get_symbol(handle, store, &symbol) {
            offset as u64
        } else {
            // Fall back to looking for a global
            return Ok(Errno::Inval);
        }
    };

    // Write value to ret_ptr
    let env = ctx.data();
    let memory = unsafe { env.memory_view(&ctx) };
    ret_ptr.write(&memory, value).map_err(|_| Errno::Inval)?;

    Ok(Errno::Success)
}

/// Closes a dynamic library.
///
/// # Parameters
/// - `ctx`: The WASI environment context
/// - `handle`: Handle to the library to close
///
/// # Returns
/// - `Errno::Success`: The library was successfully closed
/// - Other `Errno` values for errors
#[instrument(level = "trace", skip_all, ret)]
pub fn dlclose<'a>(ctx: FunctionEnvMut<'a, WasiEnv>, handle: DlHandle) -> Result<Errno, WasiError> {
    Ok(Errno::Success)
}

/// Gets error information about the last dynamic loading operation.
///
/// # Parameters
/// - `ctx`: The WASI environment context
/// - `buffer_ptr`: Pointer to write the error string
/// - `buffer_len`: Length of the buffer
/// - `nwritten`: Pointer to store number of bytes written
///
/// # Returns
/// - `Errno::Success`: The error information was successfully retrieved
/// - Other `Errno` values for errors
#[instrument(level = "trace", skip_all, ret)]
pub fn dlerror<'a, M: MemorySize + 'static>(
    ctx: FunctionEnvMut<'a, WasiEnv>,
    buffer_ptr: WasmPtr<u8, M>,
    buffer_len: M::Offset,
    nwritten: WasmPtr<M::Offset, M>,
) -> Result<Errno, WasiError> {
    Ok(Errno::Success)
}
