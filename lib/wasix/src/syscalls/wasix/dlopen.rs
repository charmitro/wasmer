use super::*;
use crate::wasi_exports_generic;
use crate::wasi_snapshot_preview1_exports;
use crate::wasi_unstable_exports;
use crate::wasix_exports_32;
use crate::wasix_exports_64;
use crate::WasiVersion;
use crate::{generate_import_object_from_env, syscalls::*};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use wasmer::imports;
use wasmer::AsEngineRef;
use wasmer::AsStoreRef;
use wasmer::FromToNativeWasmType;
use wasmer::FunctionEnv;
use wasmer::Imports;
use wasmer_wasix_types::wasi::DlFlags;
use wasmer_wasix_types::wasi::DlHandle;

#[instrument(level = "trace", skip_all, ret)]
pub fn dlopen<'a, M: MemorySize + 'static>(
    mut ctx: FunctionEnvMut<WasiEnv>,
    path_ptr: WasmPtr<u8, M>,
    path_len: M::Offset,
    flags: i32,
    handle_ptr: WasmPtr<DlHandle, M>,
) -> Result<Errno, Errno> {
    let dl_flags = DlFlags::from_native(flags);

    // Ensure only RTLD_NOW is allowed
    if dl_flags != DlFlags::Now {
        println!(
            "dlopen: Only RTLD_NOW is supported, received: {:?}",
            dl_flags
        );
        return Ok(Errno::Inval);
    }

    // Extract the path
    let path = {
        let env = ctx.data();
        let memory = unsafe { env.memory_view(&ctx) }; // Extract memory view here
        path_ptr.read_utf8_string(&memory, path_len).map_err(|e| {
            println!("Failed to read path: {:?}", e);
            Errno::Inval
        })?
    };
    println!("{}", path);

    // Load the module
    let wasm_bytes = std::fs::read(path).expect("Failed to read wasm file");
    let mut store = ctx.as_store_mut();
    let module = Module::from_binary(store.engine(), &wasm_bytes).unwrap();

    // Create imports before mutable borrow of `ctx`
    let ctx_ref = ctx.as_ref();
    let (mut env, mut store) = ctx.data_and_store_mut();
    let dl_state = &env.state.dl;

    // Create imports - is this ok?!
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

    // Create the instance
    let instance = Instance::new(&mut store, &module, &wasi_imports).unwrap();

    // Add the module to `dl_state`
    let handle = dl_state.add_module(module, instance);

    // Write handle to `handle_ptr`
    let env = ctx.data();
    let memory = unsafe { env.memory_view(&ctx) };
    handle_ptr
        .write(&memory, handle)
        .map_err(|_| Errno::Inval)?;

    Ok(Errno::Success)
}

#[instrument(level = "trace", skip_all, ret)]
pub fn dlsym<'a, M: MemorySize + 'static>(
    mut ctx: FunctionEnvMut<WasiEnv>,
    handle: DlHandle,
    symbol_ptr: WasmPtr<u8, M>,
    symbol_len: M::Offset,
    ret_ptr: WasmPtr<u64, M>,
) -> Result<Errno, Errno> {
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
    ret_ptr.write(&memory, value).unwrap();

    Ok(Errno::Success)
}

#[instrument(level = "trace", skip_all, ret)]
pub fn dlclose<'a>(ctx: FunctionEnvMut<'a, WasiEnv>, handle: DlHandle) -> Result<Errno, WasiError> {
    Ok(Errno::Success)
}

#[instrument(level = "trace", skip_all, ret)]
pub fn dlerror<'a, M: MemorySize + 'static>(
    ctx: FunctionEnvMut<'a, WasiEnv>,
    buffer_ptr: WasmPtr<u8, M>,
    buffer_len: M::Offset,
    nwritten: WasmPtr<M::Offset, M>,
) -> Result<Errno, WasiError> {
    Ok(Errno::Success)
}
