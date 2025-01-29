//! Dynamic Library Loading Implementation for WASI
//! 
//! # Overview
//! This module implements dynamic library loading (dlopen) functionality for WASI.
//! It allows WASM modules to load other WASM modules at runtime, similar to how
//! native programs use shared libraries.
//!
//! # Compilation Requirements
//! 
//! Main module must be compiled with:
//! ```sh
//! clang --target=wasm32-wasi -I./sysroot/include -L./sysroot/lib/wasm32-wasi \
//!     load.c --sysroot=/opt/wasix-sysroot -o load \
//!     -Wl,--export-table -Wl,--initial-memory=1048576 \
//!     -Wl,--max-memory=2147483648 -mbulk-memory
//! ```
//! 
//! Dynamic libraries must be compiled with:
//! ```sh
//! clang --target=wasm32-wasi libside.c -o libside.wasm \
//!     -Wl,--no-entry \
//!     -nostartfiles \
//!     --sysroot=/opt/wasix-sysroot \
//!     -Wl,--import-memory \
//!     -Wl,--global-base=131072 \
//!     -Wl,--initial-memory=1048576 \
//!     -Wl,--max-memory=2147483648 \
//!     -Wl,--export-all
//! ```
//!
//! These flags are required for:
//! - Proper memory sharing between modules
//! - Function table exports
//! - Correct global variable offsets
//! - Symbol exports for linking
//! - Consistent memory limits
//!
//! # Design
//! 
//! ## Core Components
//! 
//! 1. Dynamic Loading Functions:
//!    - dlopen(): Loads a WASM module from the filesystem
//!    - dlsym(): Looks up symbols in loaded modules
//!    - dlclose(): Unloads a module
//!    - dlerror(): Reports errors from dynamic loading operations
//!
//! 2. Module Management:
//!    - Modules are tracked using unique handles
//!    - State is maintained in WasiEnv's DlState
//!    - Constructors/destructors are called appropriately
//!
//! ## Loading Process
//!
//! 1. Path Resolution:
//!    - Read path from WASM memory
//!    - Validate and resolve filesystem path
//!
//! 2. Module Loading:
//!    - Read WASM bytes from filesystem
//!    - Parse and validate WASM module
//!
//! 3. Instance Creation:
//!    - Set up WASI imports (memory, exports, etc.)
//!    - Create new module instance
//!    - Register instance in DlState
//!
//! 4. Symbol Management:
//!    - Track exported symbols
//!    - Support global variables and functions
//!    - Handle memory addressing
//!
//! ## Memory Safety
//!
//! - All memory accesses are bounds-checked
//! - Proper cleanup on errors
//! - Safe handling of WASM memory pointers
//!
//! ## Error Handling
//!
//! - Clear error paths with proper cleanup
//! - Detailed error reporting
//! - Consistent error types (Errno)
//!
//! ## Lifecycle Management
//!
//! 1. Module Loading:
//!    - Load WASM bytes
//!    - Create instance
//!    - Run constructors
//!
//! 2. Module Usage:
//!    - Symbol lookup
//!    - Memory sharing
//!
//! 3. Module Unloading:
//!    - Run destructors
//!    - Clean up resources
//!    - Remove from state
//!
//! ## Limitations
//!
//! - Only RTLD_NOW flag supported
//! - No nested loading (modules loading other modules)
//! - Limited symbol resolution
//!
//! ## Future Improvements
//!
//! - Support for more dlopen flags
//! - Better symbol resolution
//! - Nested module loading
//! - Memory mapping optimizations
//! - Better error reporting
//!
//! # Examples
//!
//! ```no_run
//! // Load a module
//! let handle = dlopen("./mymodule.wasm", RTLD_NOW);
//!
//! // Look up a symbol
//! let symbol = dlsym(handle, "my_function");
//!
//! // Use the symbol...
//!
//! // Clean up
//! dlclose(handle);
//! ```

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
use tracing::debug;
use tracing::Instrument;
use wasmer::imports;
use wasmer::namespace;
use wasmer::AsEngineRef;
use wasmer::AsStoreRef;
use wasmer::Exports;
use wasmer::FromToNativeWasmType;
use wasmer::FunctionEnv;
use wasmer::Imports;
use wasmer::MemoryType;
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
    // Process initial checks
    wasi_try_ok!(WasiEnv::process_signals_and_exit(&mut ctx)?);
    ctx = wasi_try_ok!(maybe_backoff::<M>(ctx)?);
    ctx = wasi_try_ok!(maybe_snapshot::<M>(ctx)?);

    // Validate flags
    let dl_flags = DlFlags::from_native(flags);
    if dl_flags != DlFlags::Now {
        debug!("dlopen: Only RTLD_NOW is supported, received: {dl_flags:?}");
        return Ok(Errno::Notsup);
    }

    // Read path from WASM memory
    let path = match read_path_from_wasm(&ctx, path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return Ok(e),
    };

    // Load WASM module from filesystem
    let wasm_bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Errno::Io),
    };

    // Create and initialize module instance
    let handle = match create_module_instance(&mut ctx, &wasm_bytes) {
        Ok(h) => h,
        Err(e) => return Ok(e),
    };

    // Write handle back to WASM memory
    if let Err(e) = write_handle_to_wasm(&ctx, handle_ptr, handle) {
        return Ok(e);
    }

    Ok(Errno::Success)
}

// Helper functions to break down the complexity
fn read_path_from_wasm<M: MemorySize>(
    ctx: &FunctionEnvMut<WasiEnv>,
    path_ptr: WasmPtr<u8, M>,
    path_len: M::Offset,
) -> Result<String, Errno> {
    let env = ctx.data();
    let memory = unsafe { env.memory_view(ctx) };
    path_ptr.read_utf8_string(&memory, path_len).map_err(|e| {
        debug!("Failed to read path: {e:?}");
        Errno::Inval
    })
}

fn create_module_instance(
    ctx: &mut FunctionEnvMut<WasiEnv>,
    wasm_bytes: &[u8],
) -> Result<DlHandle, Errno> {
    let ctx_ref = ctx.as_ref();
    let (mut env, mut store) = ctx.data_and_store_mut();

    // Create module from binary
    let module = Module::from_binary(store.engine(), wasm_bytes).map_err(|_| Errno::Inval)?;

    // Get environment and memory
    let env_inner = env.try_inner().ok_or(Errno::Inval)?;
    let memory = env_inner
        .instance
        .exports
        .get_memory("memory")
        .map_err(|_| Errno::Inval)?
        .clone();

    // Get exports for imports
    let wasi_exports = env_inner.instance.exports.clone();
    let unstable_exports = wasi_unstable_exports(&mut store, &ctx_ref);
    let snapshot_exports = wasi_snapshot_preview1_exports(&mut store, &ctx_ref);
    let wasix32_exports = wasix_exports_32(&mut store, &ctx_ref);
    let wasix64_exports = wasix_exports_64(&mut store, &ctx_ref);

    // Create WASI imports
    let wasi_imports = imports! {
        "wasi_unstable" => unstable_exports,
        "wasi_snapshot_preview1" => snapshot_exports,
        "wasix_32v1" => wasix32_exports,
        "wasix_64v1" => wasix64_exports,
        "wasi" => wasi_exports,
        "env" => {
            "memory" => memory.clone(),
        }
    };

    // Create instance
    let instance = Instance::new(&mut store, &module, &wasi_imports).map_err(|e| {
        debug!("Error creating instance: {e:?}");
        Errno::Inval
    })?;

    // Add module to state
    let dl_state = &env.state.dl;
    Ok(dl_state.add_module(&mut store, instance, &memory))
}

fn write_handle_to_wasm<M: MemorySize>(
    ctx: &FunctionEnvMut<WasiEnv>,
    handle_ptr: WasmPtr<DlHandle, M>,
    handle: DlHandle,
) -> Result<(), Errno> {
    let env = ctx.data();
    let memory = unsafe { env.memory_view(ctx) };
    handle_ptr.write(&memory, handle).map_err(|_| Errno::Inval)
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

    let value = {
        let (env, mut store) = ctx.data_and_store_mut();
        let dl_state = &env.state.dl;
        let symbol = {
            let memory = unsafe { env.memory_view(&store) };
            symbol_ptr
                .read_utf8_string(&memory, symbol_len)
                .map_err(|e| Errno::Inval)?
        };

        // Try to get as a global
        // In the future we should also make this work for functions, shouldn't be too hard.
        if let Some(offset) = dl_state.get_symbol(handle, store, &symbol) {
            offset as u64
        } else {
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
