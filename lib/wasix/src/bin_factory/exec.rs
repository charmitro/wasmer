use std::sync::Arc;

use crate::{
    os::task::{
        thread::{RewindResultType, WasiThreadRunGuard},
        TaskJoinHandle,
    },
    runtime::{
        task_manager::{
            TaskWasm, TaskWasmRecycle, TaskWasmRecycleProperties, TaskWasmRunProperties,
        },
        TaintReason,
    },
    syscalls::rewind_ext,
    RewindState, SpawnError, WasiError, WasiRuntimeError,
};
use tracing::*;
use wasmer::{Function, Memory32, Memory64, Module, Store};
use wasmer_wasix_types::wasi::Errno;

use super::BinaryPackage;
use crate::{Runtime, WasiEnv, WasiFunctionEnv};

#[tracing::instrument(level = "trace", skip_all, fields(%name, package_id=%binary.id))]
pub async fn spawn_exec(
    binary: BinaryPackage,
    name: &str,
    env: WasiEnv,
    runtime: &Arc<dyn Runtime + Send + Sync + 'static>,
) -> Result<TaskJoinHandle, SpawnError> {
    spawn_union_fs(&env, &binary).await?;

    let wasm = spawn_load_wasm(&env, &binary, name).await?;

    let module = spawn_load_module(&env, name, wasm, runtime).await?;

    // Free the space used by the binary, since we don't need it
    // any longer
    drop(binary);

    spawn_exec_module(module, env, runtime)
}

#[tracing::instrument(level = "trace", skip_all, fields(%name))]
pub async fn spawn_exec_wasm(
    wasm: &[u8],
    name: &str,
    env: WasiEnv,
    runtime: &Arc<dyn Runtime + Send + Sync + 'static>,
) -> Result<TaskJoinHandle, SpawnError> {
    let module = spawn_load_module(&env, name, wasm, runtime).await?;

    spawn_exec_module(module, env, runtime)
}

pub async fn spawn_load_wasm<'a>(
    env: &WasiEnv,
    binary: &'a BinaryPackage,
    name: &str,
) -> Result<&'a [u8], SpawnError> {
    let wasm = if let Some(cmd) = binary.get_command(name) {
        cmd.atom.as_ref()
    } else if let Some(cmd) = binary.get_entrypoint_command() {
        &cmd.atom
    } else {
        tracing::error!(
          command=name,
          pkg=%binary.id,
          "Unable to spawn a command because its package has no entrypoint",
        );
        env.on_exit(Some(Errno::Noexec.into())).await;
        return Err(SpawnError::MissingEntrypoint {
            package_id: binary.id.clone(),
        });
    };
    Ok(wasm)
}

pub async fn spawn_load_module(
    env: &WasiEnv,
    name: &str,
    wasm: &[u8],
    runtime: &Arc<dyn Runtime + Send + Sync + 'static>,
) -> Result<Module, SpawnError> {
    match runtime.load_module(wasm).await {
        Ok(module) => Ok(module),
        Err(err) => {
            tracing::error!(
                command = name,
                error = &err as &dyn std::error::Error,
                "Failed to compile the module",
            );
            env.on_exit(Some(Errno::Noexec.into())).await;
            Err(err)
        }
    }
}

pub async fn spawn_union_fs(env: &WasiEnv, binary: &BinaryPackage) -> Result<(), SpawnError> {
    // If the file system has not already been union'ed then do so
    env.state
        .fs
        .conditional_union(binary)
        .await
        .map_err(|err| {
            tracing::warn!("failed to union file system - {err}");
            SpawnError::FileSystemError(crate::ExtendedFsError::with_msg(
                err,
                "could not union filesystems",
            ))
        })?;
    tracing::debug!("{:?}", env.state.fs);
    Ok(())
}

pub fn spawn_exec_module(
    module: Module,
    env: WasiEnv,
    runtime: &Arc<dyn Runtime + Send + Sync + 'static>,
) -> Result<TaskJoinHandle, SpawnError> {
    // Create a new task manager
    let tasks = runtime.task_manager();

    // Create the signaler
    let pid = env.pid();

    let join_handle = env.thread.join_handle();
    {
        // Create a thread that will run this process
        let tasks_outer = tasks.clone();

        tasks_outer
            .task_wasm(TaskWasm::new(Box::new(run_exec), env, module, true))
            .map_err(|err| {
                error!("wasi[{}]::failed to launch module - {}", pid, err);
                SpawnError::UnknownError
            })?
    };

    Ok(join_handle)
}

/// # SAFETY
/// This must be executed from the same thread that owns the instance as
/// otherwise it will cause a panic
unsafe fn run_recycle(
    callback: Option<Box<TaskWasmRecycle>>,
    ctx: WasiFunctionEnv,
    mut store: Store,
) {
    if let Some(callback) = callback {
        let env = ctx.data_mut(&mut store);
        let memory = env.memory().clone();

        let props = TaskWasmRecycleProperties {
            env: env.clone(),
            memory,
            store,
        };
        callback(props);
    }
}

pub fn run_exec(props: TaskWasmRunProperties) {
    let ctx = props.ctx;
    let mut store = props.store;

    // Create the WasiFunctionEnv
    let thread = WasiThreadRunGuard::new(ctx.data(&store).thread.clone());
    let recycle = props.recycle;

    // Perform the initialization
    let ctx = {
        // If this module exports an _initialize function, run that first.
        if let Ok(initialize) = unsafe { ctx.data(&store).inner() }
            .instance
            .exports
            .get_function("_initialize")
        {
            let initialize = initialize.clone();
            if let Err(err) = initialize.call(&mut store, &[]) {
                thread.thread.set_status_finished(Err(err.into()));
                ctx.data(&store)
                    .blocking_on_exit(Some(Errno::Noexec.into()));
                unsafe { run_recycle(recycle, ctx, store) };
                return;
            }
        }

        WasiFunctionEnv { env: ctx.env }
    };

    // Bootstrap the process
    // Unsafe: The bootstrap must be executed in the same thread that runs the
    //         actual WASM code
    let rewind_state = match unsafe { ctx.bootstrap(&mut store) } {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!("failed to bootstrap - {}", err);
            thread.thread.set_status_finished(Err(err));
            ctx.data(&store)
                .blocking_on_exit(Some(Errno::Noexec.into()));
            unsafe { run_recycle(recycle, ctx, store) };
            return;
        }
    };

    // If there is a start function
    debug!("wasi[{}]::called main()", ctx.data(&store).pid());
    // TODO: rewrite to use crate::run_wasi_func

    // Call the module
    call_module(ctx, store, thread, rewind_state, recycle);
}

fn get_start(ctx: &WasiFunctionEnv, store: &Store) -> Option<Function> {
    unsafe { ctx.data(store).inner() }
        .instance
        .exports
        .get_function("_start")
        .cloned()
        .ok()
}

/// Calls the module
fn call_module(
    ctx: WasiFunctionEnv,
    mut store: Store,
    handle: WasiThreadRunGuard,
    rewind_state: Option<(RewindState, RewindResultType)>,
    recycle: Option<Box<TaskWasmRecycle>>,
) {
    let env = ctx.data(&store);
    let pid = env.pid();
    let tasks = env.tasks().clone();
    handle.thread.set_status_running();
    let runtime = env.runtime.clone();

    // If we need to rewind then do so
    if let Some((rewind_state, rewind_result)) = rewind_state {
        let mut ctx = ctx.env.clone().into_mut(&mut store);
        if rewind_state.is_64bit {
            let res = rewind_ext::<Memory64>(
                &mut ctx,
                Some(rewind_state.memory_stack),
                rewind_state.rewind_stack,
                rewind_state.store_data,
                rewind_result,
            );
            if res != Errno::Success {
                ctx.data().blocking_on_exit(Some(res.into()));
                unsafe { run_recycle(recycle, WasiFunctionEnv { env: ctx.as_ref() }, store) };
                return;
            }
        } else {
            let res = rewind_ext::<Memory32>(
                &mut ctx,
                Some(rewind_state.memory_stack),
                rewind_state.rewind_stack,
                rewind_state.store_data,
                rewind_result,
            );
            if res != Errno::Success {
                ctx.data().blocking_on_exit(Some(res.into()));
                unsafe { run_recycle(recycle, WasiFunctionEnv { env: ctx.as_ref() }, store) };
                return;
            }
        };
    }

    // Invoke the start function
    let ret = {
        // Call the module
        let call_ret = if let Some(start) = get_start(&ctx, &store) {
            start.call(&mut store, &[])
        } else {
            debug!("wasi[{}]::exec-failed: missing _start function", pid);
            ctx.data(&store)
                .blocking_on_exit(Some(Errno::Noexec.into()));
            unsafe { run_recycle(recycle, ctx, store) };
            return;
        };

        if let Err(err) = call_ret {
            match err.downcast::<WasiError>() {
                Ok(WasiError::Exit(code)) if code.is_success() => Ok(Errno::Success),
                Ok(WasiError::ThreadExit) => Ok(Errno::Success),
                Ok(WasiError::Exit(code)) => {
                    runtime.on_taint(TaintReason::NonZeroExitCode(code));
                    Err(WasiError::Exit(code).into())
                }
                Ok(WasiError::DeepSleep(deep)) => {
                    // Create the callback that will be invoked when the thread respawns after a deep sleep
                    let rewind = deep.rewind;
                    let respawn = {
                        move |ctx, store, rewind_result| {
                            // Call the thread
                            call_module(
                                ctx,
                                store,
                                handle,
                                Some((rewind, RewindResultType::RewindWithResult(rewind_result))),
                                recycle,
                            );
                        }
                    };

                    // Spawns the WASM process after a trigger
                    if let Err(err) = unsafe {
                        tasks.resume_wasm_after_poller(Box::new(respawn), ctx, store, deep.trigger)
                    } {
                        debug!("failed to go into deep sleep - {}", err);
                    }
                    return;
                }
                Ok(WasiError::UnknownWasiVersion) => {
                    debug!("failed as wasi version is unknown");
                    runtime.on_taint(TaintReason::UnknownWasiVersion);
                    Ok(Errno::Noexec)
                }
                Err(err) => {
                    runtime.on_taint(TaintReason::RuntimeError(err.clone()));
                    Err(WasiRuntimeError::from(err))
                }
            }
        } else {
            Ok(Errno::Success)
        }
    };

    let code = if let Err(err) = &ret {
        match err.as_exit_code() {
            Some(s) => s,
            None => {
                error!("{err}");
                eprintln!("{err}");
                Errno::Noexec.into()
            }
        }
    } else {
        Errno::Success.into()
    };

    // Cleanup the environment
    ctx.data(&store).blocking_on_exit(Some(code));
    unsafe { run_recycle(recycle, ctx, store) };

    debug!("wasi[{pid}]::main() has exited with {code}");
    handle.thread.set_status_finished(ret.map(|a| a.into()));
}
