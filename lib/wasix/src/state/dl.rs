use std::collections::HashMap;
use std::sync::Mutex;
use tracing::debug;
use wasmer::{imports, AsStoreMut, Imports, Instance, Memory, StoreMut, Value};
use wasmer_types::lib::std::sync::atomic::{AtomicU32, Ordering};

/// Represents the state for dynamic loading functionality.
#[derive(Debug)]
pub struct DlState {
    /// Map of loaded modules indexed by handle
    pub modules: Mutex<HashMap<u32, ModuleData>>,
    /// Imports available to loaded modules
    pub imports: Mutex<Imports>,
    /// Counter for generating unique module handles
    next_handle: AtomicU32,
    /// Last error message
    last_error: Mutex<String>,
}

/// Data associated with a loaded module instance
#[derive(Debug, Clone)]
pub struct ModuleData {
    /// The WebAssembly module instance
    pub instance: Instance,
    /// The memory instance
    pub memory: Memory,
}

impl Clone for DlState {
    fn clone(&self) -> Self {
        // Clone each field individually to avoid holding multiple locks
        let modules = self
            .modules
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        let imports = self
            .imports
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| imports! {});

        let next_handle = self.next_handle.load(Ordering::SeqCst);

        let last_error = self
            .last_error
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        Self {
            modules: Mutex::new(modules),
            imports: Mutex::new(imports),
            next_handle: AtomicU32::new(next_handle),
            last_error: Mutex::new(last_error),
        }
    }
}

impl DlState {
    /// Creates a new DlState instance with default values
    pub fn new() -> Self {
        Self {
            modules: Mutex::new(HashMap::new()),
            imports: Mutex::new(imports! {}),
            next_handle: AtomicU32::new(1),
            last_error: Mutex::new(String::new()),
        }
    }

    /// Adds a new module instance and returns its handle
    pub fn add_module(
        &self,
        store: &mut impl AsStoreMut,
        instance: Instance,
        memory: &Memory,
    ) -> u32 {
        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let module_data = ModuleData {
            instance: instance.clone(),
            memory: memory.clone(),
        };

        if let Ok(mut modules) = self.modules.lock() {
            modules.insert(handle, module_data);
        }

        // Call constructors for the new module
        self.call_constructors(store);

        handle
    }

    /// Gets a symbol from a loaded module
    ///
    /// # Arguments
    /// * `handle` - The module handle
    /// * `store` - The WebAssembly store
    /// * `symbol` - The symbol name to look up
    ///
    /// # Returns
    /// * `Some(u64)` - The symbol value if found
    /// * `None` - If the symbol was not found or an error occurred
    pub fn get_symbol(&self, handle: u32, mut store: StoreMut, symbol: &str) -> Option<u64> {
        let modules = self.modules.lock().ok()?;
        let module_data = modules.get(&handle)?;

        // First try to get as a global
        if let Ok(global) = module_data.instance.exports.get_global(symbol) {
            debug!("Found global {}", symbol);
            let offset = match global.get(&mut store) {
                Value::I32(v) => {
                    debug!("Global offset: {}", v);
                    v as usize
                }
                Value::I64(v) => v as usize,
                _ => {
                    eprintln!("Unsupported global type for symbol '{}'", symbol);
                    return None;
                }
            };

            // Use the stored memory to dereference the pointer
            let view = module_data.memory.view(&store);
            let data = unsafe {
                std::slice::from_raw_parts(
                    view.data_ptr().add(offset),
                    4, // Assuming 32-bit integers
                )
            };

            let value = u32::from_le_bytes(data.try_into().ok()?);
            debug!("Dereferenced value: {}", value);
            return Some(value as u64);
        }

        debug!("Symbol {} not found", symbol);
        None
    }

    fn call_constructors(&self, store: &mut impl AsStoreMut) {
        if let Ok(modules) = self.modules.lock() {
            for module_data in modules.values() {
                if let Ok(ctor) = module_data
                    .instance
                    .exports
                    .get_function("__wasm_call_ctors")
                {
                    debug!("Calling constructor for module");
                    let _ = ctor.call(store, &[]);
                }
            }
        }
    }

    // Add a new method that takes the store
    pub fn call_destructors(&self, store: &mut impl AsStoreMut) {
        if let Ok(modules) = self.modules.lock() {
            for module_data in modules.values() {
                if let Ok(dtor) = module_data
                    .instance
                    .exports
                    .get_function("__wasm_call_dtors")
                {
                    debug!("Calling destructor for module");
                    let _ = dtor.call(store, &[]);
                }
            }
        }
    }
}
