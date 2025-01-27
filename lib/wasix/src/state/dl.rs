use std::collections::HashMap;
use std::sync::Mutex;
use wasmer::{imports, Imports, Instance, StoreMut, Value};
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
}

impl Clone for DlState {
    fn clone(&self) -> Self {
        // Clone each field individually to avoid holding multiple locks
        let modules = self.modules
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
            
        let imports = self.imports
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| imports! {});
            
        let next_handle = self.next_handle.load(Ordering::SeqCst);
        
        let last_error = self.last_error
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
    pub fn add_module(&self, instance: Instance) -> u32 {
        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let module_data = ModuleData { instance };
        
        if let Ok(mut modules) = self.modules.lock() {
            modules.insert(handle, module_data);
        }
        
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
        let global = module_data.instance.exports.get_global(symbol).ok()?;

        let offset = match global.get(&mut store) {
            Value::I32(v) => v as usize,
            Value::I64(v) => v as usize,
            _ => {
                eprintln!("Unsupported global type for symbol '{}'", symbol);
                return None;
            }
        };

        // If it's a memory symbol, read the value at the offset
        if let Ok(memory) = module_data.instance.exports.get_memory("memory") {
            let view = memory.view(&store);
            let memory_size = view.size().bytes().0 as usize;
            
            // Determine symbol size based on alignment and bounds
            let symbol_size = if offset % 8 == 0 && offset + 8 <= memory_size {
                8  // 64-bit aligned
            } else if offset % 4 == 0 && offset + 4 <= memory_size {
                4  // 32-bit aligned
            } else if offset + 1 <= memory_size {
                1  // byte aligned
            } else {
                eprintln!("Invalid symbol alignment or out of bounds at offset {}", offset);
                return None;
            };

            // Create a slice for just the bytes we need
            let data = unsafe { 
                // SAFETY: We've verified that:
                // 1. offset + symbol_size is within memory bounds
                // 2. The memory view is valid for the duration of this read
                // 3. The alignment requirements are met
                std::slice::from_raw_parts(
                    view.data_ptr().add(offset),
                    symbol_size
                )
            };

            // Read the value based on symbol size
            match symbol_size {
                8 => Some(u64::from_le_bytes(data.try_into().ok()?)),
                4 => Some(u32::from_le_bytes(data.try_into().ok()?) as u64),
                1 => Some(data[0] as u64),
                _ => unreachable!(),
            }
        } else {
            // Otherwise return the raw global value
            Some(offset as u64)
        }
    }
}
