use std::collections::HashMap;
use std::sync::Mutex;
use wasmer::{imports, Imports, Instance, Module, StoreMut, Value};
use wasmer_types::lib::std::slice;
use wasmer_types::lib::std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug)]
pub struct DlState {
    pub modules: Mutex<HashMap<u32, ModuleData>>,
    pub imports: Mutex<Imports>,
    next_handle: AtomicU32,
    last_error: Mutex<String>,
}

#[derive(Debug, Clone)]
struct ModuleData {
    pub module: Module,
    pub instance: Instance,
}

impl Clone for DlState {
    fn clone(&self) -> Self {
        Self {
            modules: Mutex::new(self.modules.lock().unwrap().clone()),
            imports: Mutex::new(self.imports.lock().unwrap().clone()),
            next_handle: AtomicU32::new(self.next_handle.load(Ordering::SeqCst)),
            last_error: Mutex::new(self.last_error.lock().unwrap().clone()),
        }
    }
}
impl DlState {
    pub fn new() -> Self {
        Self {
            modules: Mutex::new(HashMap::new()),
            imports: Mutex::new(imports! {}),
            next_handle: AtomicU32::new(1),
            last_error: Mutex::new(String::new()),
        }
    }

    pub fn add_module(&self, module: Module, instance: Instance) -> u32 {
        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);

        // Insert it into the modules map
        let module_data = ModuleData { module, instance };
        self.modules.lock().unwrap().insert(handle, module_data);

        handle
    }

    pub fn get_symbol(&self, handle: u32, mut store: StoreMut, symbol: &str) -> Option<u64> {
        let modules = self.modules.lock().unwrap();
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

            if offset + 4 > view.size().bytes().0 as usize {
                eprintln!("Offset {} is out of bounds for memory", offset);
                return None;
            }

            let slice =
                unsafe { slice::from_raw_parts(view.data_ptr(), view.size().bytes().0 as usize) };
            return Some(u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap()) as u64);
        }

        // Otherwise return the raw global value
        Some(offset as u64)
    }
}
