self.onmessage = async function (event) {
    if (event.data.type === "load") {
      try {
        const wasmURL = event.data.wasmURL; // Receive URL from main script
        const response = await fetch(wasmURL);
        if (!response.ok) throw new Error(`Failed to fetch WASM: ${response.statusText}`);
        const bytes = await response.arrayBuffer();
  
        // Compile the module so we can inspect its imports.
        const module = await WebAssembly.compile(bytes);
        const moduleImports = WebAssembly.Module.imports(module);
        const imports = {};
  
        // Build a stub import object based on the module's import descriptors.
        for (const imp of moduleImports) {
          if (!imports[imp.module]) {
            imports[imp.module] = {};
          }
          if (imp.kind === "function") {
            // Provide a stub function that logs a warning if called.
            imports[imp.module][imp.name] = function () {
              console.warn(`Called stub for ${imp.module}.${imp.name}`);
            };
          } else if (imp.kind === "memory") {
            // Use the minimum value if provided, or default to 256 pages.
            const initial = imp.minimum !== undefined ? imp.minimum : 256;
            const maximum = imp.maximum;
            imports[imp.module][imp.name] = new WebAssembly.Memory({ initial, maximum });
          } else if (imp.kind === "table") {
            // Use the provided minimum or default to 117.
            const initial = (imp.minimum && imp.minimum > 0) ? imp.minimum : 117;
            const maximum = imp.maximum;
            imports[imp.module][imp.name] = new WebAssembly.Table({ initial, maximum, element: "anyfunc" });
          } else if (imp.kind === "global") {
            if (imp.module === "env" && imp.name === "__stack_pointer") {
              // __stack_pointer is typically a mutable i32 with a nonzero initial value.
              imports[imp.module][imp.name] = new WebAssembly.Global({ value: "i32", mutable: true }, 0x10000);
            } else if (imp.module === "GOT.func") {
              // Force globals from GOT.func to be mutable (required by the module)
              const validTypes = ["i32", "i64", "f32", "f64"];
              const type = validTypes.includes(imp.type) ? imp.type : "i32";
              imports[imp.module][imp.name] = new WebAssembly.Global({ value: type, mutable: true }, 0);
            } else {
              // For other globals, use the reported mutability.
              const validTypes = ["i32", "i64", "f32", "f64"];
              const type = validTypes.includes(imp.type) ? imp.type : "i32";
              imports[imp.module][imp.name] = new WebAssembly.Global({ value: type, mutable: imp.mutable }, 0);
            }
          } else {
            imports[imp.module][imp.name] = 0;
          }
        }
  
        const { instance } = await WebAssembly.instantiate(module, imports);
        self.postMessage({ type: "loaded", exports: instance.exports });
      } catch (error) {
        console.error("WebAssembly Worker Error:", error);
        self.postMessage({ type: "error", error: error.message });
      }
    }
  };
  