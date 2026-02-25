use std::{process::Command};

use crate::vm::*;

mod raw_module;
mod runtime_module;
mod vm;

fn main() {
    Command::new("dotnet")
        .args(["build", "../Project/Project.csproj", "-c", "Release"])
        .status()
        .expect("dotnet build failed");

    let dllpath = "../Project/bin/Release/net10.0/Project.dll";
    let raw = raw_module::load_raw_module(&dllpath);  
    let runtime = runtime_module::create_runtime_module(&raw); 
    let start_method= runtime.get_method_by_name("Test"); 
    let mut vm = Vm{runtime};
    let result= vm.exec_method(start_method, Vec::new());
    println!("{:?}", result);
}