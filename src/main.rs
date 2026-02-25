use std::{process::Command};

mod raw_module;

//---------------------------------------------------------------------------------
fn main() {
    Command::new("dotnet")
        .args(["build", "../Project/Project.csproj", "-c", "Release"])
        .status()
        .expect("dotnet build failed");

    let dllpath = "../Project/bin/Release/net10.0/Project.dll";
    let raw_module = raw_module::load_raw_module(&dllpath);  
    raw_module::print_rawmodule(&raw_module);  
}