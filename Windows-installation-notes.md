Running This Codebase on Windows before # cargo run


1. Install Rust
Install Rust using rustup (official installer):
# Download and run rustup-init.exe from:
# https://rustup.rs/

# Or use PowerShell:
# Invoke-WebRequest https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
# .\rustup-init.exe
This installs:
rustc (compiler)
cargo (package manager + build tool)
rustup (toolchain manager)


2. Install MSVC toolchain
Install Visual Studio Build Tools:
Download: https://visualstudio.microsoft.com/downloads/
Select "Build Tools for Visual Studio"
During installation, check:
"Desktop development with C++"
This includes:
MSVC (v143 - VS 2022 C++ x64/x86 build tools)
Windows 10/11 SDK
C++ CMake tools
Restart your terminal/PowerShell after installation.
Verify the toolchain:
   rustup show
If needed, set MSVC as default:
   rustup default stable-x86_64-pc-windows-msvc


3. Quick start commands
# Check Rust installation
rustc --version
cargo --version

# Clean build artifacts (like deleting __pycache__)
cargo clean

# Check for dependency updates
cargo update

# Run
cargo run
