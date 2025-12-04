# ⚙️ Running This Codebase on Windows before `cargo run`

This guide outlines the necessary prerequisites to build and run the Rust codebase on a Windows machine.

---

## 1. Install Rust

Install **Rust** using the official installer, **rustup**:

* **Download and run** `rustup-init.exe` from:
    * [https://rustup.rs/](https://rustup.rs/)

* *Alternatively, use PowerShell:*
    ```powershell
    Invoke-WebRequest [https://win.rustup.rs/x86_64](https://win.rustup.rs/x86_64) -OutFile rustup-init.exe
    .\rustup-init.exe
    ```

This installation provides the essential tools:
* **`rustc`** (the Rust compiler)
* **`cargo`** (the Rust package manager and build tool)
* **`rustup`** (the Rust toolchain manager)

---

## 2. Install MSVC toolchain

Many Rust crates, especially those that interface with C libraries, require the **Microsoft Visual C++ (MSVC) build tools**.

* **Install Visual Studio Build Tools:**
    * **Download:** [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
    * Scroll down to **"Tools for Visual Studio"** and find **"Build Tools for Visual Studio"**.

* **During installation, check the following workload:**
    * **"Desktop development with C++"**

This includes:
* **MSVC** (`v143` - VS 2022 C++ x64/x86 build tools)
* **Windows 10/11 SDK**
* **C++ CMake tools**

> **Note:** **Restart your terminal/PowerShell** after the installation is complete.

* **Verify the toolchain:**
    ```bash
    rustup show
    ```

* **If necessary, set MSVC as the default target:**
    ```bash
    rustup default stable-x86_64-pc-windows-msvc
    ```

---

## 3. Quick Start Commands

Use the following commands once all prerequisites are met:

* **Check Rust installation:**
    ```bash
    rustc --version
    cargo --version
    ```

* **Clean build artifacts (similar to deleting `__pycache__`):**
    ```bash
    cargo clean
    ```

* **Check for dependency updates:**
    ```bash
    cargo update
    ```

* **Run the project:**
    ```bash
    cargo run
    ```
