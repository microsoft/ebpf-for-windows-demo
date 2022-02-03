# Getting Started

## Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. [Visual Studio 2019 version 16.11.7 or later](https://www.techspot.com/downloads/downloadnow/7241/?evp=70f51271955e6392571f575e301cd9a3&file=9642), including
   the "Desktop development with C++" workload, and
   the "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (latest)"
   which must be selected as an Individual component in the VS installer
3. [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
4. [WDK for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854)
5. [Clang for Windows 64-bit version 10.0.0](https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/LLVM-10.0.0-win64.exe) or [The latest release of Clang for Windows 64-bit](https://github.com/llvm/llvm-project/releases/latest)
6. [nuget.exe](https://www.nuget.org/downloads)
   
You should add the paths to `git.exe`, `cmake.exe` and `nuget.exe` to the Windows PATH environment variable after the software packages above have been installed.

## How to clone and build the project
This section outlines the steps to build, prepare and build the eBPF-for-Windows Demo project.

### Cloning the project
1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows-demo.git```.
By default this will clone the project under the `ebpf-for-windows-demo` directory.
eBPF-for-Windows Demo project includes the eBPF-for-Windows project as a submodule.

### Prepare for first build
The following steps need to be executed _once_ before the first build on a new clone.
1. Launch `Developer Command Prompt for VS 2019` by running `"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"`.
2. Change directory to ebpf-for-windows submodule location, e.g. ```cd ebpf-for-windows-demo\external\ebpf-for-windows```.
3. ```cmake -S external\ebpf-verifier -B external\ebpf-verifier\build```
4. ```nuget restore ebpf-for-windows.sln```
5. ```del external\ebpf-verifier\build\obj\project.assets.json```

### Building using Developer Command Prompt for VS 2019
**Build eBPF-for-Windows solution**
1. Launch `Developer Command Prompt for VS 2019`.
2. Change directory to ebpf-for-windows submodule location, e.g. ```cd ebpf-for-windows-demo\external\ebpf-for-windows```.
3. ```msbuild /m /p:Configuration=Release /p:Platform=x64 ebpf-for-windows.sln```

**Build eBPF-for-Windows-Demo solution**
1. Launch `Developer Command Prompt for VS 2019`.
2. Change directory to where the project is cloned, e.g. ```cd ebpf-for-windows-demo```.
3. ```msbuild /m /p:Configuration=Release /p:Platform=x64 ebpf-for-windows-demo.sln```

### Building using Visual Studio IDE
**Build eBPF-for-Windows solution**
1. Open `ebpf-for-windows.sln` file in `external\ebpf-for-windows`
2. Switch to Release / x64
3. Build solution

**Build eBPF-for-Windows-Demo solution**
1. Open `ebpf-for-windows-demo.sln`
2. Switch to Release / x64
3. Build solution
