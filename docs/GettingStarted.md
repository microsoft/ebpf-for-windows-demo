# Getting Started

### Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. **Visual Studio 2022** - one of the following editions should be installed (once installed, upgrade to **v17.4.2 or later**):

   - [Download Visual Studio Community 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=17) (free)
   - [Download Visual Studio Professional 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Professional&rel=17)
   - [Download Visual Studio Enterprise 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Enterprise&rel=17)

   during the installation, select the following feature from the *Visual Studio Installer*:

   - `"Desktop development with C++"` (ensure that the "*C++ Address Sanitizer*" component is installed)

   including the following *Spectre* library, which must be selected from the "*Individual components*" tab in the
   Visual Studio Installer:

   - `"MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (latest)"`

3. [Visual Studio Build Tools 2022](https://aka.ms/vs/17/release/vs_buildtools.exe) (version **17.4.2 or later**).
4. [SDK for Windows 11, version 22H2](https://go.microsoft.com/fwlink/p/?linkid=2196241) (version **10.0.22621.x**).
5. [WDK for Windows 11, version 22H2](https://go.microsoft.com/fwlink/?linkid=2196230) (version **10.0.22621.x**), including the
 "*Windows Driver Kit Visual Studio extension*" (make sure the "*Install Windows Driver Kit Visual Studio Extension*"
  check box is checked before completing the installer).
    >Note: as multiple versions of WDKs cannot coexist side-by-side, you may be asked to uninstall previous versions.
6. [Clang for Windows 64-bit](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/LLVM-11.0.1-win64.exe) (version **11.0.1**).
 Note: clang versions 12 and higher are NOT yet supported, as they perform program optimizations that are incompatible with the PREVAIL verifier.
7. [NuGet Windows x86 Commandline](https://www.nuget.org/downloads) (version **6.31 or higher**), which can be installed to a location
 such as "C:\Program Files (x86)\NuGet\".

You should add the paths to `git.exe`, `cmake.exe` and `nuget.exe` to the Windows PATH environment variable after the
above software packages have been installed.

## How to clone and build the project
This section outlines the steps to build, prepare and build the eBPF-for-Windows Demo project.

### Cloning the project
1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows-demo.git```.
By default this will clone the project under the `ebpf-for-windows-demo` directory.

### Prepare for first build
The following steps need to be executed _once_ before the first build on a new clone.
1. Launch `Developer Command Prompt for VS 2022` by running `"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"`.
2. ```cmake -G "Visual Studio 17 2022" -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF```
3. ```nuget restore ebpf-for-windows-demo.sln```

Note: The eBPF-for-Windows Demo project has eBPF-for-Windows as a nuget package published from the latest stable release. The nuget package is placed in 'ebpf-for-windows-demo\packages\eBPF-for-Windows.<release>'


### Building using Developer Command Prompt for VS 2022
1. Launch `Developer Command Prompt for VS 2022`.
2. Change directory to where the project is cloned, e.g. ```cd ebpf-for-windows-demo```.
3. ```msbuild /m /p:Configuration=Release /p:Platform=x64 ebpf-for-windows-demo.sln```

### Building using Visual Studio IDE
1. Open `ebpf-for-windows-demo.sln`
2. Switch to Release / x64
3. Build solution
