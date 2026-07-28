# re-Blutter
Flutter Mobile Application Reverse Engineering Tool by Compiling Dart AOT Runtime.

This is a fork of [Blutter](https://github.com/worawit/blutter) that extends it with
iOS support: it reads Mach-O binaries (`App` / `Flutter` frameworks) and accepts `.ipa`
files directly, in addition to the original Android `libapp.so` / `.apk` path.

Supported inputs:
- Android: `libapp.so` + `libflutter.so` (ELF, arm64), or an `.apk`
- iOS: `App.framework/App` + `Flutter.framework/Flutter` (Mach-O, arm64), or an `.ipa`

## Environment Setup
This application uses the C++20 Formatting library. It requires a recent C++ compiler such as g++>=13 or Clang>=16.

### Debian Unstable (gcc 13)
Use ONLY a Debian/Ubuntu version that provides gcc>=13 from its own main repository. A ported gcc on an older release will not work.

```
apt install python3-pyelftools python3-requests git cmake ninja-build \
    build-essential pkg-config libicu-dev libcapstone-dev
```

### Windows
- Install git and python 3
- Install Visual Studio with "Desktop development with C++" and "C++ CMake tools"
- Install required libraries (libcapstone and libicu4c)
```
python scripts\init_env_win.py
```
- Start "x64 Native Tools Command Prompt"

### macOS Sequoia
- Install Xcode
```
brew install cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

### macOS Ventura and Sonoma (clang 16)
- Install Xcode
```
brew install llvm@16 cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

## Usage

Android, from an extracted `lib` directory:
```
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

Android, directly from an apk:
```
python3 blutter.py path/to/app.apk out_dir
```

iOS, directly from an ipa:
```
python3 blutter.py path/to/app.ipa out_dir
```

iOS, from a directory containing `App` and `Flutter`:
```
python3 blutter.py path/to/extracted_frameworks out_dir
```

The Dart version, snapshot hash and target (os/arch) are detected automatically from the
binaries. If the matching blutter executable for that Dart version does not exist yet, the
script checks out the Dart source and builds it.

## Output files
- **asm/\*** libapp assemblies with symbols
- **blutter_frida.js** the frida script template for the target application
- **objs.txt** complete (nested) dump of Object from Object Pool
- **pp.txt** all Dart objects in Object Pool

## Directories
- **bin** blutter executables per Dart version, named `blutter_dartvm<ver>_<os>_<arch>`
- **blutter** source code, built against the Dart VM library
- **build** build projects (safe to delete after a build finishes)
- **dartsdk** Dart Runtime checkout (safe to delete after a build finishes)
- **external** 3rd party libraries, Windows only
- **packages** static libraries of the Dart Runtime
- **scripts** python scripts for fetching/building Dart

## Generating a Visual Studio Solution for Development
```
python blutter.py path\to\lib\arm64-v8a build\vs --vs-sln
```

## TODO
- More code analysis (function arguments and return types, pseudo code for common patterns)
- Better Frida script generation (more internal classes, object modification)
- Obfuscated app support

## Credits
Original Blutter by [@worawit](https://github.com/worawit/blutter), licensed under MIT.
See [LICENSE](LICENSE).
