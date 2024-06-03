# SDB - Simple Instruction-Level Debugger

> [!IMPORTANT]
> Only _64-bit static-nopie_ programs on _x86-64_ architecture are supported.

## Prerequisites

- [Make](https://www.gnu.org/software/make/) for building the project.
- A C++17 compliant compiler, such as [GCC](https://gcc.gnu.org/) or [Clang](https://clang.llvm.org/), for building the project.
- [libreadline](https://tiswww.case.edu/php/chet/readline/rltop.html) for command line editing.
- [libcapstone](https://www.capstone-engine.org/) for disassembling instructions.

## Build

```console
make
```

The executable `sdb` will be generated under the project root.

## Usage

```console
$ ./sdb --help
Usage: sdb [OPTION...] [PROGRAM]

A simple x86-64 instruction-level debugger.

  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Copyright (c) 2024 Lai-YT under the MIT License.
```

## Features

Several common features are supported. You can view them by typing `help` in the debugger.

```console
(sdb) help
Commands:
  load [program] - load a program
  cont - continue the program
  break [hex address] - set a breakpoint
  si - single step
  info reg - show registers
  info break - show breakpoints
  delete [breakpoint id] - delete a breakpoint
  syscall - execute until syscall or breakpoint
  patch [hex address] [hex data] [length] - patch memory; length: 1, 2, 4, 8
  help - show this message
```

## License

This project is licensed under the [MIT License](LICENSE).
