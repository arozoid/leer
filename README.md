# leer, a CLI wrapper for LKL (linux kernel library)
<img src="./src/leer.png" width="128" align="center">

leer is a simple runtime for the Linux Kernel Library (LKL), similar in vain to chroot/proot, but with the purpose of providing both non-root support, and better syscall emulation.

## purpose

this project was started as a way to utilize the Linux kernel to run mini Linux systems, specifically within [onyx](https://github.com/arozoid/onyx), a lightweight Linux container runtime for Linux/Termux.

i originally worked on using PRoot within [onyx](https://github.com/arozoid/onyx) for non-root purposes, especially on Termux, but i eventually found that its syscall interception wasn't accurate enough to run a Linux system as intended, generating several issues that i wouldn't be able to fix using the same engine.

## features

- **root optional:** LKL doesn't require root to run, making it a great choice for running Linux boxes on systems where root is not available, such as Termux.
- **cross-arch support:** unlike other projects, such as UML (User Mode Linux), LKL can run on any architecture that the Linux kernel supports, including ARM, x86, and more.
- **proper syscall emulation:** instead of using `ptrace` to intercept syscalls, LKL runs the Linux kernel as a process to handle syscalls more accurately and efficiently.

## usage

```bash
# leer is a work in progress! come back another time to try it out :>
```