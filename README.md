# gdbsrv
This is a simple GDB server that can be executed on a Playstation 4 or
Playstation 5 that has been jailbroken and is running an ELF loader.
The server accepts connections on port 2159, and has been tested with
gdb-15.

## Building for the PS4
Assuming you have the [ps4-payload-sdk][sdk-ps4] installed on a POSIX machine,
the GDB server can be compiled using the following two commands:
```console
john@localhost:gdbsrv$ export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
john@localhost:gdbsrv$ make -f Makefile.ps4
```

## Building for the PS5
Assuming you have the [ps5-payload-sdk][sdk-ps5] installed on a POSIX machine,
the GDB server can be compiled using the following two commands:
```console
john@localhost:gdbsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:gdbsrv$ make -f Makefile.ps5
```

## Building for GNU/Linux systems
Assuming you have a compiler toolchain installed on your GNU/Linux system,
the GDB server can be compiled using the following command:
```console
john@localhost:gdbsrv$ make -f Makefile.posix
```

## Known issues
- Symbols from dynamic sony libraries are not loaded correctly at the moment.
- A couble of arguments passed to the ELF are allocated on the heap, so gdb may
  report errors when trying to resolve the arguments to _start()

## Reporting Bugs
If you encounter problems with gdbsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
gdbsrv is licensed under the GPLv3+.

[sdk-ps4]: https://github.com/ps4-payload-dev/sdk
[sdk-ps5]: https://github.com/ps5-payload-dev/sdk
[issues]: https://github.com/ps5-payload-dev/shsrv/issues/new
