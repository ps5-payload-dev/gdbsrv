# ps5-payload-gdbsrv
This is a simple GDB server that can be executed on a Playstation 5
that has been jailbroken via the [BD-J][bdj] or the [webkit][webkit] entry
points. The server accepts connections on port 2159, and has been tested with
gdb-15.

## Quick-start
To deploy ps5-payload-gdbsrv, first launch the [ps5-payload-elfldr][elfldr],
then load the payload by issuing the following commands:

```console
john@localhost:ps5-payload-dev/gdbsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/gdbsrv$ export PS5_HOST=ps5
john@localhost:ps5-payload-dev/gdbsrv$ make test
```

Next, launch a new terminal and debug you payload by running the following set of
commands:
```console
john@localhost:ps5-payload-dev/gdbsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/gdbsrv$ export PS5_HOST=ps5
john@localhost:ps5-payload-dev/gdbsrv$ cd sample
john@localhost:ps5-payload-dev/gdbsrv/sample$ make test
```

## Known issues
Symbols from dynamic sony libraries are not loaded correctly at the moment.


## Reporting Bugs
If you encounter problems with ps5-payload-gdbsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps5-payload-gdbsrv is licensed under the GPLv3+.

[bdj]: https://github.com/john-tornblom/bdj-sdk
[sdk]: https://github.com/ps5-payload-dev/sdk
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[elfldr]: https://github.com/ps5-payload-dev/elfldr
[issues]: https://github.com/ps5-payload-dev/shsrv/issues/new