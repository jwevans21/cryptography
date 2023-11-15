# Cryptographic Library

Implementations of cryptographic functions in the C programming language.
These implementations are test based on a limited set of test vectors, but
are not validated for security.

## Building

This project uses CMake to generate the build files. The tested configuration
is `Unix Makefiles`.

```bash
$ cmake -S . -B build # Output the build files in build/

$ make -C build # Build the library
```

## Testing

The testing of the functionality is done using the Google Test framework and CTest. To run these tests (from project root directory):

```bash
$ cmake -S . -B build

$ make -C build

$ make test -C build # or cd build && ctest
```

## References

Copies of the works used as a reference for the implementations are included
in the `references/` directory.
