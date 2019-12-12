# Fuzzers for wolfSSL and wolfSSH

## Building

From the ```oss-fuzz``` directory, run:

```sh
infra/helper.py build_fuzzers wolf-ssl-ssh
```

This builds the 64 bit AddressSanitizer based fuzzers.

If you want UndefinedBehaviorSanitizer, append ```--sanitizer=undefined```.

If you want MemorySanitizer, append ```--sanitizer=memory```.

If you want 32 bit + AddressSanitizer, append ```--architecture=i386```.

For each fuzzer target, three binaries are generated: One that is primarily guided by code coverage, one by intensity (finds slow inputs) and one by peak allocations (finds inputs that consume a lot of memory).

## Running

### Intensity guided fuzzers

Append ```-intensity_guided=1``` to the fuzzer command. Optionally, also append ```-no_coverage_guided=1``` to discard the code coverage signal, and focus entirely on the intensity signal.

### Allocation guided fuzzers

Append ```-custom_guided=1``` to the fuzzer command. Optionally, also append ```-no_coverage_guided=1``` to discard the code coverage signal, and focus entirely on the allocation signal.

## Options

### Memory tests

Undefine ```MEMORY_TESTS``` in ```oss-fuzz/projects/wolf-ssl-ssh/fuzzers/include/fuzzers/shared.h``` for more speed, but fewer memory tests on output data. Please see the comments in that file for more information.
