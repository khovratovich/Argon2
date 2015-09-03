# Argon2 source code package


## Warning
Argon2 is the basis for the eventual winner of Password Hashing Competition. 
The final winner may be different from the current version (1.2.1).

## About
The Argon2 source code package includes:
* Reference C++ implementation of password hashing scheme Argon2

	`make`
        
* Optimized C++ implementation of password hashing scheme Argon2

	`make OPT=TRUE`

Build result:
* Argon2 without debug messages
`argon2`
* Argon2 with debug messages
`argon2-tv`
* Argon2 shared library
`libargon2.so`
* Argon2 built with the shared library
`argon2-lib-test`


## Usage
Options:

`argon2 -help`

Benchmark Argon2d, Argon2id, Argon2i, Argon2ds with different level of parallelism:

`argon2 -benchmark`

Generate detailed test vectors:

`argon2-tv -gen-tv

##Library usage

1. Initialize Argon2_Context structure with`
 - address of output buffer (can not be NULL)
 - output length
 - address of password array
 - * password length
 - address of salt array
 - * salt length
 - address of secret/key array
 - * key length
 - address of associated data array
 - associated data length
 - * number of iterations
 - * amount of memory in KBytes 
 - number of parallel threads
 - pointer to memory allocator
 - pointer to memory deallocator
 - * password erase indicator
 - * secret erase indicator
 - * memory erase indicator

	All these parameters but the last five affect the output digest. Parameters marked by * are security critical and should be selected according to the specification. Parameters  <number of iterations>, <amount of memory>, <number of parallel threads>, and (to some extent) <memory erase indicator> affect the performance.

2. Select the Argon2 mode that fits the needs. Argon2i is safe against side-channel attacks but is more vulnerable to GPU cracking and memory-reduction attacks than Argon2d (factor 1.5 for memory reduction) and Argon2ds (factor 5 for GPU cracking). Argon2d(s) is recommended for side-channel free environments.

3. Call <mode>(context) such as Argon2d(context) and read the output buffer.


## Copyright
Argon2 source code package is distributed unde the Creative Commons CC0 1.0 License.


## Third Party Code
* Blake 2 source code
`./Source/Blake2/*`
* platform independent endianess detection
`./Source/Common/brg-endian.h`
