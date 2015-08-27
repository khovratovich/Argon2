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
Benchmark Argon2d, Argon2id, Argon2i, Argon2ds with different level of parallelism:

`argon2 -benchmark`


## Copyright
Argon2 source code package is distributed unde the Creative Commons CC0 1.0 License.


## Third Party Code
* Blake 2 source code
`./Source/Blake2/*`
* platform independent endianess detection
`./Source/Common/brg-endian.h`
