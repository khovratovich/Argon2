CFLAGS=-m64 -mavx -std=c++11 -pthread -O3
SOURCE=blake2b.cpp argon2d-opt-sse.cpp genkat.cpp
CC=g++
all:
	 $(CC) $(CFLAGS) $(SOURCE) -o argon2d
