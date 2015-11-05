#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


CC = g++ #clang++
REF_CFLAGS = -std=c++11 -pthread -O3 -Wall
OPT_CFLAGS = -std=c++11 -pthread -O3 -Wall -march=native


ARGON2_DIR = ./Argon2
BLAKE2_DIR = ./Blake2
TEST_DIR = ./Test

ARGON2_SOURCES = argon2.cpp argon2-core.cpp kat.cpp
BLAKE2_SOURCES = blake2b.c
RUN_SOURCES = run.cpp
BENCH_SOURCES = bench.cpp
KAT_SOURCES = genkat.cpp

REF_SOURCES = argon2-ref-core.cpp
OPT_SOURCES = argon2-opt-core.cpp


BUILD_DIR = ./../../Build


LIB_NAME=argon2


SCRIPTS_DIR = ./../../Scripts


ARGON2_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SOURCES))
BLAKE2_BUILD_SOURCES = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SOURCES))
RUN_BUILD_SOURCES = $(addprefix $(TEST_DIR)/,$(RUN_SOURCES))
BENCH_BUILD_SOURCES = $(addprefix $(TEST_DIR)/,$(BENCH_SOURCES))
KAT_BUILD_SOURCES = $(addprefix $(TEST_DIR)/,$(KAT_SOURCES))


#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS=$(OPT_CFLAGS)
	ARGON2_BUILD_SOURCES += $(addprefix $(ARGON2_DIR)/,$(OPT_SOURCES))
else
	CFLAGS=$(REF_CFLAGS)
	ARGON2_BUILD_SOURCES += $(addprefix $(ARGON2_DIR)/,$(REF_SOURCES))
endif


SRC_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))


BUILD_DIR_PATH := $(shell pwd)/$(BUILD_DIR)

SYSTEM_KERNEL_NAME := $(shell uname -s)

ifeq ($(SYSTEM_KERNEL_NAME), Linux)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	LIB_PATH := -Wl,-rpath=$(BUILD_DIR_PATH)
endif
ifeq ($(SYSTEM_KERNEL_NAME), Darwin)
	LIB_EXT := dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
	LIB_PATH := -Xlinker -rpath -Xlinker $(BUILD_DIR_PATH)
endif
ifeq ($(KERNEL_NAME), NetBSD)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	LIB_PATH := -Wl,-rpath=$(BUILD_PATH)
endif
ifeq ($(findstring MINGW, $(KERNEL_NAME)), MINGW)
	LIB_EXT := dll
	LIB_CFLAGS := -shared -Wl,--out-implib,lib$(LIB_NAME).$(LIB_EXT).a
	LIB_PATH := -Wl,-rpath=$(BUILD_PATH)
endif
ifeq ($(KERNEL_NAME), $(filter $(KERNEL_NAME),OpenBSD FreeBSD))
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	LIB_PATH := -Wl,-rpath=$(BUILD_PATH)
endif


.PHONY: all
all: cleanall argon2 argon2-lib argon2-lib-test argon2-bench argon2-kat


.PHONY: argon2-bench
argon2-bench:
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(BENCH_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(TEST_DIR) \
		-o $(BUILD_DIR)/$@
.PHONY: argon2
argon2:
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(RUN_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(TEST_DIR) \
		-o $(BUILD_DIR)/$@
.PHONY: argon2-kat	
argon2-kat:
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(KAT_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(TEST_DIR) \
		-o $(BUILD_DIR)/$@
	
.PHONY: argon2-lib
argon2-lib:
	$(CC) $(CFLAGS) \
		$(LIB_CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/lib$(LIB_NAME).$(LIB_EXT)


.PHONY: argon2-lib-test
argon2-lib-test: argon2-lib
	$(CC) $(CFLAGS) \
		$(RUN_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(TEST_DIR) \
		-L$(BUILD_DIR_PATH) \
		$(LIB_PATH) \
		-l$(LIB_NAME) \
		-o $(BUILD_DIR)/$@


.PHONY: check-tv
check-tv:
	$(SCRIPTS_DIR)/check_test_vectors.sh -src=$(SRC_DIR)


.PHONY: clean
clean:
	rm -f $(BUILD_DIR)/*


.PHONY: cleanall
cleanall: clean
	rm -f *~
	rm -f $(ARGON2_DIR)/*~
	rm -f $(BLAKE2_DIR)/*~
	rm -f $(TEST_DIR)/*~
