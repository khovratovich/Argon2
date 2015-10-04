#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


#STD=C++11
ifeq ($(STD), C++11)
	CC = g++ #clang++
	CC_STANDARD = -std=c++11

	SRC_DIR = C++11
	SRC_EXT = cpp
else
	CC = gcc #clang
	CC_STANDARD = -std=c99
	
	SRC_DIR = C99
	SRC_EXT = c
endif

REF_CFLAGS = $(CC_STANDARD) -pthread -O3 -Wall
OPT_CFLAGS = $(CC_STANDARD) -pthread -O3 -m64 -mavx -Wall


ARGON2_DIR = ./Source/Argon2/$(SRC_DIR)
CORE_DIR = ./Source/Core/$(SRC_DIR)
BLAKE2_DIR = ./Source/Blake2
TEST_DIR = ./Source/Test/$(SRC_DIR)
COMMON_DIR = ./Source/Common

ARGON2_SOURCES = argon2.$(SRC_EXT)
CORE_SOURCES = argon2-core.$(SRC_EXT) kat.$(SRC_EXT)
BLAKE2_SOURCES = blake2b-ref.c
TEST_SOURCES = argon2-test.$(SRC_EXT)

REF_CORE_SOURCE = argon2-ref-core.$(SRC_EXT)
OPT_CORE_SOURCE = argon2-opt-core.$(SRC_EXT)


BUILD_DIR = ./Build


LIBNAME=argon2


ARGON2_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SOURCES))
CORE_BUILD_SOURCES = $(addprefix $(CORE_DIR)/,$(CORE_SOURCES))
BLAKE2_BUILD_SOURCES = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SOURCES))
TEST_BUILD_SOURCES = $(addprefix $(TEST_DIR)/,$(TEST_SOURCES))


#OPT=TRUE
ifeq ($(OPT), TRUE)
    CFLAGS=$(OPT_CFLAGS)
    CORE_BUILD_SOURCES += $(CORE_DIR)/$(OPT_CORE_SOURCE)
else
    CFLAGS=$(REF_CFLAGS)
    CORE_BUILD_SOURCES += $(CORE_DIR)/$(REF_CORE_SOURCE)
endif


.PHONY: all
all: cleanall argon2 argon2-tv argon2-lib argon2-lib-test


.PHONY: argon2
argon2:
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(CORE_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(CORE_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(TEST_DIR) \
		-I$(COMMON_DIR) \
		-o $(BUILD_DIR)/$@


argon2-tv:
	$(CC) $(CFLAGS) \
		-DARGON2_KAT -DARGON2_KAT_INTERNAL \
		$(ARGON2_BUILD_SOURCES) \
		$(CORE_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(CORE_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(TEST_DIR) \
		-I$(COMMON_DIR) \
		-o $(BUILD_DIR)/$@


.PHONY: argon2-lib
argon2-lib:
	$(CC) $(CFLAGS) \
		-shared -fPIC \
		$(ARGON2_BUILD_SOURCES) \
		$(CORE_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(CORE_DIR) \
		-I$(BLAKE2_DIR) \
		-I$(COMMON_DIR) \
		-o $(BUILD_DIR)/lib$(LIBNAME).so


.PHONY: argon2-lib-test
argon2-lib-test: argon2-lib
	$(CC) $(CFLAGS) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(TEST_DIR) \
		-L$(BUILD_DIR) \
		-Wl,-rpath=$(BUILD_DIR) \
		-l$(LIBNAME) \
		-o $(BUILD_DIR)/$@


.PHONY: check-tv
check-tv:
	./Scripts/check_test_vectors.sh -std=$(STD)


.PHONY: clean
clean:
	rm -f $(BUILD_DIR)/*


.PHONY: cleanall
cleanall: clean
	rm -f *~
	rm -f $(ARGON2_DIR)/*~
	rm -f $(CORE_DIR)/*~
	rm -f $(BLAKE2_DIR)/*~
	rm -f $(TEST_DIR)/*~
	rm -f $(COMMON_DIR)/*~
