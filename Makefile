#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


CC = gcc #clang++
REF_CFLAGS = -std=c99  -Wall
OPT_CFLAGS = -std=c99 -O3 -m64 -mavx -Wall


ARGON2_DIR = ./Source/C99/Argon2
BLAKE2_DIR = ./Source/C99/Blake2

ARGON2_SOURCES = argon2.c argon2-core.c kat.c
BLAKE2_SOURCES = blake2b-ref.c
TEST_SOURCES = argon2-test.c

REF_CORE_SOURCE = argon2-ref-core.c
OPT_CORE_SOURCE = argon2-opt-core.c


BUILD_DIR = ./Build


LIBNAME=argon2


ARGON2_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SOURCES))
BLAKE2_BUILD_SOURCES = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SOURCES))
TEST_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(TEST_SOURCES))


#OPT=TRUE
ifeq ($(OPT), TRUE)
    CFLAGS=$(OPT_CFLAGS)
    ARGON2_BUILD_SOURCES += $(ARGON2_DIR)/$(OPT_CORE_SOURCE)
else
    CFLAGS=$(REF_CFLAGS)
    ARGON2_BUILD_SOURCES += $(ARGON2_DIR)/$(REF_CORE_SOURCE)
endif


.PHONY: all
all: cleanall argon2 argon2-tv argon2-lib argon2-lib-test


.PHONY: argon2
argon2:
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/$@


argon2-tv:
	$(CC) $(CFLAGS) \
		-DARGON2_KAT -DARGON2_KAT_INTERNAL \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/$@


.PHONY: argon2-lib
argon2-lib:
	$(CC) $(CFLAGS) \
		-shared -fPIC \
		$(ARGON2_BUILD_SOURCES) \
		$(CORE_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/lib$(LIBNAME).so


.PHONY: argon2-lib-test
argon2-lib-test: argon2-lib
	$(CC) $(CFLAGS) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-L$(BUILD_DIR) \
		-Wl,-rpath=$(BUILD_DIR) \
		-l$(LIBNAME) \
		-o $(BUILD_DIR)/$@


.PHONY: clean
clean:
	rm -f $(BUILD_DIR)/*


.PHONY: cleanall
cleanall: clean
	rm -f *~
	rm -f $(ARGON2_DIR)/*~
	rm -f $(BLAKE2_DIR)/*~
