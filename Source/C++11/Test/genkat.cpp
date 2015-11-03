/*
 * Argon2 source code package
 * 
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 * 
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "kat.h"

int main(int argc, char *argv[]) {
    const char *type = (argc > 1) ? argv[1] : "i";
    GenerateTestVectors(type);
    return ARGON2_OK;
}
