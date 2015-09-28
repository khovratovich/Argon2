#!/bin/bash

#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


# Get current script path
script_path=$(dirname $0)


# Change current directory to root directory
if [ '.' != $script_path ] ; then
	cd $script_path/../
fi


ARGON2_TYPES=(Argon2d Argon2i Argon2di Argon2id Argon2ds)
ARGON2_IMPLEMENTATIONS=(REF OPT)

KAT_REF=kat-argon2-ref.log
KAT_OPT=kat-argon2-opt.log


for type in ${ARGON2_TYPES[@]}
do
	for implementation in ${ARGON2_IMPLEMENTATIONS[@]}
	do
		echo "Test for $type $implementation: "


		make_log="make_"$type"_"$implementation".log"
		rm -f $make_log

		flags=""
		if [ "OPT" == "$implementation" ] ; then
			flags="OPT=TRUE"
		fi

		make $flags &> $make_log

		if [ 0 -ne $? ] ; then
			echo -e "\t -> Wrong! Make error! See $make_log for details!"
			continue
		else
			rm -f $make_log
		fi


		kat_file_name="KAT_"$implementation
		kat_file=${!kat_file_name}
		rm -f $kat_file

		run_log="run_"$type"_"$implementation".log"
		./Build/argon2-tv -gen-tv -type $type > $run_log
		if [ 0 -ne $? ] ; then
			echo -e "\t -> Wrong! Run error! See $run_log for details!"
			continue
		else
			rm -f $run_log
		fi


		test_vectors_file="./TestVectors/"$type".txt"

		diff_file="diff_"$type"_"$implementation
		rm -f $diff_file


		if diff -Naur $kat_file $test_vectors_file > $diff_file ; then
			echo -e "\t -> OK!"
		else
			echo -e "\t -> Wrong! See $diff_file for details!"
		fi

	done
done
