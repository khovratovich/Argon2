#!/bin/bash

#
# Call this script to clean all *~ files from the project
#	./clean.sh
#


# The root directory path
ROOT_DIR=./../


# Get current script path
script_path=$(dirname $0)


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Change curent directory to root directory
cd $ROOT_DIR


# Remove all *~ files
find . -name "*~" -type f -delete
