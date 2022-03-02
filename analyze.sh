#!/bin/bash

BINARY="$1"

if [ -z "$BINARY" ]; then
    echo 'Binary Required'
    exit 1;
fi

# find the analyzeHeadless executable
# it's buried in ghidra directory so for now it's safe
# to simple search from the home directory
GHIDRA=$(find ~/ -type f -name 'analyzeHeadless')
# specify the directory containing custom ghidra scripts
SCRIPTPATH=~/reverse-engineering/

# run the ghidra 'analyzeHeadless' with the settings:
# . - use current directory
# tmp_proj - project name; use temp name as it will be deleted after
# -deleteProject - self-explanatory, delete the project when finished
# -scriptPath - search path to ensure scripts are found
# -postScript - specifies script to run
# -scriptlog - where to log output from scripts (ignoring the other clutter outputted by ghidra)
$GHIDRA . tmp_proj -import $BINARY -deleteProject -scriptPath $SCRIPTPATH -postScript ./Detection.java -scriptlog ./results.log


