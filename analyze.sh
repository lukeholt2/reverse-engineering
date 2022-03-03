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
# -propertiesPath - search path for properties used for script prompts (e.g. askYesorNo)
# -postScript - specifies script to run
# -scriptlog - where to log output from scripts (ignoring the other clutter outputted by ghidra)
# -analysisTimeoutPerFile - running multiple scripts can lead to timeout so need to manually increase timeout. 100s is a  _long_ time so no more than that should be needed
$GHIDRA . tmp_proj -import $BINARY \
	-deleteProject \
	-scriptPath $SCRIPTPATH \
	-propertiesPath $SCRIPTPATH \
	-postScript ./Detection.java \
	-scriptlog ./results.log \
	-analysisTimeoutPerFile 100


# it's honeslty way simpler to do this here rather than in java
if [ ! -d decompiled ]; then
    mkdir decompiled
fi
mv *.cpp decompiled/
mv *.h decompiled/
