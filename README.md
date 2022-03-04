# CEG: 7420: Reverse Engineering & Program Analysis

## Running Headless

The `analyze.sh` is designed to run each custom Ghidra Script headlessly by using the `analyzeHeadless` exectutable that is packaged with Ghidra.

**Note:** _The script will attempt to find the path to `analyzeHeadless` but this may need to be modifed to use the correct path_

`Detections.java` is passed to `analyzeHeadless` to be ran and then runs each of the other Ghidra Scripts.

#### Sub Scripts Ran

1. DetectSemantics.java - detect semantic strings within binary based on values in `semantics.txt`
2. DetectInstructions.java - detect known anti-vm instruction sets
3. Decompile.java - decompiles the binary to c++. Creates both .h & .cpp files

### Usage
  
`./analyze.sh <binary>`
  
Outputs script results to `results.log` and decompiled files to the `decompiled` directory (using same name as binary)
