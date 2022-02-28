//Highlights ANTI VM Instructions
//@author Nathan O'Neel
//@category Project
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class ProjectScript extends GhidraScript {
	public static List<String> ANTI_VM_INSTRUCTIONS = new ArrayList<>(Arrays.asList("SIDT", "SGDT", "SLDT", "SMSW", "STR", "IN", "CPUID"));
	
    public void run() throws Exception {
		if (currentProgram == null) {
			println("NO CURRENT PROGRAM");
			return;
		}
		
		InstructionIterator instructions = currentProgram.getListing().getInstructions(currentProgram.getMinAddress(), true);
		for(Instruction instruction : instructions) {
			String instructionString = instruction.getMnemonicString();
			if(ANTI_VM_INSTRUCTIONS.contains(instructionString)) {
				println("Found " + instructionString + " at " + instruction.getAddress());
				
				AddressSet set = new AddressSet();
				set.add(instruction.getAddress());
				this.createHighlight(set);
			}
		}
    }

}
