//Anti-VM Detection: Highlights Anti-VM Instructions, searches for known VM strings, and has the ability to mangle VM strings.
//@author Nathan O'Neel
//@category Project
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import util.CollectionUtils;

import generic.stl.Pair;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefinedDataIterator;


public class DetectInstructions extends BaseScript {
	
	
	public static List<String> ANTI_VM_INSTRUCTIONS = new ArrayList<>(Arrays.asList("SIDT", "SGDT", "SLDT", "SMSW", "STR", "IN", "CPUID"));
	public static List<String> TIMING_ATTACK_INSTRUCTIONS = new ArrayList<>(Arrays.asList("RDTSC", "RDTSCP"));
	
	
    public void run() throws Exception {
		
    	super.run();
		
		InstructionIterator instructions = currentProgram.getListing().getInstructions(currentProgram.getMinAddress(), true);
		
		for(Instruction instruction : instructions) {
			String instructionString = instruction.getMnemonicString();
			
			// Search for known anti-vm instructions
			if(ANTI_VM_INSTRUCTIONS.contains(instructionString)) {
				println("Found " + instructionString + " at " + instruction.getAddress());
				
				HighlightAddress(instruction);
			}
			
			// Search for known anti-vm instructions
			if(TIMING_ATTACK_INSTRUCTIONS.contains(instructionString)) {
				println("Found possible timing attack " + instructionString + " at " + instruction.getAddress());
				
				HighlightAddress(instruction);
			}
		}
	
    
    /**
     *  Highlights address of the provided instructionß
     */
    private void HighlightAddress(Instruction instruction) {
    	AddressSet set = new AddressSet();
		set.add(instruction.getAddress());
		this.createHighlight(set);
    }

}
