// Detect anti-vm strings contained in program
// @author lukeholt

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.List;
import util.CollectionUtils;
import generic.stl.Pair;

import ghidra.program.model.address.Address;
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

public class DetectSemantics extends BaseScript {

	public final static String SEMANTIC_VALUES_FILENAME = "./SemanticValues.txt";
	public static List<String> SEMANTIC_VALUES = getSemanticValues();

	@Override
	protected void run() throws Exception {

		super.run();

		List<Pair<String, Data>> strings = getProgramStrings(this.currentProgram);
		List<Pair<String, Data>> foundStrings = new ArrayList<>();
		for (Pair<String, Data> pair : strings) {
			final boolean match = SEMANTIC_VALUES.stream().anyMatch(v -> {
				return pair.first.toLowerCase().contains(v.toLowerCase());
			});

			if (match) {
				println("Found possible VM string! " + '"' + pair.first + '"' + " at location: "
						+ pair.second.getAddress());

				List<Reference> refs = Arrays.asList(this.getReferencesTo(pair.second.getAddress()));
				for (Reference ref : refs) {
					println("   References: " + ref.getFromAddress());
				}
				foundStrings.add(pair);
			}

		}

		mangleStrings(foundStrings);
	}

	/**
	 * Uses the provided foundStrings and goes to the reference of that string.
	 * Then, it manipulates the string replacing every other character with 'X'.
	 * Next, it clears the inferred DataType created by Ghidra and replaces it with
	 * the correct DataType which is a string.
	 * 
	 * @param foundStrings
	 * @throws DataTypeConflictException
	 * @throws CodeUnitInsertionException
	 * @throws MemoryAccessException
	 */
	private void mangleStrings(List<Pair<String, Data>> foundStrings)
			throws CodeUnitInsertionException, DataTypeConflictException, MemoryAccessException {

		if (!foundStrings.isEmpty())
			return;

		final boolean isMangling = this.askYesNo("String Mangle", "Would you like to mangle the Anti-VM instruction?");
		if (isMangling) {
			Assembler assembler = Assemblers.getAssembler(currentProgram);

			for (Pair<String, Data> pair : foundStrings) {

				AddressSet test = new AddressSet(this.currentProgram, pair.second.getMinAddress(),
						pair.second.getMaxAddress());

				int i = 0;
				for (Address addr : test.getFirstRange()) {
					if (pair.first.length() <= i) {
						break;
					}

					byte[] b = new byte[1];
					b[0] = (byte) pair.first.charAt(i);

					if (i % 2 == 1) {
						b[0] = 'X';
					}

					assembler.patchProgram(b, addr);

					i++;
				}

				DataType type = DataType.DEFAULT;
				Iterator<DataType> iter = this.currentProgram.getDataTypeManager().getAllDataTypes();
				while (iter.hasNext()) {
					DataType temp = iter.next();
					if (temp.getName() == "string") {
						type = temp;
						break;
					}
				}

				this.currentProgram.getDataTypeManager().getAllDataTypes();
				this.currentProgram.getListing().clearCodeUnits(pair.second.getMinAddress(),
						pair.second.getMaxAddress(), true);
				this.currentProgram.getListing().createData(pair.second.getMinAddress(), type);
			}

			// This is nice for testing..
			this.goTo(foundStrings.get(0).second.getAddress());
		}

	}

	/**
	 * Returns the strings of the provided program and the associated address
	 * 
	 * @param program
	 * @return strings, similar to 'strings' command, but also provides the data.
	 */
	private static List<Pair<String, Data>> getProgramStrings(Program program) {
		List<Pair<String, Data>> strings = new ArrayList<>();
		for (Data data : CollectionUtils.asIterable(DefinedDataIterator.definedStrings(program, null))) {
			StringDataInstance str = StringDataInstance.getStringDataInstance(data);
			String s = str.getStringValue();
			if (s != null) {
				strings.add(new Pair<String, Data>(s, data));
			}
		}
		return strings;
	}

	/**
	 * Returns semantic values from the file referenced by: SEMANTIC_VALUES_FILENAME
	 * 
	 * @return string list of known VM values
	 */
	private static List<String> getSemanticValues() {
		List<String> values = new ArrayList<>();
		try {
			Scanner scanner = new Scanner(new File(SEMANTIC_VALUES_FILENAME));

			while (scanner.hasNext()) {
				values.add(scanner.nextLine());
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return values;
	}

}
