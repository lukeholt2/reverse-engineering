/**
 * Base Script class used to perform common operations (e.g. program validation)  
 * @author lukeholt
 *
 */

import ghidra.app.script.GhidraScript;


public abstract class BaseScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new Exception("No program provided!");
		}
	}

}
