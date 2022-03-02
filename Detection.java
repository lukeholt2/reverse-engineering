// Driver for running individual scripts for Anti-VM Detection
// @author lukeholt

import ghidra.app.util.headless.HeadlessScript;

public class Detection extends HeadlessScript {

	@Override
	protected void run() throws Exception {
	    // not sure if this is necessary or not honetly
	    // but ensure continuation between scripts
		setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE_THEN_DELETE);

		// now run each script passing the state along to each
		this.runScript("ProjectScript.java", this.getState());
		this.runScript("DetectStrings.java", this.getState());
		this.runScript("Decompile.java", this.getState());
		
	}

}
