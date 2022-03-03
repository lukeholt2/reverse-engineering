// Driver for running individual scripts for Anti-VM Detection
// @author lukeholt

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;

import ghidra.app.util.headless.HeadlessScript;

public class Detection extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		// not sure if this is necessary or not honetly
		// but ensure continuation between scripts
		setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE_THEN_DELETE);

		for (File script : GetScriptFiles()) {
			// now run each script passing the state along to each
			this.runScript(script.getName(), this.getState());
		}

	}

	/**
	 *  Gets all the current Ghidra Script files 
	 *  Searches the current directory for java files excluding this one
	 *  @return An array of Files representing the anti-vm ghidra scripts
	 */
	private File[] GetScriptFiles() {
		try {
			File workingDir = new File(".");
			return workingDir.listFiles(
					(File file) -> file.getName().endsWith(".java") && !file.getName().equals("Detection.java"));
		} catch (SecurityException e) {
			e.printStackTrace();
		}

		return new File[0];
	}

}
