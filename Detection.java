
// Driver for running individual scripts for Anti-VM Detection
// @author lukeholt
import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;

import ghidra.app.util.headless.HeadlessScript;

public class Detection extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		// not sure if this is necessary or not honetly
		// but ensure continuation between scripts
		setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE_THEN_DELETE);

		for (ResourceFile script : GetScriptFiles()) {
			// now run each script passing the state along to each
			printf("Running: %s\n", script.getName());
			this.runScript(script.getName(), this.getState());
		}

	}

	/**
	 * Gets all the current Ghidra Script files
	 * Searches the current directory for java files excluding this one
	 * 
	 * @return An array of Files representing the anti-vm ghidra scripts
	 */
	private ResourceFile[] GetScriptFiles() {
		try {
			ResourceFile workingDir = GhidraScriptUtil.findSourceDirectoryContaining(this.sourceFile);
			// get all the java files -- excluding this one and the baseScript (it's
			// abstract)
			return workingDir.listFiles(
					(ResourceFile file) -> file.getName().endsWith(".java")
							&& !(file.getName().equals(this.sourceFile.getName())
									|| file.getName().equals("BaseScript.java")));
		} catch (SecurityException e) {
			e.printStackTrace();
		}

		return new ResourceFile[0];
	}

}
