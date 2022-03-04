// Decompiles binary to c++
// @author lukeholt

import ghidra.app.util.exporter.CppExporter;
import java.io.File;

public class Decompile extends BaseScript {

	@Override
	protected void run() throws Exception {

		super.run();

		// create the exporter and just go ahead and set it to export everything
		CppExporter exporter = new CppExporter(true, true, true, true, null);

		exporter.setExporterServiceProvider(state.getTool());

		File toExport = new File(String.format("%s.cpp", currentProgram.getName()));

		exporter.export(toExport, currentProgram, currentHighlight, monitor);

	}

}
