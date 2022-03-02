
import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.Arrays;

public class DetectStrings extends BaseScript {
	
	// TODO: add additional search terms
	public static ArrayList<String> SearchStrings = new ArrayList<String>(Arrays.asList("Sandbox"));
	
	@Override
	protected void run() throws Exception {
		
		for(String term: SearchStrings) {
			Address foundAddr = find(term);
			if(foundAddr != null)
				println("Search match found at "+foundAddr);
		}
	       
	}
	

}
