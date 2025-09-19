package it.unical.thesis.process;

import java.util.List;

public class Bootstrap extends AbstractCommand{

	private static final String NAME = "bootstrap_enhanced";
	
	private final String certsPath;
			
	
	public Bootstrap(String certsPath)
	{
		this.certsPath = certsPath;
	}


	public List<String> startGeneration(String caSerial, String caStartDate, String caEndDate, String serverSerial, String serverStartDate, String serverEndDate)
	{	
		final String[] command = {certsPath+"/"+NAME,
				"--ca-serial", caSerial,
		        "--server-serial", serverSerial,
		        "--ca-start-date", caStartDate,
		    	"--ca-end-date", caEndDate,
		        "--cert-start-date", serverStartDate,
		    	"--cert-end-date", serverEndDate,
		       // --client-serial 5E6F 
		};
		this.execute(command);
		ProcessReader processReader = new ProcessReader(getInputStream());
		processReader.start();
		this.waitIndefinitelyForCompletion();
		try {
			processReader.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return processReader.getLines();
	}
	
}
	
	