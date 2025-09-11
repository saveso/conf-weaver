package it.unical.thesis.process;

import it.unical.thesis.reader.ProcessReader;

public class Kill extends AbstractCommand{
	
	private static final String NAME = "kill";

	
	public Kill()
	{
		
	}
	
	
	public void sigint(long pid)
	{
		final String[] command = {NAME, "-2", String.valueOf(pid)};
		this.execute(command);
		ProcessReader processReader = new ProcessReader(getInputStream());
		processReader.start();
		this.waitIndefinitelyForCompletion();
	}

}
