package it.unical.thesis.process;

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
