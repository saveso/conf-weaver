package it.unical.thesis.process;

public class Systemctl extends AbstractCommand{

	private static final String NAME = "systemctl";
	
	public Systemctl()
	{

	}


	public void stop(String serviceName)
	{
		final String[] command = {NAME, "stop", serviceName};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	

	public void restart(String serviceName)
	{
		final String[] command = {NAME, "restart", serviceName};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	
	

}
