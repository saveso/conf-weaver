package it.unical.thesis.process;

public class Ip extends AbstractCommand{

	private static final String NAME = "ip";
	
	public Ip()
	{

	}


	public void down(String interfaceName)
	{
		final String[] command = {NAME, "link", "set", interfaceName, "down"};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	

	public void up(String interfaceName)
	{
		final String[] command = {NAME, "link", "set", interfaceName, "up"};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	
	
}
