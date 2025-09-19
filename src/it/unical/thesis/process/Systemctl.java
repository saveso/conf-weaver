package it.unical.thesis.process;

public class Systemctl extends AbstractCommand{

	private static final String NAME = "systemctl";
	
	public Systemctl()
	{

	}



	private void stop(String serviceName)
	{
		final String[] command = {NAME, "stop", serviceName};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	

	private void restart(String serviceName)
	{
		final String[] command = {NAME, "restart", serviceName};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	
	
	public void stopNetworkManagerAndWpaSupplicant()
	{
		stop("NetworkManager");
		stop("wpa_supplicant");
	}
	
	public void restartNetworkManager()
	{
		//restart("wpa_supplicant");
		restart("NetworkManager");
	}
	

}
