package it.unical.thesis.process;

import java.util.List;


public abstract class AbstractWpaSupplicant extends AbstractCommand{

	protected static final String NAME = "wpa_supplicant";

	private static final int SCAN_DURATION = 5;


	protected AbstractWpaSupplicant()
	{

	}


	public List<String> connect(String interfaceName, String networkConfPath, String wifiDriverBackend)
	{
		final String[] command = {getCommandName(),
				"-i", interfaceName,
				"-c", networkConfPath,
				"-D", wifiDriverBackend,
				"-dd"};
		this.execute(command);
		ProcessReader processReader = new ProcessReader(getInputStream());
		processReader.start();
		this.waitForCompletion(SCAN_DURATION);
		this.destroyProcess();
		try {
			processReader.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return processReader.getLines();
	}


	protected abstract String getCommandName();


}
