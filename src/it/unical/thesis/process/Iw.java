package it.unical.thesis.process;

import java.util.List;

import it.unical.thesis.reader.ProcessReader;

public class Iw extends AbstractCommand{

	private static final String NAME = "iw";
	
	
	public Iw()
	{

	}


	public List<String> startScan(String interfaceName)
	{
		final String[] command = {NAME, "dev", interfaceName, "scan"};
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
	

	public void setChannel(String interfaceName, String channel)
	{
		final String[] command = {NAME, "dev", interfaceName, "set", "channel", channel};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	
	
	public void setType(String interfaceName, String type)
	{
		final String[] command = {NAME, "dev", interfaceName, "set", "type", type};
		this.execute(command);
		this.waitIndefinitelyForCompletion();
	}
	
	
	public List<String> listWirelessInterfaces()
	{
		final String[] command = {NAME, "dev"};
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