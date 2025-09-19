package it.unical.thesis.process;

import java.util.List;

public class Id extends AbstractCommand{

	private static final String NAME = "id";


	public Id()
	{

	}


	
	public List<String> printUserId()
	{
		final String[] command = {NAME, "-u"};
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
