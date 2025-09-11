package it.unical.thesis.process;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

public abstract class AbstractCommand{

	private Process process;


	protected AbstractCommand()
	{

	}


	protected void execute(String... fullCommand)
	{
		this.printCommand(fullCommand);

		ProcessBuilder builder = new ProcessBuilder(fullCommand);
		builder.redirectErrorStream(true);
		try {
			this.process = builder.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
	protected void waitIndefinitelyForCompletion()
	{
		try {
			this.process.waitFor();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	

	protected boolean waitForCompletion(int seconds)
	{
		try {
			return this.process.waitFor(seconds,TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return false;
	}

	protected void KillWithSigint()
	{
		new Kill().sigint(this.process.pid());
	}


	protected void destroyProcess()
	{
		this.process.destroy();
		//this.process.destroyForcibly();
	}


	private void printCommand(String[] fullCommand)
	{
		System.out.println("Executing: ");
		for(String string: fullCommand)
		{
			System.out.print(string+" ");
		}
		System.out.println();
	}

	
	protected InputStream getInputStream()
	{
		return this.process.getInputStream();
	}


}
