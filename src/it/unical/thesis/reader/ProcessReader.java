package it.unical.thesis.reader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ProcessReader extends Thread {
	
	//private volatile boolean finished;
	
	private InputStream inputStream;
	
	private List<String> lines;

	
	public ProcessReader(InputStream inputStream)
	{
		this.inputStream = inputStream;
		this.lines = new ArrayList<>();
	}
	
	
	@Override
	public void run()
	{
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		String line;
		try {
			while ((line = reader.readLine()) != null) {
				//read everything
				System.out.println(line);
				lines.add(line);
			}
			reader.close();
		} catch (IOException e) {
		}
		finally {
			try {
				reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	


	public List<String> getLines() {
		return lines;
	}


}
