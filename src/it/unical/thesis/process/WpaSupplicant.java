package it.unical.thesis.process;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;

import it.unical.thesis.reader.ProcessReader;

public class WpaSupplicant extends AbstractCommand{

	private static final String NAME = "wpa_supplicant";
	
	private static final int SCAN_DURATION = 5;

	private boolean usePatch;
	
	private static final String CERTS_CHAIN_PATH = "/tmp/received_cert_chain.pem";
	
	
	public WpaSupplicant(boolean usePatch)
	{
		this.usePatch = usePatch;
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

	
	private String getCommandName()
	{
		if(usePatch)
			return "./exe/"+NAME;
		return NAME;
	}
	
	
	public void moveCertsChainTo(String path)
	{
		File file = new File(CERTS_CHAIN_PATH);
		if(file.exists())
		{
	        try {
				Files.move(Paths.get(file.getAbsolutePath()), Paths.get(path+"/"+file.getName()), StandardCopyOption.REPLACE_EXISTING);
			} catch (IOException e) {
				e.printStackTrace();
			} 
		}
	}
	

	public boolean isUsePatch() {
		return usePatch;
	}
	
	
}