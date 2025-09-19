package it.unical.thesis.process;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

public class WpaSupplicantPatched extends AbstractWpaSupplicant {
	
	private static final String CERTS_CHAIN_PATH = "/tmp/received_cert_chain.pem";

	
	
	public WpaSupplicantPatched()
	{
		
	}
	
	@Override
	protected String getCommandName() {
		return "./exe/"+NAME;
	}
	
	
	
	public boolean certsChainExists()
	{
		File file = new File(CERTS_CHAIN_PATH);
		return file.exists();
	}
	
	
	public void moveCertsChainTo(String path)
	{
		File file = new File(CERTS_CHAIN_PATH);
		//if(file.exists())
		//{
	        try {
				Files.move(Paths.get(file.getAbsolutePath()), Paths.get(path+"/"+file.getName()), StandardCopyOption.REPLACE_EXISTING);
			} catch (IOException e) {
				e.printStackTrace();
			} 
		//}
	}
	
	
}
