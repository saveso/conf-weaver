package it.unical.thesis.main;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import it.unical.thesis.data.AccessPoint;
import it.unical.thesis.data.CertificateInfo;
import it.unical.thesis.generator.HostapdConfGenerator;
import it.unical.thesis.generator.OpenSSLConfigGeneratorNoTemplates;
import it.unical.thesis.generator.WpaConfGenerator;
import it.unical.thesis.parser.IwParser;
import it.unical.thesis.parser.SSLCertificateParser;
import it.unical.thesis.parser.TsharkParser;
import it.unical.thesis.process.Ip;
import it.unical.thesis.process.Iw;
import it.unical.thesis.process.Systemctl;
import it.unical.thesis.process.Bootstrap;
import it.unical.thesis.process.Id;
import it.unical.thesis.process.Tshark;
import it.unical.thesis.process.WpaSupplicant;
import it.unical.thesis.process.WpaSupplicantPatched;
import it.unical.thesis.utils.CertificateChainAnalyzer;
import it.unical.thesis.utils.DateConverter;
import it.unical.thesis.utils.FileUtils;
import it.unical.thesis.utils.MacAddressChanger;
import it.unical.thesis.utils.OptionChooser;
import it.unical.thesis.utils.SerialConverter;

public class Main {

	private static final String TMP_PATH = "./tmp";

	//private static final String CNF_TEMPLATES_PATH = "./templates";

	private static final String CAPTURE_FULL_PATH = "./tmp/capture-01.cap";

	private static final String FREERADIUS_CERTS_PATH = "/usr/local/etc/raddb/certs";

	private static final String WPA_SUPPLICANT_CONF_PATH = "./tmp/wpa_supplicant.conf";

	private static final String WIFI_DRIVER_BACKEND = "nl80211";

	private static final String CA_CNF_FILE_NAME = "ca.cnf";

	private static final String SERVER_CNF_FILE_NAME = "server.cnf";

	private static final String CLIENT_CNF_FILE_NAME = "client.cnf";

	private static final String XPEXTENSIONS_CNF_FILE_NAME = "xpextensions";

	private static final String BLACKLIST_PATH = "./tmp/blacklist.txt";	

	private static final Pattern LINUX_PATTERN = Pattern.compile("linux", Pattern.CASE_INSENSITIVE);

	private static final String[] REQUIRED_TOOLS = {"tshark"};
	
	private static final String BASH_BOOTSTRAP_PATH = "./bash_scripts/bootstrap_enhanced";



	private static void printRequiredTools()
	{
		for(String toolName: REQUIRED_TOOLS)
		{
			System.out.println("This tool require "+ toolName +" installed in order to work.");
		}
	}


	private static void moveGeneratedCnfFiles(String generatedFilesPath, String certsPath)
	{
		File generatedFilesPathFile = new File(generatedFilesPath);
		if(generatedFilesPathFile.exists())
		{
			File[] files = generatedFilesPathFile.listFiles();
			for(File file: files)
			{
				if(file.getName().equals(CA_CNF_FILE_NAME) || file.getName().equals(SERVER_CNF_FILE_NAME)
						|| file.getName().equals(CLIENT_CNF_FILE_NAME) || file.getName().equals(XPEXTENSIONS_CNF_FILE_NAME))					try {
							Files.move(Paths.get(file.getAbsolutePath()), Paths.get(certsPath+"/"+file.getName()), StandardCopyOption.REPLACE_EXISTING);
						} catch (IOException e) {
							e.printStackTrace();
						}
			}
		}
	}


	private static void cleanUpCertsAndGenerateNewCertificates(String certsPath, List<CertificateInfo> certificatesList)
	{
		CertificateInfo caInfo = CertificateChainAnalyzer.getRootCACertificate(certificatesList);
		CertificateInfo serverInfo = CertificateChainAnalyzer.getServerCertificate(certificatesList);

		//OpenSSLConfigGenerator generator = new OpenSSLConfigGenerator();
		OpenSSLConfigGeneratorNoTemplates generator = new OpenSSLConfigGeneratorNoTemplates();

		try {			
			generator.generateAllConfigs(caInfo, serverInfo, null, TMP_PATH);
			File freeradiusCertsDir = new File(certsPath);
			if(freeradiusCertsDir.exists()) {
				cleanUpCerts(certsPath);

				//move or copy .cnf files from TMP path to certsPath
				moveGeneratedCnfFiles(TMP_PATH, certsPath);
				//copy bootstrap script to certsPath
				File bootstrapFile = new File(BASH_BOOTSTRAP_PATH);
				if(!bootstrapFile.exists())
					Files.copy(Paths.get(bootstrapFile.getAbsolutePath()), Paths.get(certsPath+"/"+bootstrapFile.getName()), StandardCopyOption.REPLACE_EXISTING);

				Bootstrap bootstrap = new Bootstrap(certsPath);
				bootstrap.startGeneration(
						SerialConverter.convertSerialToOpenSSLFormat(caInfo.getSerialNumber()), 
						DateConverter.convertToOpenSSLFormat(caInfo.getNotBefore()), 
						DateConverter.convertToOpenSSLFormat(caInfo.getNotAfter()), 
						SerialConverter.convertSerialToOpenSSLFormat(serverInfo.getSerialNumber()), 
						DateConverter.convertToOpenSSLFormat(serverInfo.getNotBefore()), 
						DateConverter.convertToOpenSSLFormat(serverInfo.getNotAfter()));
			}
		} catch (IOException e) {
			System.err.println("Error during writing .cnf files: " + e.getMessage());
			e.printStackTrace();
		}
	}


	private static List<CertificateInfo> retrieveRadiusCertificates(String ssid, Integer pmf, String interfaceName)
	{
		WpaConfGenerator wpaGenerator = new WpaConfGenerator(ssid, pmf, "username_test", "password_test");
		if(wpaGenerator.writeToFile(WPA_SUPPLICANT_CONF_PATH))
		{
			WpaSupplicantPatched wpaSupplicantPatched = new WpaSupplicantPatched();
			List<String> outputLines = wpaSupplicantPatched.connect(interfaceName, WPA_SUPPLICANT_CONF_PATH, WIFI_DRIVER_BACKEND);

			if(wpaSupplicantPatched.certsChainExists())
			{
				wpaSupplicantPatched.moveCertsChainTo(TMP_PATH);
			}
			else
			{
				WpaSupplicant wpaSupplicant = new WpaSupplicant();
				outputLines = wpaSupplicant.connect(interfaceName, WPA_SUPPLICANT_CONF_PATH, WIFI_DRIVER_BACKEND);
			}

			List<CertificateInfo> certificatesList = SSLCertificateParser.parseMultipleCertificates(outputLines);
			for(CertificateInfo certificate: certificatesList)
			{
				System.out.println(certificate);

			}
			System.out.println("Extracted certificates (duplicates): "+certificatesList.size());
			List<CertificateInfo> certificatesListDuplicatesLess = CertificateChainAnalyzer.removeDuplicates(certificatesList);
			System.out.println("Extracted certificates (without duplicates): "+certificatesListDuplicatesLess.size());
			return certificatesListDuplicatesLess;
		}
		return null;
	}


	private static AccessPoint analyzeNetworkGenerateBlacklistAndGetAccessPointData(String chosenWirelessInterface, OptionChooser optionChooser, Iw iw, Ip ip)
	{
		Map<String,AccessPoint> accessPointsMapIw = IwParser.parseIwScanOutput(iw.startScan(chosenWirelessInterface));
		List<AccessPoint> accessPointsList = new ArrayList<>(accessPointsMapIw.values());		
		System.out.println("Available access points");
		for(int i=0;i<accessPointsList.size();i++)
		{
			System.out.println(i+1+" for "+accessPointsList.get(i).getSsid()+", "+accessPointsList.get(i).getBssid());
		}
		System.out.println("Choose an access point:");
		int choice = optionChooser.choose(accessPointsList.size());
		if(choice==0)
		{
			System.err.println("Cannot continue without selecting an access point!");	
			return null;
		}
		int chosenIndex = choice-1;
		AccessPoint iwAP = accessPointsList.get(chosenIndex);
		//System.out.println(iwAP);
		String blacklist = generateBlackList(accessPointsList, iwAP);
		FileUtils.writeToFile(BLACKLIST_PATH, blacklist);
		/*List<String> output = airmon.startMonitorMode(chosenWirelessInterface);
		String monitorInterface = AirmonParser.parseNewMonitorInterface(output);
		String usingInterface;
		if(monitorInterface!=null)
			usingInterface=monitorInterface;
		else
			usingInterface=chosenWirelessInterface;
		System.out.println("Using interface: "+usingInterface);*/	   
		changeToMonnitorMode(chosenWirelessInterface, ip, iw);
		//Airodump airodump = new Airodump();
		//airodump.startScan(usingInterface,CAPTURE_INCOMPLETE_FILE_PATH,"pcap", iwAP.getBssid(),String.valueOf(iwAP.getChannel()));
		iw.setChannel(chosenWirelessInterface, String.valueOf(iwAP.getChannel()));
		//TODO I should check if tshark is installed
		Tshark tshark = new Tshark();
		tshark.startScan(chosenWirelessInterface, CAPTURE_FULL_PATH, iwAP.getBssid());
		List<String> outputTshark = tshark.analyzeWithFilters(CAPTURE_FULL_PATH);
		AccessPoint tsharkAP = TsharkParser.parseFromTsharkOutput(outputTshark);
		System.out.println(tsharkAP);
		//deleteFile(CAPTURE_FULL_FILE_PATH);
		//airmon.stopMonitorMode(usingInterface);
		changeToManagedMode(chosenWirelessInterface, ip, iw);

		return tsharkAP;
	}


	private static void cleanUpCerts(String certsPath)
	{
		System.out.println("Cleanup of certs folder...");

		File dir = new File(certsPath);
		File[] files = dir.listFiles();
		for(File f: files)
		{
			if(f.getName().endsWith(".pem") ||
					f.getName().endsWith(".der") ||
					f.getName().endsWith(".csr") ||
					f.getName().endsWith(".crt") ||
					f.getName().endsWith(".key") ||
					f.getName().endsWith(".p12") ||
					f.getName().startsWith("serial") ||
					f.getName().startsWith("index.txt"))
				f.delete();
		}		
	}


	private static String chooseInterface(List<String> interfacesNames, OptionChooser optionChooser)
	{
		System.out.println("Available interfaces");
		for(int i=0;i<interfacesNames.size();i++)
		{
			System.out.println(i+1+" for "+interfacesNames.get(i));
		}
		System.out.println("Choose an interface:");
		int choice = optionChooser.choose(interfacesNames.size());
		if(choice==0)
			return null;
		String chosenInterface = interfacesNames.get(choice-1);
		System.out.println("Chosen interface: "+chosenInterface);
		return chosenInterface;
	}


	private static String generateBlackList(List<AccessPoint> accessPointsList, AccessPoint chosenAP)
	{
		StringBuilder stringBuilder = new StringBuilder();		
		for(int i=0;i<accessPointsList.size();i++)
		{
			if(accessPointsList.get(i).getSsid().equals(chosenAP.getSsid()) /*&& i!=chosenIndex*/)
				stringBuilder.append(accessPointsList.get(i).getBssid()).append("\n");
		}
		return stringBuilder.toString();
	}


	private static void changeToMonnitorMode(String interfaceName, Ip ip, Iw iw)
	{
		ip.down(interfaceName);
		iw.setType(interfaceName, "monitor");
		ip.up(interfaceName);
	}

	private static void changeToManagedMode(String interfaceName, Ip ip, Iw iw)
	{
		ip.down(interfaceName);
		iw.setType(interfaceName, "managed");
		ip.up(interfaceName);
	}



	public static void main(String[] args) {
		System.out.println("Educational purposes only!");
		if(!LINUX_PATTERN.matcher(System.getProperty("os.name")).find())
		{
			System.out.println("This software currently works only on linux.");
			return;
		}
		
		System.out.println("This software requires root access to work.");
		Id id = new Id();
		List<String> idOutputLines = id.printUserId();
		int userId = Integer.parseInt(idOutputLines.getFirst());
		if(userId==0)
			System.out.println("Root access detected!");
		else
		{
			System.out.println("Root access NOT detected!");
			return;
		}
		printRequiredTools();
		File outputDir = new File(TMP_PATH);
		if(!outputDir.exists())
			outputDir.mkdir();

		System.out.println("conf-weaver starting...");
		//TODO should I use java.net?
		//List<String> wirelessInterfaces = NetworkInterfaceManager.getNetworkInterfacesNames(NetworkType.WIFI);
		Systemctl systemctl = new Systemctl();
		systemctl.stopNetworkManagerAndWpaSupplicant();
		Iw iw = new Iw();
		//Airmon airmon = new Airmon();
		//airmon.checkKill();
		//List<String> output = airmon.listWirelessInterfaces();
		List<String> output = iw.listWirelessInterfaces();
		List<String> wirelessInterfaces = IwParser.parseInterfaceNames(output);
		OptionChooser optionChooser = new OptionChooser();		
		String chosenWirelessInterface = chooseInterface(wirelessInterfaces, optionChooser);
		if(chosenWirelessInterface!=null)
		{
			Ip ip = new Ip();
			ip.down(chosenWirelessInterface);
			ip.up(chosenWirelessInterface);
			AccessPoint accessPoint = analyzeNetworkGenerateBlacklistAndGetAccessPointData(chosenWirelessInterface, optionChooser, iw, ip);
			//optionChooser.closeScanner();
			if(accessPoint!=null) {
				accessPoint.setBssid(MacAddressChanger.randomizeLastByte(accessPoint.getBssid()));
				HostapdConfGenerator hostapdConfGenerator = new HostapdConfGenerator(chosenWirelessInterface, WIFI_DRIVER_BACKEND, accessPoint);
				hostapdConfGenerator.writeToFile(TMP_PATH);

				if(accessPoint.supportsIeee8021x()) {
					List<CertificateInfo> certificatesList = retrieveRadiusCertificates(accessPoint.getSsid(),accessPoint.getIeee80211w(),chosenWirelessInterface);
					if(certificatesList!=null) {
						cleanUpCertsAndGenerateNewCertificates(FREERADIUS_CERTS_PATH, certificatesList);
					}
				}
			}
		}
		else {
			System.err.println("Cannot continue without selecting an interface!");
		}

		optionChooser.closeScanner();
		systemctl.restartNetworkManager();
	}


}
