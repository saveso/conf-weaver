package it.unical.thesis.process;

import java.util.List;

import it.unical.thesis.reader.ProcessReader;

public class Tshark extends AbstractCommand{

	private static final String NAME = "tshark";
		
	private static final int SCAN_DURATION = 15;
	
	
	public Tshark()
	{

	}


	public void startScan(String interfaceName, String filePath, String bssid)
	{
		// Build capture filter for target BSSID
		String captureFilter = String.format(
			    "(type mgt subtype beacon and wlan addr2 %s) or " +
			    "(type mgt subtype probe-resp and wlan addr2 %s) or " +
			    "(type mgt subtype probe-req and wlan addr1 %s) or" +
			    "(type mgt subtype assoc-resp and wlan addr2 %s)",
			    bssid, bssid, bssid, bssid);
		final String[] command = {NAME, "-i", interfaceName, "-f", captureFilter, "-w", filePath};
		this.execute(command);
		ProcessReader processReader = new ProcessReader(getInputStream());
		processReader.start();
		this.waitForCompletion(SCAN_DURATION);
		this.destroyProcess();
	}
	

	public List<String> analyzeWithFilters(String fileName) {
		String[] command = {
			    "tshark",
			    "-r", fileName,
			    "-T", "fields",
	            "-E", "separator=|",
	            "-E", "quote=d",
	            "-E", "occurrence=a",
	            // Campi base (0-3)
	            "-e", "wlan.bssid",
	            "-e", "wlan.ssid", 
	            "-e", "wlan_radio.channel",
	            "-e", "wlan.ds.current_channel",
	            // Frequenza e modalità (4-7)
	            "-e", "radiotap.channel.freq",
	            "-e", "radiotap.channel.flags.2ghz",
	            "-e", "radiotap.channel.flags.5ghz",
	            "-e", "radiotap.channel.flags.ofdm",
	            // Beacon e timing (8-9)
	            "-e", "wlan.fixed.beacon",
	            "-e", "wlan.tim.dtim_period",
	            // Capabilities (10-12)
	            "-e", "wlan.fixed.capabilities.privacy",
	            "-e", "wlan.fixed.capabilities.short_preamble",
	            "-e", "wlan.fixed.capabilities.short_slot_time",
	            // 802.11n/HT (13-14)
	            "-e", "wlan.ht.capabilities",
	            "-e", "wlan.ht.capabilities.ldpccoding",
	            // 802.11ac/VHT (15-17)
	            "-e", "wlan.vht.capabilities",
	            "-e", "wlan.vht.capabilities.rxldpc",
	            "-e", "wlan.vht.op.channelwidth",
	            // Rates (18-19)
	            "-e", "wlan.supported_rates",
	            "-e", "wlan.extended_supported_rates",
	            // Paese e regolamentazione (20-21)
	            "-e", "wlan.country_info.code",
	            "-e", "wlan.country_info.environment",
	            // Sicurezza RSN/WPA (22-28)
	            "-e", "wlan.rsn.version",
	            "-e", "wlan.rsn.akms.type",
	            "-e", "wlan.rsn.gcs.type",
	            "-e", "wlan.rsn.pcs.type",
	            "-e", "wlan.rsn.gmcs.type",
	            "-e", "wlan.rsn.capabilities.mfpc",
	            "-e", "wlan.rsn.capabilities.mfpr",
	            // RRM (29-31)
	            "-e", "wlan.fixed.capabilities.radio_measurement",
	            "-e", "wlan.rmcap",
	            "-e", "wlan.rmcap.b1",
	            // WPS (32-36)
	            "-e", "wps.version",
	            "-e", "wps.config_methods",
	            "-e", "wps.device_name",
	            "-e", "wps.manufacturer",
	            "-e", "wps.model_name",
	            // 802.11ax/HE (37-41) - AGGIORNATO CON FILTRI CORRETTI
	            "-e", "wlan.ext_tag.number",
	            "-e", "wlan.ext_tag.he_mac_caps",
	            "-e", "wlan.ext_tag.he_phy_cap.fbytes",
	            "-e", "wlan.ext_tag.bss_color_information.bss_color",
	            "-e", "wlan.ext_tag.he_operation.default_pe_duration",
	            // Extended capabilities (42)
	            "-e", "wlan.extcap",
	            // Vendor elements (43-45)
	            "-e", "wlan.tag.vendor.oui.type",
	            "-e", "wlan.tag.vendor.data",
	            "-e", "wlan.tag.oui",
	            // SSID nascosto (46)
	            "-e", "wlan.tag.length",
	            // Campi informativi (47-49)
	            "-e", "frame.time_relative",
	            "-e", "radiotap.dbm_antsignal",
	            "-e", "radiotap.antenna"
			};

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