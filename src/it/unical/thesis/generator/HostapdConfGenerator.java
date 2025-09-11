package it.unical.thesis.generator;

import it.unical.thesis.data.AccessPoint;
import it.unical.thesis.utils.FileUtils;


public class HostapdConfGenerator {
	
	private final String chosenWirelessInterface;
	private final String driverName;
    private final AccessPoint accessPoint;

    public HostapdConfGenerator(String chosenWirelessInterface, String driverName, AccessPoint accessPoint) {
        this.chosenWirelessInterface = chosenWirelessInterface;
        this.driverName = driverName;
    	this.accessPoint = accessPoint;
    }
    

    public boolean writeToFile(String directory) {
        String filePath = directory + "/hostapd-" + accessPoint.getSsid() + ".conf";
        return FileUtils.writeToFile(filePath, generateHostapdConf());
    }
    
    
    private String generateHostapdConf() {
        StringBuilder conf = new StringBuilder();

        conf.append("interface=").append(chosenWirelessInterface).append("\n");
        conf.append("driver=").append(driverName != null ? driverName : "nl80211").append("\n");

        if (accessPoint.getSsid() != null) conf.append("ssid=").append(accessPoint.getSsid()).append("\n");
        if (accessPoint.getBssid() != null) conf.append("bssid=").append(accessPoint.getBssid()).append("\n");
        if (accessPoint.getChannel() != null) conf.append("channel=").append(accessPoint.getChannel()).append("\n");
        if (accessPoint.getHwMode() != null) conf.append("hw_mode=").append(accessPoint.getHwMode()).append("\n");

        if (accessPoint.getWpa() != null) conf.append("wpa=").append(accessPoint.getWpa()).append("\n");
        if (accessPoint.getWpaKeyMgmt() != null) conf.append("wpa_key_mgmt=").append(accessPoint.getWpaKeyMgmt()).append("\n");
        if (accessPoint.getRsnPairwise() != null) conf.append("rsn_pairwise=").append(accessPoint.getRsnPairwise()).append("\n");
        if (accessPoint.getWpaPairwise() != null) conf.append("wpa_pairwise=").append(accessPoint.getWpaPairwise()).append("\n");

        if (accessPoint.getWpaGroupwise() != null) conf.append("wpa_group=").append(accessPoint.getWpaGroupwise()).append("\n");
        if (accessPoint.getRsnGroupwise() != null) conf.append("rsn_group=").append(accessPoint.getRsnGroupwise()).append("\n");
        if (accessPoint.getGroupMgmtCipher() != null) conf.append("group_mgmt_cipher=").append(accessPoint.getGroupMgmtCipher()).append("\n");
        if (accessPoint.getIeee80211w() != null) conf.append("ieee80211w=").append(accessPoint.getIeee80211w()).append("\n");

        if (accessPoint.getIeee80211n() != null && accessPoint.getIeee80211n()) conf.append("ieee80211n=1\n");
        if (accessPoint.getIeee80211ac() != null && accessPoint.getIeee80211ac()) conf.append("ieee80211ac=1\n");
        if (accessPoint.getIeee80211ax() != null && accessPoint.getIeee80211ax()) conf.append("ieee80211ax=1\n");
        if (accessPoint.getHtCapab() != null) conf.append("ht_capab=").append(accessPoint.getHtCapab()).append("\n");
        if (accessPoint.getVhtCapab() != null) conf.append("vht_capab=").append(accessPoint.getVhtCapab()).append("\n");
        if (accessPoint.getHeCapab() != null) conf.append("he_capab=").append(accessPoint.getHeCapab()).append("\n");
        if (accessPoint.getVhtOperChwidth() != null) conf.append("vht_oper_chwidth=").append(accessPoint.getVhtOperChwidth()).append("\n");
        if (accessPoint.getHeOperChwidth() != null) conf.append("he_oper_chwidth=").append(accessPoint.getHeOperChwidth()).append("\n");
        if (accessPoint.getVhtOperCentrFreqSeg0Idx() != null) conf.append("vht_oper_centr_freq_seg0_idx=").append(accessPoint.getVhtOperCentrFreqSeg0Idx()).append("\n");
        if (accessPoint.getHeBssColor() != null) conf.append("he_bss_color=").append(accessPoint.getHeBssColor()).append("\n");
        if (accessPoint.getHeDefaultPeDuration() != null) conf.append("he_default_pe_duration=").append(accessPoint.getHeDefaultPeDuration()).append("\n");

        if (accessPoint.getSupportedRates() != null) conf.append("supported_rates=").append(accessPoint.getSupportedRates()).append("\n");
        if (accessPoint.getBasicRates() != null) conf.append("basic_rates=").append(accessPoint.getBasicRates()).append("\n");
        if (accessPoint.getCountryCode() != null) conf.append("country_code=").append(accessPoint.getCountryCode()).append("\n");
        if (accessPoint.getIeee80211d() != null && accessPoint.getIeee80211d()) conf.append("ieee80211d=1\n");
        if (accessPoint.getIeee80211h() != null && accessPoint.getIeee80211h()) conf.append("ieee80211h=1\n");
        if (accessPoint.getWmmEnabled() != null && accessPoint.getWmmEnabled()) conf.append("wmm_enabled=1\n");

        if (accessPoint.getBeaconInt() != null) conf.append("beacon_int=").append(accessPoint.getBeaconInt()).append("\n");
        if (accessPoint.getDtimPeriod() != null) conf.append("dtim_period=").append(accessPoint.getDtimPeriod()).append("\n");

        if (accessPoint.getIgnoreBroadcastSsid() != null && accessPoint.getIgnoreBroadcastSsid()) conf.append("ignore_broadcast_ssid=1\n");
        if (accessPoint.getWpsState() != null) conf.append("wps_state=").append(accessPoint.getWpsState()).append("\n");
        if (accessPoint.getRrmNeighborReport() != null && accessPoint.getRrmNeighborReport()) conf.append("rrm_neighbor_report=1\n");
        if (accessPoint.getRrmBeaconReport() != null && accessPoint.getRrmBeaconReport()) conf.append("rrm_beacon_report=1\n");
        if (accessPoint.getMobilityDomain() != null) conf.append("mobility_domain=").append(accessPoint.getMobilityDomain()).append("\n");

        if (accessPoint.getVendorElements() != null) conf.append("vendor_elements=").append(accessPoint.getVendorElements()).append("\n");

        if (accessPoint.supportsIeee8021x()) {
            conf.append("ieee8021x=1\n");
            conf.append("eapol_key_index_workaround=0\n");
            conf.append("own_ip_addr=127.0.0.1\n");
            conf.append("auth_server_addr=127.0.0.1\n");
            conf.append("auth_server_port=1812\n");
            conf.append("auth_server_shared_secret=testing123\n");
        }
        else {
            conf.append("wpa_passphrase=").append("testing123").append("\n");
        }
        
        return conf.toString();
    }
      
    
}