package it.unical.thesis.data;

public class AccessPoint {
    
    private String bssid;
    private String ssid;
    private Integer channel;
    private String hwMode;
    
    private Integer wpa;
    private String wpaKeyMgmt;
    private String rsnPairwise;
    private String wpaPairwise;
    private String wpaGroupwise;
    private String rsnGroupwise;
    private String groupMgmtCipher;
    private Integer ieee80211w;
    private Boolean ieee8021x;
    
    private Boolean ieee80211n;
    private Boolean ieee80211ac;
    private Boolean ieee80211ax;
    private String htCapab;
    private String vhtCapab;
    private String heCapab;
    private Integer vhtOperChwidth;
    private Integer heOperChwidth;
    private Integer vhtOperCentrFreqSeg0Idx;
    private Integer heBssColor;
    private Integer heDefaultPeDuration;
    
    private String supportedRates;
    private String basicRates;
    private String countryCode;
    private Boolean ieee80211d;
    private Boolean ieee80211h;
    private Boolean wmmEnabled;
    
    private Integer beaconInt;
    private Integer dtimPeriod;
    
    private Boolean ignoreBroadcastSsid;
    private Integer wpsState;
    private Boolean rrmNeighborReport;
    private Boolean rrmBeaconReport;
    private String mobilityDomain;
    
    private String vendorElements;
    
    
    public AccessPoint() {
    }
    
    public AccessPoint(String bssid, String ssid, Integer channel) {
        this.bssid = bssid;
        this.ssid = ssid;
        this.channel = channel;
    }
    
    
    public String getBssid() { return bssid; }
    public void setBssid(String bssid) { this.bssid = bssid; }
    
    public String getSsid() { return ssid; }
    public void setSsid(String ssid) { this.ssid = ssid; }
    
    public Integer getChannel() { return channel; }
    public void setChannel(Integer channel) { this.channel = channel; }
    
    public String getHwMode() { return hwMode; }
    public void setHwMode(String hwMode) { this.hwMode = hwMode; }
    
    public Integer getWpa() { return wpa; }
    public void setWpa(Integer wpa) { this.wpa = wpa; }
    
    public String getWpaKeyMgmt() { return wpaKeyMgmt; }
    public void setWpaKeyMgmt(String wpaKeyMgmt) { this.wpaKeyMgmt = wpaKeyMgmt; }
    
    public String getRsnPairwise() { return rsnPairwise; }
    public void setRsnPairwise(String rsnPairwise) { this.rsnPairwise = rsnPairwise; }
    
    public String getWpaPairwise() { return wpaPairwise; }
    public void setWpaPairwise(String wpaPairwise) { this.wpaPairwise = wpaPairwise; }
    
    public String getGroupMgmtCipher() { return groupMgmtCipher; }
    public void setGroupMgmtCipher(String groupMgmtCipher) { this.groupMgmtCipher = groupMgmtCipher; }
    
    public Integer getIeee80211w() { return ieee80211w; }
    public void setIeee80211w(Integer ieee80211w) { this.ieee80211w = ieee80211w; }
    
    public Boolean getIeee8021x() { return ieee8021x; }
    public void setIeee8021x(Boolean ieee8021x) { this.ieee8021x = ieee8021x; }
    
    public Boolean getIeee80211n() { return ieee80211n; }
    public void setIeee80211n(Boolean ieee80211n) { this.ieee80211n = ieee80211n; }
    
    public Boolean getIeee80211ac() { return ieee80211ac; }
    public void setIeee80211ac(Boolean ieee80211ac) { this.ieee80211ac = ieee80211ac; }
    
    public Boolean getIeee80211ax() { return ieee80211ax; }
    public void setIeee80211ax(Boolean ieee80211ax) { this.ieee80211ax = ieee80211ax; }
    
    public String getHtCapab() { return htCapab; }
    public void setHtCapab(String htCapab) { this.htCapab = htCapab; }
    
    public String getVhtCapab() { return vhtCapab; }
    public void setVhtCapab(String vhtCapab) { this.vhtCapab = vhtCapab; }
    
    public String getHeCapab() { return heCapab; }
    public void setHeCapab(String heCapab) { this.heCapab = heCapab; }
    
    public Integer getVhtOperChwidth() { return vhtOperChwidth; }
    public void setVhtOperChwidth(Integer vhtOperChwidth) { this.vhtOperChwidth = vhtOperChwidth; }
    
    public Integer getHeOperChwidth() { return heOperChwidth; }
    public void setHeOperChwidth(Integer heOperChwidth) { this.heOperChwidth = heOperChwidth; }
    
    public Integer getVhtOperCentrFreqSeg0Idx() { return vhtOperCentrFreqSeg0Idx; }
    public void setVhtOperCentrFreqSeg0Idx(Integer vhtOperCentrFreqSeg0Idx) { 
        this.vhtOperCentrFreqSeg0Idx = vhtOperCentrFreqSeg0Idx; 
    }
    
    public Integer getHeBssColor() { return heBssColor; }
    public void setHeBssColor(Integer heBssColor) { this.heBssColor = heBssColor; }
    
    public Integer getHeDefaultPeDuration() { return heDefaultPeDuration; }
    public void setHeDefaultPeDuration(Integer heDefaultPeDuration) { this.heDefaultPeDuration = heDefaultPeDuration; }
    
    public String getSupportedRates() { return supportedRates; }
    public void setSupportedRates(String supportedRates) { this.supportedRates = supportedRates; }
    
    public String getBasicRates() { return basicRates; }
    public void setBasicRates(String basicRates) { this.basicRates = basicRates; }
    
    public String getCountryCode() { return countryCode; }
    public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
    
    public Boolean getIeee80211d() { return ieee80211d; }
    public void setIeee80211d(Boolean ieee80211d) { this.ieee80211d = ieee80211d; }
    
    public Boolean getIeee80211h() { return ieee80211h; }
    public void setIeee80211h(Boolean ieee80211h) { this.ieee80211h = ieee80211h; }
    
    public Boolean getWmmEnabled() { return wmmEnabled; }
    public void setWmmEnabled(Boolean wmmEnabled) { this.wmmEnabled = wmmEnabled; }
    
    public Integer getBeaconInt() { return beaconInt; }
    public void setBeaconInt(Integer beaconInt) { this.beaconInt = beaconInt; }
    
    public Integer getDtimPeriod() { return dtimPeriod; }
    public void setDtimPeriod(Integer dtimPeriod) { this.dtimPeriod = dtimPeriod; }
    
    public Boolean getIgnoreBroadcastSsid() { return ignoreBroadcastSsid; }
    public void setIgnoreBroadcastSsid(Boolean ignoreBroadcastSsid) { 
        this.ignoreBroadcastSsid = ignoreBroadcastSsid; 
    }
    
    public Integer getWpsState() { return wpsState; }
    public void setWpsState(Integer wpsState) { this.wpsState = wpsState; }
    
    public Boolean getRrmNeighborReport() { return rrmNeighborReport; }
    public void setRrmNeighborReport(Boolean rrmNeighborReport) { this.rrmNeighborReport = rrmNeighborReport; }
    
    public Boolean getRrmBeaconReport() { return rrmBeaconReport; }
    public void setRrmBeaconReport(Boolean rrmBeaconReport) { this.rrmBeaconReport = rrmBeaconReport; }
    
    public String getMobilityDomain() { return mobilityDomain; }
    public void setMobilityDomain(String mobilityDomain) { this.mobilityDomain = mobilityDomain; }
    
    public String getVendorElements() { return vendorElements; }
    public void setVendorElements(String vendorElements) { this.vendorElements = vendorElements; }
    
    public String getWpaGroupwise() { return wpaGroupwise; }
    public void setWpaGroupwise(String wpaGroupwise) { this.wpaGroupwise = wpaGroupwise; }
    public String getRsnGroupwise() { return rsnGroupwise; }
    public void setRsnGroupwise(String rsnGroupwise) { this.rsnGroupwise = rsnGroupwise; }
    
    
    public boolean isValid() {
        return bssid != null && ssid != null && channel != null && hwMode != null;
    }
    
    public boolean isOpen() {
        return wpa == null || wpa == 0;
    }
    
    public boolean supportsN() {
        return ieee80211n != null && ieee80211n;
    }
    
    public boolean supportsAC() {
        return ieee80211ac != null && ieee80211ac;
    }
    
    public boolean supportsAX() {
        return ieee80211ax != null && ieee80211ax;
    }
    
    public boolean isHidden() {
        return ignoreBroadcastSsid != null && ignoreBroadcastSsid;
    }
    
    public boolean supportsIeee8021x() {
        return ieee8021x != null && ieee8021x;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AccessPoint {\n");
        
        sb.append("  bssid='").append(bssid).append("',\n");
        sb.append("  ssid='").append(ssid).append("',\n");
        sb.append("  channel=").append(channel).append(",\n");
        sb.append("  hwMode='").append(hwMode).append("',\n");
        
        sb.append("  wpa=").append(wpa).append(",\n");
        sb.append("  wpaKeyMgmt='").append(wpaKeyMgmt).append("',\n");
        sb.append("  rsnPairwise='").append(rsnPairwise).append("',\n");
        sb.append("  wpaPairwise='").append(wpaPairwise).append("',\n");
        sb.append("  wpaGroupwise='").append(wpaGroupwise).append("',\n");
        sb.append("  rsnGroupwise='").append(rsnGroupwise).append("',\n");
        sb.append("  groupMgmtCipher='").append(groupMgmtCipher).append("',\n");
        sb.append("  ieee80211w=").append(ieee80211w).append(",\n");
        sb.append("  ieee8021x=").append(ieee8021x).append(",\n");
        
        sb.append("  ieee80211n=").append(ieee80211n).append(",\n");
        sb.append("  ieee80211ac=").append(ieee80211ac).append(",\n");
        sb.append("  ieee80211ax=").append(ieee80211ax).append(",\n");
        sb.append("  htCapab='").append(htCapab).append("',\n");
        sb.append("  vhtCapab='").append(vhtCapab).append("',\n");
        sb.append("  heCapab='").append(heCapab).append("',\n");
        sb.append("  vhtOperChwidth=").append(vhtOperChwidth).append(",\n");
        sb.append("  heOperChwidth=").append(heOperChwidth).append(",\n");
        sb.append("  vhtOperCentrFreqSeg0Idx=").append(vhtOperCentrFreqSeg0Idx).append(",\n");
        sb.append("  heBssColor=").append(heBssColor).append(",\n");
        sb.append("  heDefaultPeDuration=").append(heDefaultPeDuration).append(",\n");
        
        sb.append("  supportedRates='").append(supportedRates).append("',\n");
        sb.append("  basicRates='").append(basicRates).append("',\n");
        sb.append("  countryCode='").append(countryCode).append("',\n");
        sb.append("  ieee80211d=").append(ieee80211d).append(",\n");
        sb.append("  ieee80211h=").append(ieee80211h).append(",\n");
        sb.append("  wmmEnabled=").append(wmmEnabled).append(",\n");
        
        sb.append("  beaconInt=").append(beaconInt).append(",\n");
        sb.append("  dtimPeriod=").append(dtimPeriod).append(",\n");
        
        sb.append("  ignoreBroadcastSsid=").append(ignoreBroadcastSsid).append(",\n");
        sb.append("  wpsState=").append(wpsState).append(",\n");
        sb.append("  rrmNeighborReport=").append(rrmNeighborReport).append(",\n");
        sb.append("  rrmBeaconReport=").append(rrmBeaconReport).append(",\n");
        sb.append("  mobilityDomain='").append(mobilityDomain).append("',\n");
        sb.append("  vendorElements='").append(vendorElements).append("'\n");
        
        sb.append("}");
        return sb.toString();
    }
   
}