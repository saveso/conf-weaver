package it.unical.thesis.parser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.unical.thesis.data.AccessPoint;

public class IwParser {
	
	private IwParser()
	{
		
	}

	public static HashMap<String, AccessPoint> parseIwScanOutput(List<String> scanLines) {
        HashMap<String, AccessPoint> accessPoints = new HashMap<>();
        
        List<List<String>> bssEntries = splitIntoBSSEntries(scanLines);
        
        for (List<String> entry : bssEntries) {
            AccessPoint ap = parseBSSEntry(entry);
            if (ap != null && ap.getBssid() != null) {
                accessPoints.put(ap.getBssid(), ap);
            }
        }
        
        return accessPoints;
    }
    
    public static HashMap<String, AccessPoint> parseIwScanOutput(String scanOutput) {
        List<String> lines = Arrays.asList(scanOutput.split("\n"));
        return parseIwScanOutput(lines);
    }
    
    private static List<List<String>> splitIntoBSSEntries(List<String> lines) {
        List<List<String>> bssEntries = new ArrayList<>();
        List<String> currentEntry = new ArrayList<>();
        
        for (String line : lines) {
            if (line.trim().startsWith("BSS ")) {
                if (!currentEntry.isEmpty()) {
                    bssEntries.add(new ArrayList<>(currentEntry));
                    currentEntry.clear();
                }
                currentEntry.add(line.trim());
            } else if (!currentEntry.isEmpty()) {
                currentEntry.add(line);
            }
        }
        
        if (!currentEntry.isEmpty()) {
            bssEntries.add(currentEntry);
        }
        
        return bssEntries;
    }
    
    private static AccessPoint parseBSSEntry(List<String> lines) {
        AccessPoint ap = new AccessPoint();
        
        if (lines.isEmpty()) return null;
        
        String firstLine = lines.get(0);
        String bssid = extractBSSID(firstLine);
        if (bssid == null) return null;
        
        ap.setBssid(bssid);
        
        for (String line : lines) {
            line = line.trim();
            
            if (line.startsWith("freq:")) {
                Integer channel = extractChannelFromFreq(line);
                if (channel != null) {
                    ap.setChannel(channel);
                    ap.setHwMode(getHwModeFromFreq(extractFreq(line)));
                }
            }
            else if (line.startsWith("SSID:")) {
                String ssid = line.substring(5).trim();
                if (!ssid.isEmpty()) {
                    ap.setSsid(ssid);
                }
            }
            else if (line.startsWith("DS Parameter set: channel")) {
                Integer channel = extractNumber(line, "channel (\\d+)");
                if (channel != null) ap.setChannel(channel);
            }
            else if (line.startsWith("Country:")) {
                String country = extractCountryCode(line);
                if (country != null) {
                    ap.setCountryCode(country);
                    ap.setIeee80211d(true);
                }
            }
            else if (line.startsWith("beacon interval:")) {
                Integer beaconInt = extractNumber(line, "(\\d+) TUs");
                if (beaconInt != null) ap.setBeaconInt(beaconInt);
            }
            else if (line.contains("DTIM Period")) {
                Integer dtimPeriod = extractNumber(line, "DTIM Period (\\d+)");
                if (dtimPeriod != null) ap.setDtimPeriod(dtimPeriod);
            }
            
            else if (line.startsWith("RSN:")) {
                parseRSNInfo(lines, ap);
            }
            else if (line.startsWith("WPA:")) {
                parseWPAInfo(lines, ap);
            }
            
            else if (line.startsWith("HT capabilities:")) {
                ap.setIeee80211n(true);
                parseHTCapabilities(lines, ap);
            }
            else if (line.startsWith("VHT capabilities:")) {
                ap.setIeee80211ac(true);
                parseVHTCapabilities(lines, ap);
            }
            else if (line.startsWith("HE capabilities:")) {
                ap.setIeee80211ax(true);
            }
            
            else if (line.startsWith("WMM:")) {
                ap.setWmmEnabled(true);
            }
            
            else if (line.contains("Wi-Fi Protected Setup State:")) {
                Integer wpsState = extractNumber(line, "State: (\\d+)");
                if (wpsState != null) ap.setWpsState(wpsState);
            }
            
            else if (line.startsWith("RM enabled capabilities:")) {
                parseRRMCapabilities(lines, ap);
            }
            
            else if (line.startsWith("Supported rates:")) {
                String rates = extractSupportedRates(line);
                if (rates != null) {
                    ap.setSupportedRates(rates);
                    ap.setBasicRates(extractBasicRates(line));
                }
            }
        }
        
        if (ap.getHwMode() == null && ap.getChannel() != null) {
            ap.setHwMode(ap.getChannel() <= 14 ? "g" : "a");
        }
        
        return ap;
    }
    
    private static String extractBSSID(String line) {
        Pattern pattern = Pattern.compile("([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})");
        Matcher matcher = pattern.matcher(line);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static Integer extractChannelFromFreq(String line) {
        Double freq = extractFreq(line);
        if (freq == null) return null;
        
        if (freq >= 2412 && freq <= 2484) {
            if (freq == 2484) return 14;
            return (int)((freq - 2412) / 5) + 1;
        } else if (freq >= 5000 && freq <= 6000) {
            return (int)((freq - 5000) / 5);
        }
        return null;
    }
    
    private static Double extractFreq(String line) {
        Pattern pattern = Pattern.compile("freq: ([0-9.]+)");
        Matcher matcher = pattern.matcher(line);
        return matcher.find() ? Double.parseDouble(matcher.group(1)) : null;
    }
    
    private static String getHwModeFromFreq(Double freq) {
        if (freq == null) return null;
        if (freq >= 2400 && freq <= 2500) return "g";
        if (freq >= 5000 && freq <= 6000) return "a";
        return "g"; // default
    }
    
    private static Integer extractNumber(String text, String pattern) {
        Pattern p = Pattern.compile(pattern);
        Matcher matcher = p.matcher(text);
        return matcher.find() ? Integer.parseInt(matcher.group(1)) : null;
    }
    
    private static String extractCountryCode(String line) {
        Pattern pattern = Pattern.compile("Country: ([A-Z]{2})");
        Matcher matcher = pattern.matcher(line);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static void parseRSNInfo(List<String> lines, AccessPoint ap) {
        ap.setWpa(2);
        
        for (String line : lines) {
            line = line.trim();
            if (line.contains("Authentication suites:")) {
                if (line.contains("PSK")) {
                    ap.setWpaKeyMgmt("WPA-PSK");
                }
                if (line.contains("SAE")) {
                    if (ap.getWpaKeyMgmt() != null) {
                        ap.setWpaKeyMgmt(ap.getWpaKeyMgmt() + " SAE");
                    } else {
                        ap.setWpaKeyMgmt("SAE");
                    }
                }
            }
            else if (line.contains("Pairwise ciphers:")) {
                if (line.contains("CCMP")) {
                    ap.setRsnPairwise("CCMP");
                }
            }
            else if (line.contains("MFP-capable") || line.contains("MFP-required")) {
                ap.setIeee80211w(1);
                if (line.contains("MFP-required")) {
                    ap.setIeee80211w(2);
                }
            }
        }
    }
    
    private static void parseWPAInfo(List<String> lines, AccessPoint ap) {
        if (ap.getWpa() == null) ap.setWpa(1); // WPA1
        
        for (String line : lines) {
            line = line.trim();
            if (line.contains("Pairwise ciphers:") && line.contains("TKIP")) {
                ap.setWpaPairwise("TKIP");
            }
        }
    }
    
    private static void parseHTCapabilities(List<String> lines, AccessPoint ap) {
        StringBuilder htCapab = new StringBuilder();
        
        for (String line : lines) {
            line = line.trim();
            if (line.contains("HT20/HT40")) htCapab.append("[HT40+][HT40-]");
            else if (line.contains("HT20")) htCapab.append("[HT20]");
            
            if (line.contains("RX HT20 SGI")) htCapab.append("[SHORT-GI-20]");
            if (line.contains("RX HT40 SGI")) htCapab.append("[SHORT-GI-40]");
            if (line.contains("TX STBC")) htCapab.append("[TX-STBC]");
            if (line.contains("RX STBC")) htCapab.append("[RX-STBC]");
            if (line.contains("RX LDPC")) htCapab.append("[LDPC]");
            if (line.contains("DSSS/CCK HT40")) htCapab.append("[DSSS_CCK-40]");
        }
        
        if (htCapab.length() > 0) {
            ap.setHtCapab(htCapab.toString());
        }
    }
    
    private static void parseVHTCapabilities(List<String> lines, AccessPoint ap) {
        StringBuilder vhtCapab = new StringBuilder();
        
        for (String line : lines) {
            line = line.trim();
            if (line.contains("short GI (80 MHz)")) vhtCapab.append("[SHORT-GI-80]");
            if (line.contains("TX STBC")) vhtCapab.append("[TX-STBC-2BY1]");
            if (line.contains("RX LDPC")) vhtCapab.append("[RXLDPC]");
            if (line.contains("SU Beamformer")) vhtCapab.append("[SU-BEAMFORMER]");
            if (line.contains("SU Beamformee")) vhtCapab.append("[SU-BEAMFORMEE]");
            if (line.contains("MU Beamformer")) vhtCapab.append("[MU-BEAMFORMER]");
            
            if (line.contains("channel width: 0")) {
                ap.setVhtOperChwidth(0); // 20/40 MHz
            } else if (line.contains("channel width: 1")) {
                ap.setVhtOperChwidth(1); // 80 MHz
            }
            
            if (line.contains("center freq segment 1:")) {
                Integer centerFreq = extractNumber(line, "center freq segment 1: (\\d+)");
                if (centerFreq != null) ap.setVhtOperCentrFreqSeg0Idx(centerFreq);
            }
        }
        
        if (vhtCapab.length() > 0) {
            ap.setVhtCapab(vhtCapab.toString());
        }
    }
    
    private static void parseRRMCapabilities(List<String> lines, AccessPoint ap) {
        for (String line : lines) {
            line = line.trim();
            if (line.contains("Neighbor Report")) {
                ap.setRrmNeighborReport(true);
            }
            if (line.contains("Beacon") && (line.contains("Passive") || line.contains("Active"))) {
                ap.setRrmBeaconReport(true);
            }
        }
    }
    
    private static String extractSupportedRates(String line) {
        String ratesStr = line.substring(line.indexOf(":") + 1).trim();
        return ratesStr.replaceAll("\\*", "").replaceAll(" +", " ");
    }
    
    private static String extractBasicRates(String line) {
        StringBuilder basicRates = new StringBuilder();
        String[] parts = line.substring(line.indexOf(":") + 1).trim().split(" ");
        
        for (String part : parts) {
            if (part.contains("*")) {
                if (basicRates.length() > 0) basicRates.append(" ");
                basicRates.append(part.replace("*", ""));
            }
        }
        
        return basicRates.length() > 0 ? basicRates.toString() : null;
    }

    
    public static List<String> parseInterfaceNames(List<String> lines) {
        List<String> interfaces = new ArrayList<>();
        
        Pattern interfacePattern = Pattern.compile("^\\s+Interface\\s+(\\w+)\\s*$");
        
        for (String line : lines) {
            Matcher matcher = interfacePattern.matcher(line);
            if (matcher.find()) {
                String interfaceName = matcher.group(1);
                interfaces.add(interfaceName);
            }
        }
        
        return interfaces;
    }

}
