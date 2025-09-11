package it.unical.thesis.parser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import it.unical.thesis.data.AccessPoint;

public class TsharkParser {
    
    public static AccessPoint parseFromTsharkOutput(List<String> lines) {
        if (lines == null || lines.isEmpty()) {
            return null;
        }
        
        Map<String, AccessPoint> apMap = new HashMap<>();
        
        for (String line : lines) {
            if (line == null || line.trim().isEmpty()) continue;
            
            AccessPoint ap = parseLine(line);
            if (ap != null && ap.getBssid() != null) {
                String bssid = ap.getBssid();
                
                if (apMap.containsKey(bssid)) {
                    mergeAccessPoints(apMap.get(bssid), ap);
                } else {
                    apMap.put(bssid, ap);
                }
            }
        }
        
        return apMap.values().stream()
                .filter(AccessPoint::isValid)
                .findFirst()
                .orElse(null);
    }
    
    private static AccessPoint parseLine(String line) {
        if (line == null || line.trim().isEmpty()) {
            return null;
        }
        
        String[] fields = line.split("\\|", -1);
        
        if (fields.length < 20) {
            return null;
        }
        
        AccessPoint ap = new AccessPoint();
        
        try {
            int idx = 0;
            
            String bssid = getFieldValue(fields, idx++);
            String ssidHex = getFieldValue(fields, idx++);
            String radioChannel = getFieldValue(fields, idx++);
            String dsChannel = getFieldValue(fields, idx++);
            
            if (bssid != null) ap.setBssid(bssid);
            if (ssidHex != null) {
                String ssid = hexToString(ssidHex);
                ap.setSsid(ssid);
            }
            
            Integer channel = parseInteger(dsChannel);
            if (channel == null) {
                channel = parseInteger(radioChannel);
            }
            ap.setChannel(channel);
            
            String freq = getFieldValue(fields, idx++);
            String is2ghz = getFieldValue(fields, idx++);
            String is5ghz = getFieldValue(fields, idx++);
            String isOfdm = getFieldValue(fields, idx++);
            
            ap.setHwMode(determineHwMode(freq, is2ghz, is5ghz, channel));
            
            String beacon = getFieldValue(fields, idx++);
            String dtimPeriod = getFieldValue(fields, idx++);
            
            if (beacon != null) ap.setBeaconInt(parseInteger(beacon));
            if (dtimPeriod != null) ap.setDtimPeriod(parseInteger(dtimPeriod));
            
            String privacy = getFieldValue(fields, idx++);
            String shortPreamble = getFieldValue(fields, idx++);
            String shortSlot = getFieldValue(fields, idx++);
            
            String htCap = getFieldValue(fields, idx++);
            String htLdpc = getFieldValue(fields, idx++);
            
            if (htCap != null && !htCap.isEmpty()) {
                ap.setIeee80211n(true);
                ap.setHtCapab(formatHtCapabilities(htCap, htLdpc));
            }
            
            String vhtCap = getFieldValue(fields, idx++);
            String vhtLdpc = getFieldValue(fields, idx++);
            String vhtChWidth = getFieldValue(fields, idx++);
            
            boolean hasVht = (vhtCap != null && !vhtCap.isEmpty()) || 
                           (vhtLdpc != null && !vhtLdpc.isEmpty()) ||
                           (vhtChWidth != null && !vhtChWidth.isEmpty());
                           
            if (hasVht) {
                ap.setIeee80211ac(true);
                if (vhtCap != null && !vhtCap.isEmpty()) {
                    ap.setVhtCapab(formatVhtCapabilities(vhtCap));
                }
                if (vhtChWidth != null) {
                    ap.setVhtOperChwidth(parseInteger(vhtChWidth));
                }
            }
            
            String supportedRates = getFieldValue(fields, idx++);
            String extendedRates = getFieldValue(fields, idx++);
            
            String formattedRates = formatSupportedRates(supportedRates, extendedRates);
            if (formattedRates != null) ap.setSupportedRates(formattedRates);
            
            String countryCode = getFieldValue(fields, idx++);
            String countryEnv = getFieldValue(fields, idx++);
            
            if (countryCode != null && !countryCode.isEmpty()) {
                ap.setCountryCode(countryCode);
                ap.setIeee80211d(true);
                ap.setIeee80211h(true);
            }
            
            String rsnVersion = getFieldValue(fields, idx++);
            String rsnAkms = getFieldValue(fields, idx++);
            String rsnGcs = getFieldValue(fields, idx++);
            String rsnPcs = getFieldValue(fields, idx++);
            String rsnGmcs = getFieldValue(fields, idx++);
            String rsnMfpc = getFieldValue(fields, idx++);
            String rsnMfpr = getFieldValue(fields, idx++);

            Integer wpaLevel = determineWpaLevel(privacy, rsnVersion);
            ap.setWpa(wpaLevel);

            if (rsnAkms != null && !rsnAkms.isEmpty()) {
                String keyMgmt = formatKeyManagement(rsnAkms);
                ap.setWpaKeyMgmt(keyMgmt);
                
                ap.setIeee8021x(keyMgmt != null && 
                                 (keyMgmt.contains("EAP") || 
                                		 keyMgmt.contains("eap")));
            }

            if (rsnPcs != null && !rsnPcs.isEmpty()) {
                String rsnCipher = mapPairwiseCipherType(rsnPcs);
                ap.setRsnPairwise(rsnCipher);
            }

            if (rsnGcs != null && !rsnGcs.isEmpty()) {
                String groupCipher = mapPairwiseCipherType(rsnGcs);
            }

            if (rsnGmcs != null && !rsnGmcs.isEmpty()) {
                String groupMgmtCipher = mapGroupMgmtCipherType(rsnGmcs);
                ap.setGroupMgmtCipher(groupMgmtCipher);
            }

            ap.setIeee80211w(determinePmfLevel(rsnMfpc, rsnMfpr));
                        
            String radioMeasurement = getFieldValue(fields, idx++);
            String rrmCap = getFieldValue(fields, idx++);
            String rrmB1 = getFieldValue(fields, idx++);
            
            if (parseBoolean(radioMeasurement) == Boolean.TRUE || 
                (rrmCap != null && !rrmCap.isEmpty())) {
                ap.setRrmNeighborReport(true);
                ap.setRrmBeaconReport(true);
            }
            
            String wpsVersion = getFieldValue(fields, idx++);
            String wpsConfig = getFieldValue(fields, idx++);
            String wpsDevice = getFieldValue(fields, idx++);
            String wpsMfg = getFieldValue(fields, idx++);
            String wpsModel = getFieldValue(fields, idx++);
            
            if (wpsVersion != null && !wpsVersion.isEmpty()) {
                Integer wpsState = parseWpsState(wpsVersion);
                if (wpsState != null) {
                    ap.setWpsState(wpsState);
                }
            }
            
            String extTagNumber = getFieldValue(fields, idx++);
            String heMacCaps = getFieldValue(fields, idx++);
            String hePhyCaps = getFieldValue(fields, idx++);
            String bssColor = getFieldValue(fields, idx++);
            String peDuration = getFieldValue(fields, idx++);
            
            boolean hasHe = "35".equals(extTagNumber) || "36".equals(extTagNumber) ||
                            (heMacCaps != null && !heMacCaps.isEmpty()) ||
                            (hePhyCaps != null && !hePhyCaps.isEmpty());
                            
            if (hasHe) {
                ap.setIeee80211ax(true);
                
                if (heMacCaps != null && hePhyCaps != null) {
                    String heCapab = formatHeCapabilities(heMacCaps, hePhyCaps);
                    ap.setHeCapab(heCapab);
                }
                
                 if (bssColor != null) {
                     ap.setHeBssColor(parseInteger(bssColor));
                 }
                 if (peDuration != null) {
                     ap.setHeDefaultPeDuration(parseInteger(peDuration));
                }
            }
            
            String extCap = getFieldValue(fields, idx++);
            
            String vendorOuiType = getFieldValue(fields, idx++);
            String vendorData = getFieldValue(fields, idx++);
            String oui = getFieldValue(fields, idx++);
            
            if (vendorData != null && !vendorData.isEmpty()) {
                String formattedVendor = formatVendorElements(vendorData);
                ap.setVendorElements(formattedVendor);
            }
            
            String tagLength = getFieldValue(fields, idx++);
            if ("0".equals(tagLength) && (ap.getSsid() == null || ap.getSsid().isEmpty())) {
                ap.setIgnoreBroadcastSsid(true);
            }
            
            String frameTime = getFieldValue(fields, idx++);
            String signalStrength = getFieldValue(fields, idx++);
            if (fields.length > idx) {
                String antenna = getFieldValue(fields, idx++);
            }
            
            extractBasicRates(ap);
            setConsistentDefaults(ap);
            
            return ap;
            
        } catch (Exception e) {
            System.err.println("Errore parsing riga: " + line.substring(0, Math.min(100, line.length())) + "...");
            e.printStackTrace();
            return null;
        }
    }
    
    private static String formatHeCapabilities(String heMacCaps, String hePhyCaps) {
        if (heMacCaps == null && hePhyCaps == null) return null;
        
        List<String> capList = new ArrayList<>();
        
        try {
            if (heMacCaps != null && !heMacCaps.isEmpty()) {
                parseHeMacCapabilities(heMacCaps, capList);
            }
            
            if (hePhyCaps != null && !hePhyCaps.isEmpty()) {
                parseHePhyCapabilities(hePhyCaps, capList);
            }
            
            return capList.isEmpty() ? null : "[" + String.join("][", capList) + "]";
            
        } catch (Exception e) {
            System.err.println("Errore parsing HE capabilities: " + e.getMessage());
            return null;
        }
    }
    
    private static void parseHeMacCapabilities(String heMacCaps, List<String> capList) {
        if (heMacCaps == null || heMacCaps.isEmpty()) return;
        
        try {
            long macCaps;
            if (heMacCaps.startsWith("0x") || heMacCaps.startsWith("0X")) {
                macCaps = Long.parseUnsignedLong(heMacCaps.substring(2), 16);
            } else {
                macCaps = Long.parseUnsignedLong(heMacCaps, 16);
            }
            
            if ((macCaps & 0x01L) != 0) capList.add("HE-HTC");
            if ((macCaps & 0x02L) != 0) capList.add("TWT-REQ");
            if ((macCaps & 0x04L) != 0) capList.add("TWT-RESP");
            if ((macCaps & 0x4000000L) != 0) capList.add("BSR");
            if ((macCaps & 0x200000L) != 0) capList.add("OM-CTRL");
            
            int ampduExp = (int)((macCaps >> 23) & 0x03);
            if (ampduExp > 0) {
                capList.add("MAX-A-MPDU-LEN-EXP" + (ampduExp + 3));
            }
            
        } catch (NumberFormatException e) {
            System.err.println("Errore parsing HE MAC caps: " + heMacCaps);
        }
    }
    
    private static void parseHePhyCapabilities(String hePhyCaps, List<String> capList) {
        if (hePhyCaps == null || hePhyCaps.isEmpty()) return;
        
        try {
            String[] hexBytes = hePhyCaps.replaceAll("[^0-9a-fA-F]", "").split("(?<=\\G..)");
            if (hexBytes.length == 0) return;
            
            if (hexBytes.length > 0) {
                int firstByte = Integer.parseInt(hexBytes[0], 16);
                
                if ((firstByte & 0x02) != 0) capList.add("HE40-2.4GHZ");
                if ((firstByte & 0x10) != 0) capList.add("HE-242RU-2.4GHZ");
            }
            
            if (hexBytes.length > 2) {
                int byte1 = Integer.parseInt(hexBytes[1], 16);
                int byte2 = Integer.parseInt(hexBytes[2], 16);
                int combined = (byte2 << 8) | byte1;
                
                if ((byte1 & 0x02) != 0) capList.add("HE-LDPC");
                if ((byte2 & 0x04) != 0) capList.add("TX-STBC-LE80");
                if ((byte2 & 0x08) != 0) capList.add("RX-STBC-LE80");
                if ((byte2 & 0x40) != 0) capList.add("UL-MU-MIMO");
                if ((byte2 & 0x80) != 0) capList.add("PARTIAL-BW-UL-MU-MIMO");
            }
            
            if (hexBytes.length > 4) {
                int byte3 = Integer.parseInt(hexBytes[3], 16);
                int byte4 = Integer.parseInt(hexBytes[4], 16);
                
                if ((byte3 & 0x80) != 0) capList.add("SU-BEAMFORMER");
                if ((byte4 & 0x01) != 0) capList.add("SU-BEAMFORMEE");
                if ((byte4 & 0x02) != 0) capList.add("MU-BEAMFORMER");
            }
            
        } catch (Exception e) {
            System.err.println("Errore parsing HE PHY caps: " + hePhyCaps + " - " + e.getMessage());
        }
    }
    
    private static void extractBasicRates(AccessPoint ap) {
        String supportedRatesStr = ap.getSupportedRates();
        if (supportedRatesStr == null || supportedRatesStr.isEmpty()) return;
        
        List<String> basicRatesList = new ArrayList<>();
        String[] rates = supportedRatesStr.split(" ");
        
        for (String rate : rates) {
            try {
                int rateValue = Integer.parseInt(rate);
                if (rateValue == 10 || rateValue == 20 || rateValue == 55 || rateValue == 110) {
                    basicRatesList.add(rate);
                }
            } catch (NumberFormatException e) {
            }
        }
        
        if (!basicRatesList.isEmpty()) {
            ap.setBasicRates(String.join(" ", basicRatesList));
        }
    }
    
    private static String formatHtCapabilities(String htCap, String htLdpc) {
        if (htCap == null || htCap.isEmpty()) return null;
        
        try {
            int capabilities;
            if (htCap.startsWith("0x") || htCap.startsWith("0X")) {
                capabilities = Integer.parseInt(htCap.substring(2), 16);
            } else {
                capabilities = Integer.parseInt(htCap);
            }
            
            List<String> capList = new ArrayList<>();
            
            if ((capabilities & 0x02) != 0) {
                capList.add("HT40+");
            } else {
                capList.add("HT40-");
            }
            
            if ((capabilities & 0x01) != 0 || parseBoolean(htLdpc) == Boolean.TRUE) {
                capList.add("LDPC");
            }
            
            if ((capabilities & 0x10) != 0) {
                capList.add("GF");
            }
            
            if ((capabilities & 0x20) != 0) {
                capList.add("SHORT-GI-20");
            }
            
            if ((capabilities & 0x40) != 0) {
                capList.add("SHORT-GI-40");
            }
            
            if ((capabilities & 0x80) != 0) {
                capList.add("TX-STBC");
            }
            
            int rxStbc = (capabilities >> 8) & 0x03;
            if (rxStbc > 0) {
                capList.add("RX-STBC" + rxStbc);
            }
            
            return capList.isEmpty() ? null : "[" + String.join("][", capList) + "]";
            
        } catch (NumberFormatException e) {
            return htCap;
        }
    }
    
    private static String formatVhtCapabilities(String vhtCap) {
        if (vhtCap == null || vhtCap.isEmpty()) return null;
        
        try {
            long capabilities;
            if (vhtCap.startsWith("0x") || vhtCap.startsWith("0X")) {
                capabilities = Long.parseLong(vhtCap.substring(2), 16);
            } else {
                capabilities = Long.parseLong(vhtCap);
            }
            
            List<String> capList = new ArrayList<>();
            
            int maxMpdu = (int)(capabilities & 0x03);
            if (maxMpdu == 1) capList.add("MAX-MPDU-7991");
            else if (maxMpdu == 2) capList.add("MAX-MPDU-11454");
            
            int chWidth = (int)((capabilities >> 2) & 0x03);
            if (chWidth >= 1) capList.add("VHT160");
            if (chWidth >= 2) capList.add("VHT160-80PLUS80");
            
            if ((capabilities & 0x10) != 0) {
                capList.add("RXLDPC");
            }
            
            if ((capabilities & 0x20) != 0) {
                capList.add("SHORT-GI-80");
            }
            
            if ((capabilities & 0x40) != 0) {
                capList.add("SHORT-GI-160");
            }
            
            if ((capabilities & 0x80) != 0) {
                capList.add("TX-STBC-2BY1");
            }
            
            return capList.isEmpty() ? null : "[" + String.join("][", capList) + "]";
            
        } catch (NumberFormatException e) {
            return vhtCap;
        }
    }
    
    private static List<String> parseRateString(String rateString) {
        List<String> rates = new ArrayList<>();
        
        if (rateString == null || rateString.isEmpty()) return rates;
        
        String[] rateArray = rateString.split(",");
        for (String rate : rateArray) {
            rate = rate.trim();
            if (rate.isEmpty()) continue;
            
            try {
                int rateValue;
                if (rate.startsWith("0x") || rate.startsWith("0X")) {
                    rateValue = Integer.parseInt(rate.substring(2), 16);
                } else {
                    rateValue = Integer.parseInt(rate);
                }
                
                int actualRate = rateValue & 0x7F;
                int rateInHundredsKbps = actualRate * 5;
                
                rates.add(String.valueOf(rateInHundredsKbps));
                
            } catch (NumberFormatException e) {
                rates.add(rate);
            }
        }
        
        return rates;
    }
    
    private static String getFieldValue(String[] fields, int index) {
        if (index >= fields.length) return null;
        String value = fields[index].trim();
        
        if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 1) {
            value = value.substring(1, value.length() - 1);
        }
        
        return value.isEmpty() ? null : value;
    }
    
    private static Integer parseInteger(String value) {
        if (value == null || value.isEmpty()) return null;
        try {
            if (value.startsWith("0x") || value.startsWith("0X")) {
                return Integer.parseInt(value.substring(2), 16);
            }
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    private static Boolean parseBoolean(String value) {
        if (value == null || value.isEmpty()) return null;
        if ("True".equalsIgnoreCase(value) || "1".equals(value)) return true;
        if ("False".equalsIgnoreCase(value) || "0".equals(value)) return false;
        return null;
    }
    
    private static String hexToString(String hex) {
        if (hex == null || hex.isEmpty()) return null;
        
        try {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i + 1 >= hex.length()) break;
                String hexPair = hex.substring(i, i + 2);
                int value = Integer.parseInt(hexPair, 16);
                if (value >= 32 && value <= 126) {
                    result.append((char) value);
                } else if (value == 0) {
                    break;
                }
            }
            return result.length() > 0 ? result.toString() : null;
        } catch (Exception e) {
            return hex;
        }
    }
    
    private static String determineHwMode(String freq, String is2ghz, String is5ghz, Integer channel) {
        if (freq != null && !freq.isEmpty()) {
            try {
                int frequency = Integer.parseInt(freq);
                if (frequency >= 2412 && frequency <= 2484) {
                    return "g";
                } else if (frequency >= 5000 && frequency <= 6000) {
                    return "a";
                }
            } catch (NumberFormatException e) {
            }
        }
        
        if (parseBoolean(is5ghz) == Boolean.TRUE) return "a";
        if (parseBoolean(is2ghz) == Boolean.TRUE) return "g";
        
        if (channel != null) {
            if (channel >= 1 && channel <= 14) {
                return "g";
            } else if (channel >= 36) {
                return "a";
            }
        }
        
        return "g";
    }
    
    private static Integer determineWpaLevel(String privacy, String rsnVersion) {
        if (rsnVersion != null && !rsnVersion.isEmpty()) {
            return 2;
        } else if (parseBoolean(privacy) == Boolean.TRUE) {
            return 1;
        }
        return 0;
    }
    
    private static Integer determinePmfLevel(String mfpc, String mfpr) {
        Boolean mfpcBool = parseBoolean(mfpc);
        Boolean mfprBool = parseBoolean(mfpr);
        
        if (mfprBool == Boolean.TRUE) {
            return 2;
        } else if (mfpcBool == Boolean.TRUE) {
            return 1;
        }
        return 0;
    }
    
    private static Integer parseWpsState(String wpsValue) {
        if (wpsValue == null || wpsValue.isEmpty()) return null;
        
        try {
            Integer wps;
            
            if (wpsValue.startsWith("0x") || wpsValue.startsWith("0X")) {
                wps = Integer.parseInt(wpsValue.substring(2), 16);
            } else {
                wps = Integer.parseInt(wpsValue);
            }
            
            if (wps == 0x10 || wps == 16) return 2;
            if (wps == 0x01 || wps == 1) return 1;
            if (wps == 0x02 || wps == 2) return 2;
            
            return wps > 0 ? 2 : 0;
            
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    private static void setConsistentDefaults(AccessPoint ap) {
        if (ap.getWmmEnabled() == null) {
            boolean shouldEnableWmm = false;
            
            if (ap.getIeee80211n() != null && ap.getIeee80211n()) {
                shouldEnableWmm = true;
            }
            
            if (ap.getWpa() != null && ap.getWpa() >= 2) {
                shouldEnableWmm = true;
            }
            
            if (ap.getHtCapab() != null && !ap.getHtCapab().isEmpty()) {
                shouldEnableWmm = true;
            }
            
            if (shouldEnableWmm) {
                ap.setWmmEnabled(true);
            }
        }
        
        if (ap.getBeaconInt() == null) {
            ap.setBeaconInt(100);
        }
        
        if (ap.getDtimPeriod() == null) {
            ap.setDtimPeriod(1);
        }
    }
    
    private static void mergeAccessPoints(AccessPoint existing, AccessPoint newAp) {
        if (existing.getSsid() == null && newAp.getSsid() != null) {
            existing.setSsid(newAp.getSsid());
        }
        if (existing.getChannel() == null && newAp.getChannel() != null) {
            existing.setChannel(newAp.getChannel());
        }
        if (existing.getCountryCode() == null && newAp.getCountryCode() != null) {
            existing.setCountryCode(newAp.getCountryCode());
            existing.setIeee80211d(newAp.getIeee80211d());
            existing.setIeee80211h(newAp.getIeee80211h());
        }
        if (existing.getWpsState() == null && newAp.getWpsState() != null) {
            existing.setWpsState(newAp.getWpsState());
        }
        if (existing.getWmmEnabled() == null && newAp.getWmmEnabled() != null) {
            existing.setWmmEnabled(newAp.getWmmEnabled());
        }
        if (existing.getHtCapab() == null && newAp.getHtCapab() != null) {
            existing.setHtCapab(newAp.getHtCapab());
            existing.setIeee80211n(newAp.getIeee80211n());
        }
        if (existing.getVhtCapab() == null && newAp.getVhtCapab() != null) {
            existing.setVhtCapab(newAp.getVhtCapab());
            existing.setIeee80211ac(newAp.getIeee80211ac());
        }
        if (existing.getHeCapab() == null && newAp.getHeCapab() != null) {
            existing.setHeCapab(newAp.getHeCapab());
            existing.setIeee80211ax(newAp.getIeee80211ax());
        }
        if (existing.getWpaKeyMgmt() == null && newAp.getWpaKeyMgmt() != null) {
            existing.setWpaKeyMgmt(newAp.getWpaKeyMgmt());
        }
        if (existing.getSupportedRates() == null && newAp.getSupportedRates() != null) {
            existing.setSupportedRates(newAp.getSupportedRates());
        }
    }
    
    private static String formatSupportedRates(String supportedRates, String extendedRates) {
        List<String> allRates = new ArrayList<>();
        
        if (supportedRates != null && !supportedRates.isEmpty()) {
            allRates.addAll(parseRateString(supportedRates));
        }
        
        if (extendedRates != null && !extendedRates.isEmpty()) {
            allRates.addAll(parseRateString(extendedRates));
        }
        
        if (allRates.isEmpty()) return null;
        
        allRates = allRates.stream()
                .filter(rate -> {
                    try {
                        int rateVal = Integer.parseInt(rate);
                        return rateVal >= 10 && rateVal <= 5400;
                    } catch (NumberFormatException e) {
                        return false;
                    }
                })
                .distinct()
                .sorted((a, b) -> {
                    try {
                        return Integer.compare(Integer.parseInt(a), Integer.parseInt(b));
                    } catch (NumberFormatException e) {
                        return a.compareTo(b);
                    }
                })
                .collect(Collectors.toList());
        
        return allRates.isEmpty() ? null : String.join(" ", allRates);
    }
    
    private static String mapGroupMgmtCipherType(String cipherType) {
        if (cipherType == null) return null;
        
        try {
            int cipher = Integer.parseInt(cipherType);
            switch (cipher) {
                case 1: return "AES-128-CMAC";
                case 2: return "BIP-GMAC-128";
                case 3: return "BIP-GMAC-256";
                case 4: return "BIP-CMAC-256";
                case 11: return "AES-128-CMAC";
                case 12: return "BIP-GMAC-128";
                case 13: return "BIP-GMAC-256";
                default: return "AES-128-CMAC";
            }
        } catch (NumberFormatException e) {
            return cipherType;
        }
    }

    private static String formatKeyManagement(String akmsType) {
        if (akmsType == null || akmsType.isEmpty()) return null;
        
        List<String> keyMgmtList = new ArrayList<>();
        
        String[] akmsList = akmsType.split(",");
        
        for (String akms : akmsList) {
            akms = akms.trim();
            if (akms.isEmpty()) continue;
            
            try {
                int akmsInt = Integer.parseInt(akms);
                String keyMgmt = mapSingleAkmsType(akmsInt);
                if (keyMgmt != null && !keyMgmtList.contains(keyMgmt)) {
                    keyMgmtList.add(keyMgmt);
                }
            } catch (NumberFormatException e) {
                if (!keyMgmtList.contains(akms)) {
                    keyMgmtList.add(akms);
                }
            }
        }
        
        return keyMgmtList.isEmpty() ? null : String.join(" ", keyMgmtList);
    }

    private static String mapSingleAkmsType(int akms) {
        switch (akms) {
            case 1: return "WPA-EAP";
            case 2: return "WPA-PSK";
            case 3: return "FT-EAP";
            case 4: return "FT-PSK";
            case 5: return "WPA-EAP-SHA256";
            case 6: return "WPA-PSK-SHA256";
            case 7: return "TDLS";
            case 8: return "SAE";
            case 9: return "FT-SAE";
            case 10: return "AP-PEER-KEY";
            case 11: return "WPA-EAP";
            case 12: return "WPA-EAP";
            case 13: return "FT-EAP-SHA384";
            case 14: return "FILS-SHA256";
            case 15: return "FILS-SHA384";
            case 16: return "FT-FILS-SHA256";
            case 17: return "FT-FILS-SHA384";
            case 18: return "OWE";
            default: 
                System.err.println("WARNING: Unknown AKMS type: " + akms + ", using WPA-PSK as fallback");
                return "WPA-PSK";
        }
    }

    private static String formatVendorElements(String vendorData) {
        if (vendorData == null || vendorData.isEmpty()) return null;
        
        String cleaned = vendorData.replaceAll("[\\s,:]", "");
        
        if (!cleaned.matches("[0-9a-fA-F]*")) {
            return null;
        }
        
        if (!cleaned.toLowerCase().startsWith("dd")) {
            int payloadLength = cleaned.length() / 2;
            int totalLength = payloadLength + 4;
            
            if (totalLength > 255) {
                payloadLength = 251;
                totalLength = 255;
                cleaned = cleaned.substring(0, payloadLength * 2);
            }
            
            String lengthHex = String.format("%02x", totalLength);
            return "dd" + lengthHex + "000000" + "00" + cleaned;
        }
        
        return cleaned.toLowerCase();
    }
   
    private static String mapPairwiseCipherType(String cipherTypes) {
        if (cipherTypes == null || cipherTypes.isEmpty()) return null;

        List<String> mappedCiphers = new ArrayList<>();
        String[] cipherList = cipherTypes.split(",");

        for (String cipherStr : cipherList) {
            cipherStr = cipherStr.trim();
            if (cipherStr.isEmpty()) continue;

            try {
                int cipher = Integer.parseInt(cipherStr);
                switch (cipher) {
                    case 1:
                        if (!mappedCiphers.contains("WEP40")) mappedCiphers.add("WEP40");
                        break;
                    case 2:
                        if (!mappedCiphers.contains("TKIP")) mappedCiphers.add("TKIP");
                        break;
                    case 4:
                        if (!mappedCiphers.contains("CCMP")) mappedCiphers.add("CCMP");
                        break;
                    case 5:
                        if (!mappedCiphers.contains("WEP104")) mappedCiphers.add("WEP104");
                        break;
                    case 8:
                        if (!mappedCiphers.contains("GCMP")) mappedCiphers.add("GCMP");
                        break;
                    case 9:
                        if (!mappedCiphers.contains("GCMP-256")) mappedCiphers.add("GCMP-256");
                        break;
                    case 10:
                        if (!mappedCiphers.contains("CCMP-256")) mappedCiphers.add("CCMP-256");
                        break;
                    default:
                        if (!mappedCiphers.contains("CCMP")) mappedCiphers.add("CCMP");
                        break;
                }
            } catch (NumberFormatException e) {
                if (!mappedCiphers.contains(cipherStr)) {
                    mappedCiphers.add(cipherStr);
                }
            }
        }
        
        return String.join(" ", mappedCiphers);
    }
}