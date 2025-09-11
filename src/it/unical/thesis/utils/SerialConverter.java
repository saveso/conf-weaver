package it.unical.thesis.utils;

import java.math.BigInteger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class SerialConverter {
    
    private static final Pattern COLON_SEPARATED_HEX = Pattern.compile("^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$");
    private static final Pattern DECIMAL_WITH_HEX = Pattern.compile("^(\\d+)\\s*\\(0x([0-9a-fA-F]+)\\)$");
    private static final Pattern PURE_HEX = Pattern.compile("^(0x)?[0-9a-fA-F]+$");
    private static final Pattern PURE_DECIMAL = Pattern.compile("^\\d+$");
    

    public static String convertSerialToOpenSSLFormat(String serialNumber) {
        if (serialNumber == null || serialNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Serial number non può essere null o vuoto");
        }
        
        String trimmed = serialNumber.trim();
        String result;
        
        if (COLON_SEPARATED_HEX.matcher(trimmed).matches()) {
            result = trimmed.replace(":", "").toUpperCase();
        }

        else if (DECIMAL_WITH_HEX.matcher(trimmed).matches()) {
            Matcher decimalHexMatcher = DECIMAL_WITH_HEX.matcher(trimmed);
            decimalHexMatcher.matches();
            String hexPart = decimalHexMatcher.group(2);
            result = hexPart.toUpperCase();
        }

        else if (PURE_HEX.matcher(trimmed).matches()) {
            String hex = trimmed.startsWith("0x") ? trimmed.substring(2) : trimmed;
            result = hex.toUpperCase();
        }

        else if (PURE_DECIMAL.matcher(trimmed).matches()) {
            BigInteger decimal = new BigInteger(trimmed);
            result = decimal.toString(16).toUpperCase();
        }
        else {
            throw new IllegalArgumentException("Formato serial number non riconosciuto: " + serialNumber);
        }
        
        return padSerial(result);
    }
    

    private static String padSerial(String serial) {
        if (serial.length() == 1) {
            return "0" + serial;
        }
        return serial;
    }
    

    public static String convertFromOpenSSLFormat(String opensslSerial) {
        if (opensslSerial == null || opensslSerial.trim().isEmpty()) {
            throw new IllegalArgumentException("OpenSSL serial non può essere null o vuoto");
        }
        
        String hex = opensslSerial.trim().toUpperCase();
        
        if (!hex.matches("^[0-9A-F]+$")) {
            throw new IllegalArgumentException("Serial OpenSSL deve contenere solo caratteri esadecimali: " + opensslSerial);
        }
        
        BigInteger decimal = new BigInteger(hex, 16);
        return decimal.toString() + " (0x" + hex + ")";
    }
    

    public static boolean isValidOpenSSLFormat(String serialNumber) {
        if (serialNumber == null || serialNumber.trim().isEmpty()) {
            return false;
        }
        return serialNumber.trim().matches("^[0-9A-Fa-f]+$");
    }
    

    public static String formatWithColons(String hexSerial) {
        if (hexSerial == null || hexSerial.trim().isEmpty()) {
            throw new IllegalArgumentException("Hex serial non può essere null o vuoto");
        }
        
        String hex = hexSerial.trim().toUpperCase();
        
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) {
                formatted.append(":");
            }
            formatted.append(hex, i, Math.min(i + 2, hex.length()));
        }
        
        return formatted.toString();
    }
    
}