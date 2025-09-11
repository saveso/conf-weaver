package it.unical.thesis.utils;

import java.util.Arrays;
import java.util.Random;
import java.util.regex.Pattern;

public class MacAddressChanger {
	
    private static final Pattern MAC_PATTERN = Pattern.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");

	private MacAddressChanger()
	{
		
	}
    

    public static String randomizeDeviceIdentifier(String originalMac) {
        if (originalMac == null || !MAC_PATTERN.matcher(originalMac).matches()) {
            throw new IllegalArgumentException("Invalid MAC address format. Expected format like XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.");
        }

        String delimiter = originalMac.contains(":") ? ":" : "-";
        String[] parts = originalMac.split(delimiter);

        String ouiPart = parts[0] + delimiter + parts[1] + delimiter + parts[2];

        Random random = new Random();
        byte[] randomBytes = new byte[3];
        random.nextBytes(randomBytes);

        String randomPart = String.format("%02X%s%02X%s%02X",
                randomBytes[0], delimiter,
                randomBytes[1], delimiter,
                randomBytes[2]);

        return ouiPart + delimiter + randomPart;
    }


    public static String randomizeLastByte(String originalMac) {
        if (originalMac == null || !MAC_PATTERN.matcher(originalMac).matches()) {
            throw new IllegalArgumentException("Invalid MAC address format. Expected format like XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.");
        }

        String delimiter = originalMac.contains(":") ? ":" : "-";
        String[] parts = originalMac.split(delimiter);
        String[] firstFiveParts = Arrays.copyOfRange(parts, 0, 5);
        String prefix = String.join(delimiter, firstFiveParts);

        Random random = new Random();
        int lastOctet = random.nextInt(256); // Generates an int between 0 and 255.

        String randomLastPart = String.format("%02X", lastOctet);

        return prefix + delimiter + randomLastPart;
    }

}