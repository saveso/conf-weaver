package it.unical.thesis.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;

public class DateConverter {
    

    public static String convertToOpenSSLFormat(String dateString) {
        if (dateString == null || dateString.trim().isEmpty()) {
            throw new IllegalArgumentException("Date string cannot be null or empty");
        }
        
        try {
            String cleanDate = dateString.replace(" GMT", "").trim();
            
            DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy", Locale.ENGLISH);
            LocalDateTime dateTime = LocalDateTime.parse(cleanDate, inputFormatter);
            
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmss");
            String formatted = dateTime.format(outputFormatter) + "Z";
            
            return formatted;
            
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid date format: " + dateString + 
                ". Expected format: 'MMM dd HH:mm:ss yyyy GMT' (e.g. 'Aug 27 16:52:32 2025 GMT')", e);
        }
    }
    

    public static String convertFromOpenSSLFormat(String opensslDate) {
        if (opensslDate == null || opensslDate.trim().isEmpty()) {
            throw new IllegalArgumentException("OpenSSL date string cannot be null or empty");
        }
        
        try {
            String cleanDate = opensslDate.replace("Z", "").trim();
            
            if (cleanDate.length() != 12) {
                throw new IllegalArgumentException("Invalid length. Expected 12 characters + Z");
            }
            
            DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmss");
            LocalDateTime dateTime = LocalDateTime.parse(cleanDate, inputFormatter);
            
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy", Locale.ENGLISH);
            String formatted = dateTime.format(outputFormatter) + " GMT";
            
            return formatted;
            
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid OpenSSL format: " + opensslDate + 
                ". Expected format: 'YYMMDDHHMMSSZ' (e.g. '250827165232Z')", e);
        }
    }
  
}