package it.unical.thesis.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;

public class DateConverter {
    

    public static String convertToOpenSSLFormat(String dateString) {
        if (dateString == null || dateString.trim().isEmpty()) {
            throw new IllegalArgumentException("Data string non può essere null o vuota");
        }
        
        try {
            String cleanDate = dateString.replace(" GMT", "").trim();
            
            DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy", Locale.ENGLISH);
            LocalDateTime dateTime = LocalDateTime.parse(cleanDate, inputFormatter);
            
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmss");
            String formatted = dateTime.format(outputFormatter) + "Z";
            
            return formatted;
            
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Formato data non valido: " + dateString + 
                ". Formato atteso: 'MMM dd HH:mm:ss yyyy GMT' (es. 'Aug 27 16:52:32 2025 GMT')", e);
        }
    }
    

    public static String convertFromOpenSSLFormat(String opensslDate) {
        if (opensslDate == null || opensslDate.trim().isEmpty()) {
            throw new IllegalArgumentException("OpenSSL date string non può essere null o vuota");
        }
        
        try {
            String cleanDate = opensslDate.replace("Z", "").trim();
            
            if (cleanDate.length() != 12) {
                throw new IllegalArgumentException("Lunghezza non valida. Attesi 12 caratteri + Z");
            }
            
            DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmss");
            LocalDateTime dateTime = LocalDateTime.parse(cleanDate, inputFormatter);
            
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy", Locale.ENGLISH);
            String formatted = dateTime.format(outputFormatter) + " GMT";
            
            return formatted;
            
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Formato OpenSSL non valido: " + opensslDate + 
                ". Formato atteso: 'YYMMDDHHMMSSZ' (es. '250827165232Z')", e);
        }
    }
  
}
