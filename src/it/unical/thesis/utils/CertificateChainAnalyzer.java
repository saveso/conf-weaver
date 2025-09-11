package it.unical.thesis.utils;

import java.util.*;
import java.util.stream.Collectors;

import it.unical.thesis.data.CertificateInfo;

public class CertificateChainAnalyzer {
    
    public static CertificateInfo getServerCertificate(List<CertificateInfo> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return null;
        }
        
        List<CertificateInfo> unique = removeDuplicates(certificates);
        
        List<CertificateInfo> endEntities = unique.stream()
            .filter(cert -> !cert.isCA())
            .collect(Collectors.toList());
        
        if (endEntities.isEmpty()) {
            return null;
        }
        
        if (endEntities.size() == 1) {
            return endEntities.get(0);
        }
        
        return endEntities.stream()
            .max(Comparator.comparing((CertificateInfo cert) -> cert.getDepth())
                 .thenComparing(cert -> cert.hasServerAuth() ? 1 : 0))
            .orElse(endEntities.get(0));
    }
    
    public static CertificateInfo getRootCACertificate(List<CertificateInfo> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return null;
        }
        
        List<CertificateInfo> unique = removeDuplicates(certificates);
        
        List<CertificateInfo> rootCAs = unique.stream()
            .filter(cert -> cert.isCA() && cert.isSelfSigned())
            .collect(Collectors.toList());
        
        if (rootCAs.isEmpty()) {
            return null;
        }
        
        return rootCAs.stream()
            .min(Comparator.comparing(CertificateInfo::getDepth))
            .orElse(rootCAs.get(0));
    }
    
    public static List<CertificateInfo> removeDuplicates(List<CertificateInfo> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return new ArrayList<>();
        }
        
        Map<String, CertificateInfo> uniqueCerts = new LinkedHashMap<>();
        
        for (CertificateInfo cert : certificates) {
            String key = generateUniqueKey(cert);
            
            if (!uniqueCerts.containsKey(key)) {
                uniqueCerts.put(key, cert);
            } else {
                CertificateInfo existing = uniqueCerts.get(key);
                if (isMoreComplete(cert, existing)) {
                    uniqueCerts.put(key, cert);
                }
            }
        }
        
        return new ArrayList<>(uniqueCerts.values());
    }
    
    private static String generateUniqueKey(CertificateInfo cert) {
        StringBuilder key = new StringBuilder();
        
        if (cert.getSerialNumber() != null && !cert.getSerialNumber().trim().isEmpty()) {
            key.append("SN:").append(cert.getSerialNumber().trim());
        }
        
        if (cert.getSubjectKeyIdentifier() != null && !cert.getSubjectKeyIdentifier().trim().isEmpty()) {
            if (key.length() > 0) key.append("|");
            key.append("SKI:").append(cert.getSubjectKeyIdentifier().trim());
        }
        
        if (key.length() == 0 && cert.getSubject() != null) {
            key.append("SUBJ:").append(cert.getSubject().toDNString());
        }
        
        if (key.length() == 0) {
            key.append("HASH:").append(cert.hashCode());
        }
        
        return key.toString();
    }
    
    private static boolean isMoreComplete(CertificateInfo cert1, CertificateInfo cert2) {
        int score1 = getCompletenessScore(cert1);
        int score2 = getCompletenessScore(cert2);
        return score1 > score2;
    }
    
    private static int getCompletenessScore(CertificateInfo cert) {
        int score = 0;
        
        if (cert.getDepth() >= 0) score += 10;
        
        if (cert.getSerialNumber() != null && !cert.getSerialNumber().trim().isEmpty()) score += 5;
        if (cert.getSignatureAlgorithm() != null && !cert.getSignatureAlgorithm().trim().isEmpty()) score += 3;
        if (cert.getNotBefore() != null && !cert.getNotBefore().trim().isEmpty()) score += 3;
        if (cert.getNotAfter() != null && !cert.getNotAfter().trim().isEmpty()) score += 3;
        
        if (cert.getSubject() != null && !cert.getSubject().isEmpty()) score += 5;
        if (cert.getIssuer() != null && !cert.getIssuer().isEmpty()) score += 5;
        
        if (cert.getKeyAlgorithm() != null && !cert.getKeyAlgorithm().trim().isEmpty()) score += 2;
        if (cert.getKeySize() > 0) score += 2;
        
        if (cert.getSubjectKeyIdentifier() != null && !cert.getSubjectKeyIdentifier().trim().isEmpty()) score += 3;
        if (cert.getAuthorityKeyIdentifier() != null && !cert.getAuthorityKeyIdentifier().trim().isEmpty()) score += 3;
        if (cert.getKeyUsage() != null && !cert.getKeyUsage().trim().isEmpty()) score += 2;
        if (cert.getExtendedKeyUsage() != null && !cert.getExtendedKeyUsage().trim().isEmpty()) score += 2;
        
        return score;
    }
}