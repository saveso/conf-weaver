package it.unical.thesis.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;

import it.unical.thesis.data.CertificateInfo;
import it.unical.thesis.data.DistinguishedName;

public class OpenSSLConfigGenerator {
    
    public enum PolicyType {
        STRICT,
        FLEXIBLE,
        PERMISSIVE
    }
    
    public void generateConfigurations(CertificateInfo caInfo, CertificateInfo serverInfo,
                                     String caTemplatePath, String serverTemplatePath,
                                     String caOutputPath, String serverOutputPath,
                                     PolicyType caPolicyType, PolicyType serverPolicyType) throws IOException {
        
        System.out.println("Generazione configurazione CA con policy " + caPolicyType + "...");
        updateCnfFile(caInfo, "[certificate_authority]", "[v3_ca]", 
                     caTemplatePath, caOutputPath, caPolicyType);
        
        System.out.println("Generazione configurazione Server con policy " + serverPolicyType + "...");
        updateCnfFile(serverInfo, "[server]", "[v3_req]", 
                     serverTemplatePath, serverOutputPath, serverPolicyType);
        
        System.out.println("Configurazioni generate con successo!");
    }
    
    private void updateCnfFile(CertificateInfo certInfo, String dnSectionName, 
                             String extensionsSectionName, String templatePath, 
                             String outputPath, PolicyType policyType) throws IOException {
        
        List<String> templateLines = Files.readAllLines(Paths.get(templatePath));
        List<String> outputLines = new ArrayList<>();

        Map<String, String> dnUpdates = populateCompleteDnMap(certInfo.getSubject());
        Map<String, String> extUpdates = populateCompleteExtensionsMap(certInfo);
        Map<String, String> generalUpdates = populateGeneralParametersMap(certInfo);
        
        String currentSection = null;
        boolean isSkippingSection = false;
        Set<String> sectionsToSkip = Set.of("[alt_names]", "[policy_match]", "[policy_anything]", "[policy_flexible]");

        for (String line : templateLines) {
            String trimmedLine = line.trim();

            if (trimmedLine.startsWith("[") && trimmedLine.endsWith("]")) {
                appendRemainingKeys(outputLines, currentSection, dnSectionName, dnUpdates);
                appendRemainingKeys(outputLines, currentSection, extensionsSectionName, extUpdates);
                appendRemainingKeys(outputLines, currentSection, null, generalUpdates);
                
                currentSection = trimmedLine;
                
                if (sectionsToSkip.contains(currentSection.toLowerCase())) {
                    isSkippingSection = true;
                    continue;
                } else {
                    isSkippingSection = false;
                }
            }

            if (isSkippingSection) {
                continue;
            }
            
            if (currentSection != null && !trimmedLine.isEmpty() && !trimmedLine.startsWith("#")) {
                String[] parts = trimmedLine.split("=", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    
                    if (currentSection.equals(dnSectionName) && 
                            key.equalsIgnoreCase("localityName") && 
                            !dnUpdates.containsKey("localityName")) {
                            
                            continue;
                        }
                    
                    Map<String, String> currentMap = null;
                    if (currentSection.equals(dnSectionName)) {
                        currentMap = dnUpdates;
                    } else if (currentSection.equals(extensionsSectionName)) {
                        currentMap = extUpdates;
                    } else {
                        currentMap = generalUpdates;
                    }

                    if (currentMap != null && currentMap.containsKey(key)) {
                        outputLines.add(key + " = " + currentMap.get(key));
                        currentMap.remove(key);
                    } else {
                        if (currentSection.equals("[CA_default]") && key.equals("policy")) {
                            outputLines.add("policy = " + getPolicyName(policyType));
                        } else {
                            outputLines.add(line);
                        }
                    }
                } else {
                    outputLines.add(line);
                }
            } else {
                outputLines.add(line);
            }
        }

        appendRemainingKeys(outputLines, currentSection, dnSectionName, dnUpdates);
        appendRemainingKeys(outputLines, currentSection, extensionsSectionName, extUpdates);
        appendRemainingKeys(outputLines, currentSection, null, generalUpdates);
        
        createPolicySection(outputLines, policyType);
        createSubjectAltNamesSection(outputLines, certInfo);

        Files.write(Paths.get(outputPath), outputLines);
    }
    
    private Map<String, String> populateCompleteDnMap(DistinguishedName dn) {
        Map<String, String> map = new LinkedHashMap<>();
        
        if (dn == null) return map;
        
        if (isNotEmpty(dn.getCountry())) {
            map.put("countryName", sanitizeConfigValue(dn.getCountry()));
        }
        if (isNotEmpty(dn.getState())) {
            map.put("stateOrProvinceName", sanitizeConfigValue(dn.getState()));
        }
        if (isNotEmpty(dn.getLocality())) {
            map.put("localityName", sanitizeConfigValue(dn.getLocality()));
        }
        if (isNotEmpty(dn.getOrganization())) {
            map.put("organizationName", sanitizeConfigValue(dn.getOrganization()));
        }
        if (isNotEmpty(dn.getOrganizationalUnit())) {
            map.put("organizationalUnitName", sanitizeConfigValue(dn.getOrganizationalUnit()));
        }
        if (isNotEmpty(dn.getCommonName())) {
            map.put("commonName", sanitizeConfigValue(dn.getCommonName()));
        }
        if (isNotEmpty(dn.getEmailAddress())) {
            map.put("emailAddress", sanitizeConfigValue(dn.getEmailAddress()));
        }
        
        return map;
    }
    
    private Map<String, String> populateCompleteExtensionsMap(CertificateInfo certInfo) {
        Map<String, String> map = new LinkedHashMap<>();
        
        StringBuilder bc = new StringBuilder();
        if (certInfo.isBasicConstraintsCritical()) {
            bc.append("critical,");
        }
        bc.append("CA:").append(certInfo.isCA() ? "TRUE" : "FALSE");
        if (certInfo.isCA() && certInfo.getPathLengthConstraint() != null) {
            bc.append(",pathlen:").append(certInfo.getPathLengthConstraint());
        }
        map.put("basicConstraints", bc.toString());

        if (isNotEmpty(certInfo.getKeyUsage())) {
            map.put("keyUsage", certInfo.getKeyUsage());
        } else if (certInfo.isCA()) {
            map.put("keyUsage", "critical,keyCertSign,cRLSign");
        } else {
            map.put("keyUsage", "nonRepudiation,digitalSignature,keyEncipherment");
        }

        if (isNotEmpty(certInfo.getExtendedKeyUsage())) {
            map.put("extendedKeyUsage", convertExtendedKeyUsage(certInfo.getExtendedKeyUsage()));
        }
        
        map.put("subjectKeyIdentifier", "hash");
        
        if (!certInfo.isSelfSigned()) {
            map.put("authorityKeyIdentifier", "keyid:always,issuer:always");
        }

        if (isNotEmpty(certInfo.getCrlDistributionPoints())) {
            map.put("crlDistributionPoints", formatCrlDistributionPoints(certInfo.getCrlDistributionPoints()));
        }
        
        if (isNotEmpty(certInfo.getAuthorityInfoAccess())) {
            map.put("authorityInfoAccess", certInfo.getAuthorityInfoAccess());
        }
        
        if (isNotEmpty(certInfo.getCertificatePolicies())) {
            map.put("certificatePolicies", certInfo.getCertificatePolicies());
        }
        
        if (isNotEmpty(certInfo.getIssuerAltName())) {
            map.put("issuerAltName", certInfo.getIssuerAltName());
        }

        if (isNotEmpty(certInfo.getSubjectAltName())) {
            map.put("subjectAltName", "@alt_names");
        }
        
        return map;
    }
    
    private Map<String, String> populateGeneralParametersMap(CertificateInfo certInfo) {
        Map<String, String> map = new HashMap<>();
        
        if (certInfo.getKeySize() > 0) {
            map.put("default_bits", String.valueOf(certInfo.getKeySize()));
        }
        
        if (isNotEmpty(certInfo.getSignatureAlgorithm())) {
            String md = extractMessageDigest(certInfo.getSignatureAlgorithm());
            if (md != null) {
                map.put("default_md", md);
            }
        }
        
        if (isNotEmpty(certInfo.getNotBefore()) && isNotEmpty(certInfo.getNotAfter())) {
            try {
                long days = calculateValidityDays(certInfo.getNotBefore(), certInfo.getNotAfter());
                if (days > 0) {
                    map.put("default_days", String.valueOf(days));
                }
            } catch (Exception e) {
            }
        }
        
        return map;
    }
    
    private Map<String, String> populatePolicyMap(PolicyType policyType) {
        Map<String, String> map = new LinkedHashMap<>();
        
        switch (policyType) {
            case STRICT:
                map.put("countryName", "match");
                map.put("stateOrProvinceName", "match");
                map.put("localityName", "match");
                map.put("organizationName", "match");
                map.put("organizationalUnitName", "optional");
                map.put("commonName", "supplied");
                map.put("emailAddress", "optional");
                break;
                
            case FLEXIBLE:
                map.put("countryName", "match");
                map.put("stateOrProvinceName", "optional");
                map.put("localityName", "optional");
                map.put("organizationName", "match");
                map.put("organizationalUnitName", "optional");
                map.put("commonName", "supplied");
                map.put("emailAddress", "optional");
                break;
                
            case PERMISSIVE:
                map.put("countryName", "optional");
                map.put("stateOrProvinceName", "optional");
                map.put("localityName", "optional");
                map.put("organizationName", "optional");
                map.put("organizationalUnitName", "optional");
                map.put("commonName", "supplied");
                map.put("emailAddress", "optional");
                break;
        }
        
        return map;
    }
    
    private String getPolicyName(PolicyType policyType) {
        switch (policyType) {
            case STRICT: return "policy_strict";
            case FLEXIBLE: return "policy_flexible";
            case PERMISSIVE: return "policy_permissive";
            default: return "policy_flexible";
        }
    }
    
    private void createPolicySection(List<String> outputLines, PolicyType policyType) {
        outputLines.add("");
        outputLines.add("[" + getPolicyName(policyType) + "]");
        
        Map<String, String> policyMap = populatePolicyMap(policyType);
        for (Map.Entry<String, String> entry : policyMap.entrySet()) {
            outputLines.add(entry.getKey() + " = " + entry.getValue());
        }
    }
    
    private void createSubjectAltNamesSection(List<String> outputLines, CertificateInfo certInfo) {
        if (!isNotEmpty(certInfo.getSubjectAltName())) {
            return;
        }
        
        outputLines.add("");
        outputLines.add("[alt_names]");
        
        String[] altNames = certInfo.getSubjectAltName().split(",");
        int dnsCount = 1;
        int ipCount = 1;
        int emailCount = 1;
        int uriCount = 1;
        
        for (String altName : altNames) {
            altName = altName.trim();
            
            if (altName.toUpperCase().startsWith("DNS:")) {
                String dnsName = altName.substring(4).trim();
                outputLines.add("DNS." + dnsCount++ + " = " + dnsName);
            } else if (altName.toUpperCase().startsWith("IP:")) {
                String ipAddr = altName.substring(3).trim();
                outputLines.add("IP." + ipCount++ + " = " + ipAddr);
            } else if (altName.toUpperCase().startsWith("EMAIL:")) {
                String email = altName.substring(6).trim();
                outputLines.add("email." + emailCount++ + " = " + email);
            } else if (altName.toUpperCase().startsWith("URI:")) {
                String uri = altName.substring(4).trim();
                outputLines.add("URI." + uriCount++ + " = " + uri);
            } else if (!altName.contains(":")) {
                outputLines.add("DNS." + dnsCount++ + " = " + altName);
            }
        }
    }
    
    private void appendRemainingKeys(List<String> outputLines, String currentSection, 
                                   String targetSection, Map<String, String> remainingKeys) {
        if (currentSection != null && currentSection.equals(targetSection) && !remainingKeys.isEmpty()) {
            if (!outputLines.isEmpty() && !outputLines.get(outputLines.size() - 1).trim().isEmpty()) {
                outputLines.add("");
            }
            
            for (Map.Entry<String, String> entry : remainingKeys.entrySet()) {
                outputLines.add(entry.getKey() + " = " + entry.getValue());
            }
            remainingKeys.clear();
        }
    }
    
    private String sanitizeConfigValue(String value) {
        if (value == null) return "";
        
        return value.replace("Ã‚", "a")
                   .replace("Ã¨", "e")
                   .replace("Ã ", "a")
                   .replace("Ã²", "o")
                   .replace("Ã¹", "u")
                   .replaceAll("[\\p{Cntrl}]", "")
                   .trim();
    }
    
    private String formatCrlDistributionPoints(String crlPoints) {
        if (!isNotEmpty(crlPoints)) return "";
        
        if (crlPoints.startsWith("URI:")) {
            return crlPoints;
        }
        
        if (crlPoints.matches("^https?://.*")) {
            return "URI:" + crlPoints;
        }
        
        if (crlPoints.contains(",")) {
            String[] urls = crlPoints.split(",");
            StringBuilder formatted = new StringBuilder();
            
            for (int i = 0; i < urls.length; i++) {
                String url = urls[i].trim();
                if (i > 0) formatted.append(",");
                
                if (url.matches("^https?://.*")) {
                    formatted.append("URI:").append(url);
                } else if (url.startsWith("URI:")) {
                    formatted.append(url);
                } else {
                    formatted.append("URI:").append(url);
                }
            }
            return formatted.toString();
        }
        
        return "URI:" + crlPoints;
    }
    
    private String convertExtendedKeyUsage(String extKeyUsage) {
        if (!isNotEmpty(extKeyUsage)) return extKeyUsage;
        
        return extKeyUsage
            .replace("1.3.6.1.5.5.7.3.1", "serverAuth")
            .replace("1.3.6.1.5.5.7.3.2", "clientAuth")
            .replace("1.3.6.1.5.5.7.3.3", "codeSigning")
            .replace("1.3.6.1.5.5.7.3.4", "emailProtection")
            .replace("1.3.6.1.5.5.7.3.8", "timeStamping")
            .replace("1.3.6.1.5.5.7.3.9", "OCSPSigning");
    }
    
    private String extractMessageDigest(String signatureAlgorithm) {
        if (!isNotEmpty(signatureAlgorithm)) return null;
        
        String lower = signatureAlgorithm.toLowerCase();
        if (lower.contains("sha256")) return "sha256";
        if (lower.contains("sha512")) return "sha512";
        if (lower.contains("sha384")) return "sha384";
        if (lower.contains("sha1")) return "sha1";
        if (lower.contains("md5")) return "md5";
        
        return null;
    }
    
    private long calculateValidityDays(String notBefore, String notAfter) throws DateTimeParseException {
        DateTimeFormatter[] formatters = {
            DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy 'GMT'", Locale.ENGLISH),
            DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy 'GMT'", Locale.ENGLISH),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ISO_LOCAL_DATE_TIME
        };
        
        LocalDateTime startDate = null, endDate = null;
        
        for (DateTimeFormatter formatter : formatters) {
            try {
                startDate = LocalDateTime.parse(notBefore, formatter);
                endDate = LocalDateTime.parse(notAfter, formatter);
                break;
            } catch (DateTimeParseException ignored) {
            }
        }
        
        if (startDate != null && endDate != null) {
            return ChronoUnit.DAYS.between(startDate, endDate);
        }
        
        throw new DateTimeParseException("Unable to parse dates", notBefore + " / " + notAfter, 0);
    }
    
    private boolean isNotEmpty(String str) {
        return str != null && !str.trim().isEmpty();
    }
}