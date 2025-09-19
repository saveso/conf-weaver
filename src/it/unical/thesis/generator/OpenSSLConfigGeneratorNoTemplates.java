package it.unical.thesis.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import it.unical.thesis.data.CertificateInfo;
import it.unical.thesis.data.DistinguishedName;

public class OpenSSLConfigGeneratorNoTemplates {
    
    public void generateCaConfig(CertificateInfo caInfo, String outputPath) throws IOException {
        if (caInfo == null) {
            throw new IllegalArgumentException("CertificateInfo for CA cannot be null");
        }
        
        List<String> lines = new ArrayList<>();
        
        lines.add("[ ca ]");
        lines.add("default_ca = CA_default");
        lines.add("");
        
        lines.add("[ CA_default ]");
        lines.add("dir = ./");
        lines.add("certs = $dir");
        lines.add("crl_dir = $dir/crl");
        lines.add("database = $dir/index.txt");
        lines.add("new_certs_dir = $dir");
        lines.add("certificate = $dir/ca.pem");
        lines.add("serial = $dir/serial");
        lines.add("crl = $dir/crl.pem");
        lines.add("private_key = $dir/ca.key");
        lines.add("RANDFILE = $dir/.rand");
        lines.add("name_opt = ca_default");
        lines.add("cert_opt = ca_default");
        
        lines.add("default_days = 3650");
        lines.add("default_crl_days = 30");
        lines.add("default_md = " + getMessageDigest(caInfo.getSignatureAlgorithm()));
        lines.add("preserve = no");
        lines.add("policy = policy_match");
        
        if (isNotEmpty(caInfo.getCrlDistributionPoints())) {
            lines.add("crlDistributionPoints = " + formatCrlDistributionPoints(caInfo.getCrlDistributionPoints()));
        }
        
        lines.add("");
        
        lines.add("[ policy_match ]");
        lines.add("countryName = match");
        lines.add("stateOrProvinceName = optional");
        lines.add("localityName = optional");
        lines.add("organizationName = match");
        lines.add("organizationalUnitName = optional");
        lines.add("commonName = supplied");
        lines.add("emailAddress = optional");
        lines.add("");
        
        lines.add("[ req ]");
        lines.add("prompt = no");
        lines.add("distinguished_name = certificate_authority");
        lines.add("default_bits = " + (caInfo.getKeySize() > 0 ? caInfo.getKeySize() : 4096));
        lines.add("input_password = whatever");
        lines.add("output_password = whatever");
        lines.add("x509_extensions = v3_ca");
        lines.add("");
        
        lines.add("[certificate_authority]");
        addDistinguishedNameSection(lines, caInfo.getSubject());
        lines.add("");
        
        lines.add("[v3_ca]");
        lines.add("subjectKeyIdentifier = hash");
        lines.add("authorityKeyIdentifier = keyid:always,issuer:always");
        
        if (caInfo.getPathLengthConstraint() != null) {
            lines.add("basicConstraints = critical,CA:TRUE,pathlen:" + caInfo.getPathLengthConstraint());
        } else {
            lines.add("basicConstraints = critical,CA:TRUE");
        }
        
        if (isNotEmpty(caInfo.getCrlDistributionPoints())) {
            lines.add("crlDistributionPoints = " + formatCrlDistributionPoints(caInfo.getCrlDistributionPoints()));
        }
        
        lines.add("keyUsage = critical,keyCertSign,cRLSign");
        
        if (isNotEmpty(caInfo.getAuthorityInfoAccess())) {
            lines.add("authorityInfoAccess = " + caInfo.getAuthorityInfoAccess());
        }
        
        writeConfigFile(outputPath, lines, "ca.cnf");
    }
    
    public void generateServerConfig(CertificateInfo serverInfo, String outputPath) throws IOException {
        if (serverInfo == null) {
            throw new IllegalArgumentException("CertificateInfo for Server cannot be null");
        }
        
        List<String> lines = new ArrayList<>();
        
        lines.add("[ ca ]");
        lines.add("default_ca = CA_default");
        lines.add("");
        
        lines.add("[ CA_default ]");
        lines.add("dir = ./");
        lines.add("certs = $dir");
        lines.add("crl_dir = $dir/crl");
        lines.add("database = $dir/index.txt");
        lines.add("new_certs_dir = $dir");
        lines.add("certificate = $dir/ca.pem");
        lines.add("serial = $dir/serial");
        lines.add("crl = $dir/crl.pem");
        lines.add("private_key = $dir/ca.key");
        lines.add("RANDFILE = $dir/.rand");
        lines.add("name_opt = ca_default");
        lines.add("cert_opt = ca_default");
        lines.add("default_days = 365");
        lines.add("default_crl_days = 30");
        lines.add("default_md = " + getMessageDigest(serverInfo.getSignatureAlgorithm()));
        lines.add("preserve = no");
        lines.add("policy = policy_flexible");
        lines.add("copy_extensions = copy");
        lines.add("");
        
        lines.add("[ policy_flexible ]");
        lines.add("countryName = match");
        lines.add("stateOrProvinceName = optional");
        lines.add("localityName = optional");
        lines.add("organizationName = match");
        lines.add("organizationalUnitName = optional");
        lines.add("commonName = supplied");
        lines.add("emailAddress = optional");
        lines.add("");
        
        lines.add("[ req ]");
        lines.add("prompt = no");
        lines.add("distinguished_name = server");
        lines.add("default_bits = " + (serverInfo.getKeySize() > 0 ? serverInfo.getKeySize() : 2048));
        lines.add("input_password = whatever");
        lines.add("output_password = whatever");
        lines.add("req_extensions = v3_req");
        lines.add("");
        
        lines.add("[server]");
        addDistinguishedNameSection(lines, serverInfo.getSubject());
        lines.add("");
        
        lines.add("[ v3_req ]");
        lines.add("basicConstraints = CA:FALSE");
        lines.add("keyUsage = nonRepudiation, digitalSignature, keyEncipherment");
        lines.add("subjectKeyIdentifier = hash");
        
        if (isNotEmpty(serverInfo.getExtendedKeyUsage())) {
            lines.add("extendedKeyUsage = " + convertExtendedKeyUsage(serverInfo.getExtendedKeyUsage()));
        } else {
            lines.add("extendedKeyUsage = serverAuth");
        }
        
        if (isNotEmpty(serverInfo.getSubjectAltName())) {
            lines.add("subjectAltName = @alt_names");
            lines.add("");
            addSubjectAltNames(lines, serverInfo.getSubjectAltName());
        }
        
        writeConfigFile(outputPath, lines, "server.cnf");
    }
    
    public void generateClientConfig(CertificateInfo clientInfo, String outputPath) throws IOException {
        if (clientInfo == null) {
            throw new IllegalArgumentException("CertificateInfo for Client cannot be null");
        }
        
        List<String> lines = new ArrayList<>();
        
        lines.add("[ ca ]");
        lines.add("default_ca = CA_default");
        lines.add("");
        
        lines.add("[ CA_default ]");
        lines.add("dir = ./");
        lines.add("certs = $dir");
        lines.add("crl_dir = $dir/crl");
        lines.add("database = $dir/index.txt");
        lines.add("new_certs_dir = $dir");
        lines.add("certificate = $dir/ca.pem");
        lines.add("serial = $dir/serial");
        lines.add("crl = $dir/crl.pem");
        lines.add("private_key = $dir/ca.key");
        lines.add("RANDFILE = $dir/.rand");
        lines.add("name_opt = ca_default");
        lines.add("cert_opt = ca_default");
        lines.add("default_days = 365");
        lines.add("default_crl_days = 30");
        lines.add("default_md = " + getMessageDigest(clientInfo.getSignatureAlgorithm()));
        lines.add("preserve = no");
        lines.add("policy = policy_flexible");
        lines.add("copy_extensions = copy");
        lines.add("");
        
        lines.add("[ policy_flexible ]");
        lines.add("countryName = optional");
        lines.add("stateOrProvinceName = optional");
        lines.add("localityName = optional");
        lines.add("organizationName = optional");
        lines.add("organizationalUnitName = optional");
        lines.add("commonName = supplied");
        lines.add("emailAddress = optional");
        lines.add("");
        
        lines.add("[ req ]");
        lines.add("prompt = no");
        lines.add("distinguished_name = client");
        lines.add("default_bits = " + (clientInfo.getKeySize() > 0 ? clientInfo.getKeySize() : 2048));
        lines.add("input_password = whatever");
        lines.add("output_password = whatever");
        lines.add("req_extensions = v3_req");
        lines.add("");
        
        lines.add("[client]");
        addDistinguishedNameSection(lines, clientInfo.getSubject());
        lines.add("");
        
        lines.add("[ v3_req ]");
        lines.add("basicConstraints = CA:FALSE");
        lines.add("keyUsage = nonRepudiation, digitalSignature, keyEncipherment");
        lines.add("subjectKeyIdentifier = hash");
        
        if (isNotEmpty(clientInfo.getExtendedKeyUsage())) {
            lines.add("extendedKeyUsage = " + convertExtendedKeyUsage(clientInfo.getExtendedKeyUsage()));
        } else {
            lines.add("extendedKeyUsage = clientAuth");
        }
        
        if (isNotEmpty(clientInfo.getSubjectAltName())) {
            lines.add("subjectAltName = @alt_names");
            lines.add("");
            addSubjectAltNames(lines, clientInfo.getSubjectAltName());
        }
        
        writeConfigFile(outputPath, lines, "client.cnf");
    }
    
    public void generateXpExtensions(String crlDistributionPoints, String outputPath) throws IOException {
        List<String> lines = new ArrayList<>();
        
        lines.add("#");
        lines.add("#  File containing the OIDs required for Windows and iOS");
        lines.add("#  Generated automatically - DO NOT EDIT MANUALLY");
        lines.add("#");
        lines.add("");
        
        lines.add("[ xpclient_ext]");
        lines.add("extendedKeyUsage = 1.3.6.1.5.5.7.3.2");
        lines.add("subjectKeyIdentifier = hash");
        lines.add("authorityKeyIdentifier = keyid:always,issuer:always");
        if (isNotEmpty(crlDistributionPoints)) {
            lines.add("crlDistributionPoints = " + formatCrlDistributionPoints(crlDistributionPoints));
        }
        lines.add("");
        
        lines.add("[ xpserver_ext]");
        lines.add("extendedKeyUsage = 1.3.6.1.5.5.7.3.1");
        lines.add("subjectKeyIdentifier = hash");
        lines.add("authorityKeyIdentifier = keyid:always,issuer:always");
        if (isNotEmpty(crlDistributionPoints)) {
            lines.add("crlDistributionPoints = " + formatCrlDistributionPoints(crlDistributionPoints));
        }
        lines.add("");
        
        lines.add("# Wi-Fi Certified WPA3 Release 2 - TOFU policy");
        lines.add("certificatePolicies = 1.3.6.1.4.1.40808.1.3.2");
        
        writeConfigFile(outputPath, lines, "xpextensions");
    }
    
    public void generateAllConfigs(CertificateInfo caInfo, CertificateInfo serverInfo, 
                                 CertificateInfo clientInfo, String outputDir) throws IOException {
        
        if (caInfo == null) {
            throw new IllegalArgumentException("CertificateInfo for CA is required");
        }
        
        Files.createDirectories(Paths.get(outputDir));
        
        System.out.println("Generating OpenSSL configuration files...");
        
        generateCaConfig(caInfo, outputDir + "/ca.cnf");
        
        if (serverInfo != null) {
            generateServerConfig(serverInfo, outputDir + "/server.cnf");
        }
        
        if (clientInfo != null) {
            generateClientConfig(clientInfo, outputDir + "/client.cnf");
        }
        
        generateXpExtensions(caInfo.getCrlDistributionPoints(), outputDir + "/xpextensions");
        
        System.out.println("\n=== ALL FILES GENERATED ===");
        System.out.println("Directory: " + outputDir);
        System.out.println("CRL Distribution Points used: " + caInfo.getCrlDistributionPoints());
        System.out.println("\nNow run the OpenSSL commands to generate certificates.");
    }
    
    private void addDistinguishedNameSection(List<String> lines, DistinguishedName dn) {
        if (dn != null) {
            if (isNotEmpty(dn.getCountry())) lines.add("countryName = " + sanitizeValue(dn.getCountry()));
            if (isNotEmpty(dn.getState())) lines.add("stateOrProvinceName = " + sanitizeValue(dn.getState()));
            if (isNotEmpty(dn.getLocality())) lines.add("localityName = " + sanitizeValue(dn.getLocality()));
            if (isNotEmpty(dn.getOrganization())) lines.add("organizationName = " + sanitizeValue(dn.getOrganization()));
            if (isNotEmpty(dn.getOrganizationalUnit())) lines.add("organizationalUnitName = " + sanitizeValue(dn.getOrganizationalUnit()));
            if (isNotEmpty(dn.getCommonName())) lines.add("commonName = " + sanitizeValue(dn.getCommonName()));
            if (isNotEmpty(dn.getEmailAddress())) lines.add("emailAddress = " + sanitizeValue(dn.getEmailAddress()));
        }
    }
    
    private String getMessageDigest(String signatureAlgorithm) {
        if (signatureAlgorithm == null) return "sha256";
        String lower = signatureAlgorithm.toLowerCase();
        if (lower.contains("sha256")) return "sha256";
        if (lower.contains("sha512")) return "sha512";
        if (lower.contains("sha384")) return "sha384";
        if (lower.contains("sha1")) return "sha1";
        return "sha256";
    }
    
    private String formatCrlDistributionPoints(String crlPoints) {
        if (crlPoints == null || crlPoints.trim().isEmpty()) return "";
        if (crlPoints.startsWith("URI:")) return crlPoints;
        if (crlPoints.matches("^https?://.*")) return "URI:" + crlPoints;
        return "URI:" + crlPoints;
    }
    
    private String convertExtendedKeyUsage(String extKeyUsage) {
        if (!isNotEmpty(extKeyUsage)) return extKeyUsage;
        
        return extKeyUsage
            .replace("1.3.6.1.5.5.7.3.1", "serverAuth")
            .replace("1.3.6.1.5.5.7.3.2", "clientAuth")
            .replace("1.3.6.1.5.5.7.3.3", "codeSigning")
            .replace("1.3.6.1.5.5.7.3.4", "emailProtection");
    }
    
    private boolean isNotEmpty(String str) {
        return str != null && !str.trim().isEmpty();
    }
    
    private String sanitizeValue(String value) {
        if (value == null) return "";
        return value.replaceAll("[\\r\\n\\t]", " ").trim();
    }
    
    private void addSubjectAltNames(List<String> lines, String subjectAltName) {
        lines.add("[alt_names]");
        String[] altNames = subjectAltName.split(",");
        int dnsCount = 1;
        int ipCount = 1;
        
        for (String altName : altNames) {
            altName = altName.trim();
            if (altName.toUpperCase().startsWith("DNS:")) {
                lines.add("DNS." + dnsCount++ + " = " + altName.substring(4).trim());
            } else if (altName.toUpperCase().startsWith("IP:")) {
                lines.add("IP." + ipCount++ + " = " + altName.substring(3).trim());
            } else if (!altName.contains(":")) {
                lines.add("DNS." + dnsCount++ + " = " + altName);
            }
        }
    }
    
    private void writeConfigFile(String outputPath, List<String> lines, String fileType) throws IOException {
        Files.write(Paths.get(outputPath), lines);
        System.out.println("Generated " + fileType + ": " + outputPath);
    }
    
   
}