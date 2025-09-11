package it.unical.thesis.data;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;


public class CertificateInfo {
    private DistinguishedName subject;
    private DistinguishedName issuer;

    private String serialNumber;
    private String notBefore;
    private String notAfter;
    private String signatureAlgorithm;
    private int version;
    
    private String keyAlgorithm;
    private int keySize;
    private String publicKeyModulus;
    private String publicKeyExponent;

    private boolean isCA;
    private boolean basicConstraintsCritical;
    private Integer pathLengthConstraint;
    private String subjectKeyIdentifier;
    private String authorityKeyIdentifier;
    private String crlDistributionPoints;
    
    private String keyUsage;
    private String extendedKeyUsage;
    private String subjectAltName;
    private String issuerAltName;
    private String certificatePolicies;

    private boolean selfSigned;
    private String thumbprint;
    private String sha256Fingerprint;
    private boolean expired;
    private int depth;

    private String authorityKeyId;
    private DistinguishedName authorityDirName;
    private String authoritySerial;

    private boolean validForServerAuth;
    private boolean validForClientAuth;
    
    private String authorityInfoAccess;
    
    public CertificateInfo() {
        this.subject = new DistinguishedName();
        this.issuer = new DistinguishedName();
        this.depth = -1; // Non specificato
        this.version = 3; // Default X.509v3
    }

    public CertificateInfo(DistinguishedName subject, DistinguishedName issuer) {
        this();
        this.subject = subject;
        this.issuer = issuer;
        computeDerivedFields();
    }

    
    public DistinguishedName getSubject() { return subject; }
    public void setSubject(DistinguishedName subject) { 
        this.subject = subject; 
        computeDerivedFields();
    }

    public DistinguishedName getIssuer() { return issuer; }
    public void setIssuer(DistinguishedName issuer) { 
        this.issuer = issuer; 
        computeDerivedFields();
    }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { 
        this.serialNumber = serialNumber; 
    }

    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    public String getNotBefore() { return notBefore; }
    public void setNotBefore(String notBefore) { 
        this.notBefore = notBefore; 
        computeExpiration();
    }

    public String getNotAfter() { return notAfter; }
    public void setNotAfter(String notAfter) { 
        this.notAfter = notAfter; 
        computeExpiration();
    }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { 
        this.signatureAlgorithm = signatureAlgorithm; 
    }

    public String getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }

    public int getKeySize() { return keySize; }
    public void setKeySize(int keySize) { this.keySize = keySize; }

    public String getPublicKeyModulus() { return publicKeyModulus; }
    public void setPublicKeyModulus(String publicKeyModulus) { 
        this.publicKeyModulus = publicKeyModulus; 
    }

    public String getPublicKeyExponent() { return publicKeyExponent; }
    public void setPublicKeyExponent(String publicKeyExponent) { 
        this.publicKeyExponent = publicKeyExponent; 
    }
    
    public boolean isCA() { return isCA; }
    public void setCA(boolean isCA) { this.isCA = isCA; }

    public boolean isBasicConstraintsCritical() { return basicConstraintsCritical; }
    public void setBasicConstraintsCritical(boolean critical) { 
        this.basicConstraintsCritical = critical; 
    }

    public Integer getPathLengthConstraint() { return pathLengthConstraint; }
    public void setPathLengthConstraint(Integer pathLengthConstraint) { 
        this.pathLengthConstraint = pathLengthConstraint; 
    }

    public String getSubjectKeyIdentifier() { return subjectKeyIdentifier; }
    public void setSubjectKeyIdentifier(String subjectKeyIdentifier) { 
        this.subjectKeyIdentifier = subjectKeyIdentifier; 
        computeDerivedFields();
    }

    public String getAuthorityKeyIdentifier() { return authorityKeyIdentifier; }
    public void setAuthorityKeyIdentifier(String authorityKeyIdentifier) { 
        this.authorityKeyIdentifier = authorityKeyIdentifier; 
        parseAuthorityKeyIdentifier();
        computeDerivedFields();
    }

    public String getCrlDistributionPoints() { return crlDistributionPoints; }
    public void setCrlDistributionPoints(String crlDistributionPoints) { 
        this.crlDistributionPoints = crlDistributionPoints; 
    }

    public String getKeyUsage() { return keyUsage; }
    public void setKeyUsage(String keyUsage) { 
        this.keyUsage = keyUsage; 
        computeAuthCapabilities();
    }

    public String getExtendedKeyUsage() { return extendedKeyUsage; }
    public void setExtendedKeyUsage(String extendedKeyUsage) { 
        this.extendedKeyUsage = extendedKeyUsage; 
        computeAuthCapabilities();
    }

    public String getSubjectAltName() { return subjectAltName; }
    public void setSubjectAltName(String subjectAltName) { this.subjectAltName = subjectAltName; }

    public String getIssuerAltName() { return issuerAltName; }
    public void setIssuerAltName(String issuerAltName) { this.issuerAltName = issuerAltName; }

    public String getCertificatePolicies() { return certificatePolicies; }
    public void setCertificatePolicies(String certificatePolicies) { 
        this.certificatePolicies = certificatePolicies; 
    }
    
    public boolean isSelfSigned() { return selfSigned; }
    
    public String getThumbprint() { return thumbprint; }
    public void setThumbprint(String thumbprint) { this.thumbprint = thumbprint; }
    
    public String getSha256Fingerprint() { return sha256Fingerprint; }
    public void setSha256Fingerprint(String sha256Fingerprint) { 
        this.sha256Fingerprint = sha256Fingerprint; 
    }
    
    public boolean isExpired() { return expired; }
    
    public int getDepth() { return depth; }
    public void setDepth(int depth) { this.depth = depth; }

    public String getAuthorityKeyId() { return authorityKeyId; }
    public DistinguishedName getAuthorityDirName() { return authorityDirName; }
    public String getAuthoritySerial() { return authoritySerial; }

    public boolean isValidForServerAuth() { return validForServerAuth; }
    public boolean isValidForClientAuth() { return validForClientAuth; }
    
    public String getAuthorityInfoAccess() {
        return authorityInfoAccess;
    }

    public void setAuthorityInfoAccess(String authorityInfoAccess) {
        this.authorityInfoAccess = authorityInfoAccess;
    }

    
    public boolean isRoot() {
        return isCA && selfSigned && depth == 0;
    }

 
    public boolean isIntermediate() {
        return isCA && !selfSigned && depth > 0;
    }

 
    public boolean isEndEntity() {
        return !isCA;
    }


    public boolean hasServerAuth() {
        return validForServerAuth || 
               (extendedKeyUsage != null && extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1"));
    }


    public boolean hasClientAuth() {
        return validForClientAuth || 
               (extendedKeyUsage != null && extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2"));
    }

 
    public boolean isValidForRADIUS() {
        if (expired) return false;
        
        if (isCA) return true;
        
        return extendedKeyUsage == null || hasServerAuth();
    }

   
    public boolean matchesHostname(String hostname) {
        if (hostname == null) return false;
        
        if (subject != null && subject.getCommonName() != null) {
            if (matchesDnsName(subject.getCommonName(), hostname)) {
                return true;
            }
        }
        
        if (subjectAltName != null) {
            String[] altNames = subjectAltName.split(",");
            for (String altName : altNames) {
                altName = altName.trim();
                if (altName.startsWith("DNS:")) {
                    String dnsName = altName.substring(4).trim();
                    if (matchesDnsName(dnsName, hostname)) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    
    private boolean matchesDnsName(String certName, String hostname) {
        if (certName.equals(hostname)) return true;
        
        // Gestione wildcard semplice
        if (certName.startsWith("*.")) {
            String domain = certName.substring(2);
            return hostname.endsWith("." + domain);
        }
        
        return false;
    }


    public String getCertificateType() {
        if (isRoot()) return "Root CA";
        if (isIntermediate()) return "Intermediate CA";
        if (isEndEntity()) {
            if (hasServerAuth() && hasClientAuth()) return "Server/Client Certificate";
            if (hasServerAuth()) return "Server Certificate";
            if (hasClientAuth()) return "Client Certificate";
            return "End Entity Certificate";
        }
        return "Unknown";
    }


    private void computeDerivedFields() {
        if (subject != null && issuer != null) {
            boolean sameSubjectIssuer = subject.toDNString().equals(issuer.toDNString());
            boolean sameKeyIds = subjectKeyIdentifier != null && 
                               subjectKeyIdentifier.equals(authorityKeyId);
            this.selfSigned = sameSubjectIssuer || sameKeyIds;
        }
    }


    private void computeExpiration() {
        if (notAfter != null) {
            try {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy 'GMT'", Locale.ENGLISH);
                LocalDateTime expiryDate = LocalDateTime.parse(notAfter, formatter);
                this.expired = LocalDateTime.now().isAfter(expiryDate);
            } catch (DateTimeParseException e) {
                try {
                    DateTimeFormatter altFormatter = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy 'GMT'", Locale.ENGLISH);
                    LocalDateTime expiryDate = LocalDateTime.parse(notAfter, altFormatter);
                    this.expired = LocalDateTime.now().isAfter(expiryDate);
                } catch (DateTimeParseException e2) {
                    this.expired = false;
                }
            }
        }
    }


    private void computeAuthCapabilities() {
        this.validForServerAuth = extendedKeyUsage != null && 
                                 extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1");
        this.validForClientAuth = extendedKeyUsage != null && 
                                 extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2");
    }


    private void parseAuthorityKeyIdentifier() {
        if (authorityKeyIdentifier == null) return;
        
        String[] lines = authorityKeyIdentifier.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.startsWith("keyid:")) {
                this.authorityKeyId = line.substring(6).trim();
            } else if (line.startsWith("DirName:")) {
                String dnString = line.substring(8).trim();
                this.authorityDirName = new DistinguishedName(dnString);
            } else if (line.startsWith("serial:")) {
                this.authoritySerial = line.substring(7).trim();
            }
        }
    }
    
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== CERTIFICATE INFORMATION ===\n");
        sb.append("Type: ").append(getCertificateType()).append("\n");
        sb.append("Version: ").append(version).append("\n");
        sb.append("Subject: ").append(subject != null ? subject.toDNString() : "N/A").append("\n");
        sb.append("Issuer: ").append(issuer != null ? issuer.toDNString() : "N/A").append("\n");
        sb.append("Serial Number: ").append(serialNumber != null ? serialNumber : "N/A").append("\n");
        sb.append("Valid From: ").append(notBefore != null ? notBefore : "N/A").append("\n");
        sb.append("Valid Until: ").append(notAfter != null ? notAfter : "N/A").append(" (Expired: ").append(expired).append(")\n");
        sb.append("Signature Algorithm: ").append(signatureAlgorithm != null ? signatureAlgorithm : "N/A").append("\n");
        sb.append("Public Key: ").append(keyAlgorithm != null ? keyAlgorithm : "N/A").append(" (").append(keySize).append(" bit)\n");
        
        sb.append("\n=== X.509 EXTENSIONS ===\n");
        sb.append("Is CA: ").append(isCA);
        if (pathLengthConstraint != null) {
            sb.append(" (Path Length: ").append(pathLengthConstraint).append(")");
        }
        sb.append("\n");
        sb.append("Basic Constraints Critical: ").append(basicConstraintsCritical).append("\n");
        
        if (subjectKeyIdentifier != null) {
            sb.append("Subject Key Identifier: ").append(subjectKeyIdentifier).append("\n");
        }
        
        if (authorityKeyId != null) {
            sb.append("Authority Key ID: ").append(authorityKeyId).append("\n");
        }
        
        if (keyUsage != null) {
            sb.append("Key Usage: ").append(keyUsage).append("\n");
        }
        if (extendedKeyUsage != null) {
            sb.append("Extended Key Usage: ").append(extendedKeyUsage).append("\n");
            sb.append("  - Server Auth: ").append(hasServerAuth()).append("\n");
            sb.append("  - Client Auth: ").append(hasClientAuth()).append("\n");
        }
        if (subjectAltName != null) {
            sb.append("Subject Alt Name: ").append(subjectAltName).append("\n");
        }
        if (crlDistributionPoints != null) {
            sb.append("CRL Distribution Points: ").append(crlDistributionPoints).append("\n");
        }
        
        sb.append("\n=== DERIVED INFORMATION ===\n");
        sb.append("Self-Signed: ").append(selfSigned).append("\n");
        sb.append("Chain Depth: ").append(depth >= 0 ? depth : "Unknown").append("\n");
        if (thumbprint != null) {
            sb.append("SHA-1 Fingerprint: ").append(thumbprint).append("\n");
        }
        if (sha256Fingerprint != null) {
            sb.append("SHA-256 Fingerprint: ").append(sha256Fingerprint).append("\n");
        }
        sb.append("Valid for RADIUS: ").append(isValidForRADIUS()).append("\n");
        
        if (authorityInfoAccess != null) {
            sb.append("Authority Information Access: ").append(authorityInfoAccess).append("\n");
        }
        
        return sb.toString();
    }
}