package it.unical.thesis.data;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DistinguishedName {
    private String country; // C
    private String state; // ST
    private String locality; // L
    private String organization; // O
    private String organizationalUnit; // OU
    private String emailAddress; // emailAddress
    private String commonName; // CN

    public DistinguishedName() {}

    public DistinguishedName(String country, String state, String locality,
                           String organization, String organizationalUnit,
                           String emailAddress, String commonName) {
        this.country = country;
        this.state = state;
        this.locality = locality;
        this.organization = organization;
        this.organizationalUnit = organizationalUnit;
        this.emailAddress = emailAddress;
        this.commonName = commonName;
    }

    public DistinguishedName(String dnString) {
        parseDNString(dnString);
    }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    
    public String getCountryName() { return country; }
    public void setCountryName(String country) { this.country = country; }

    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    
    public String getStateOrProvinceName() { return state; }
    public void setStateOrProvinceName(String state) { this.state = state; }

    public String getLocality() { return locality; }
    public void setLocality(String locality) { this.locality = locality; }
    
    public String getLocalityName() { return locality; }
    public void setLocalityName(String locality) { this.locality = locality; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }
    
    public String getOrganizationName() { return organization; }
    public void setOrganizationName(String organization) { this.organization = organization; }

    public String getOrganizationalUnit() { return organizationalUnit; }
    public void setOrganizationalUnit(String organizationalUnit) { this.organizationalUnit = organizationalUnit; }
    
    public String getOrganizationalUnitName() { return organizationalUnit; }
    public void setOrganizationalUnitName(String organizationalUnit) { this.organizationalUnit = organizationalUnit; }

    public String getEmailAddress() { return emailAddress; }
    public void setEmailAddress(String emailAddress) { this.emailAddress = emailAddress; }

    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }

 
    private void parseDNString(String dnString) {
        if (dnString == null || dnString.trim().isEmpty()) {
            return;
        }

        Map<String, String> components = new HashMap<>();
        
        Pattern pattern = Pattern.compile("([A-Za-z]+)=([^,/]+)");
        Matcher matcher = pattern.matcher(dnString);
        
        while (matcher.find()) {
            String key = matcher.group(1).trim();
            String value = matcher.group(2).trim();
            components.put(key.toUpperCase(), value);
        }

        this.country = components.get("C");
        this.state = components.get("ST");
        this.locality = components.get("L");
        this.organization = components.get("O");
        this.organizationalUnit = components.get("OU");
        this.emailAddress = components.get("EMAILADDRESS");
        this.commonName = components.get("CN");
    }

 
    public String toConfigFormat() {
        StringBuilder sb = new StringBuilder();
        
        if (country != null && !country.trim().isEmpty()) {
            sb.append("countryName = ").append(country).append("\n");
        }
        if (state != null && !state.trim().isEmpty()) {
            sb.append("stateOrProvinceName = ").append(state).append("\n");
        }
        if (locality != null && !locality.trim().isEmpty()) {
            sb.append("localityName = ").append(locality).append("\n");
        }
        if (organization != null && !organization.trim().isEmpty()) {
            sb.append("organizationName = ").append(organization).append("\n");
        }
        if (organizationalUnit != null && !organizationalUnit.trim().isEmpty()) {
            sb.append("organizationalUnitName = ").append(organizationalUnit).append("\n");
        }
        if (commonName != null && !commonName.trim().isEmpty()) {
            sb.append("commonName = ").append(commonName).append("\n");
        }
        if (emailAddress != null && !emailAddress.trim().isEmpty()) {
            sb.append("emailAddress = ").append(emailAddress).append("\n");
        }
        
        return sb.toString().trim();
    }

  
    public String toSubjectString() {
        StringBuilder sb = new StringBuilder();
        
        if (country != null && !country.trim().isEmpty()) {
            sb.append("/C=").append(country);
        }
        if (state != null && !state.trim().isEmpty()) {
            sb.append("/ST=").append(state);
        }
        if (locality != null && !locality.trim().isEmpty()) {
            sb.append("/L=").append(locality);
        }
        if (organization != null && !organization.trim().isEmpty()) {
            sb.append("/O=").append(organization);
        }
        if (organizationalUnit != null && !organizationalUnit.trim().isEmpty()) {
            sb.append("/OU=").append(organizationalUnit);
        }
        if (commonName != null && !commonName.trim().isEmpty()) {
            sb.append("/CN=").append(commonName);
        }
        if (emailAddress != null && !emailAddress.trim().isEmpty()) {
            sb.append("/emailAddress=").append(emailAddress);
        }
        
        return sb.toString();
    }

    public String toDNString() {
        StringBuilder dn = new StringBuilder();
        
        if (country != null && !country.trim().isEmpty()) {
            dn.append("C=").append(country);
        }
        if (state != null && !state.trim().isEmpty()) {
            if (dn.length() > 0) dn.append(", ");
            dn.append("ST=").append(state);
        }
        if (locality != null && !locality.trim().isEmpty()) {
            if (dn.length() > 0) dn.append(", ");
            dn.append("L=").append(locality);
        }
        if (organization != null && !organization.trim().isEmpty()) {
            if (dn.length() > 0) dn.append(", ");
            dn.append("O=").append(organization);
        }
        if (organizationalUnit != null && !organizationalUnit.trim().isEmpty()) {
            dn.append("/OU=").append(organizationalUnit);
        }
        if (emailAddress != null && !emailAddress.trim().isEmpty()) {
            dn.append("/emailAddress=").append(emailAddress);
        }
        if (commonName != null && !commonName.trim().isEmpty()) {
            if (dn.length() > 0) dn.append(", ");
            dn.append("CN=").append(commonName);
        }

        return dn.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        DistinguishedName that = (DistinguishedName) obj;
        
        return java.util.Objects.equals(country, that.country) &&
               java.util.Objects.equals(state, that.state) &&
               java.util.Objects.equals(locality, that.locality) &&
               java.util.Objects.equals(organization, that.organization) &&
               java.util.Objects.equals(organizationalUnit, that.organizationalUnit) &&
               java.util.Objects.equals(emailAddress, that.emailAddress) &&
               java.util.Objects.equals(commonName, that.commonName);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(country, state, locality, organization, 
                                    organizationalUnit, emailAddress, commonName);
    }


    public boolean isEmpty() {
        return (country == null || country.trim().isEmpty()) &&
               (state == null || state.trim().isEmpty()) &&
               (locality == null || locality.trim().isEmpty()) &&
               (organization == null || organization.trim().isEmpty()) &&
               (organizationalUnit == null || organizationalUnit.trim().isEmpty()) &&
               (emailAddress == null || emailAddress.trim().isEmpty()) &&
               (commonName == null || commonName.trim().isEmpty());
    }


    public String getShortName() {
        if (commonName != null && !commonName.trim().isEmpty()) {
            return commonName;
        }
        if (organization != null && !organization.trim().isEmpty()) {
            return organization;
        }
        return "Unknown";
    }

    public DistinguishedName copy() {
        return new DistinguishedName(country, state, locality, organization, 
                                   organizationalUnit, emailAddress, commonName);
    }


    public boolean isValid() {
        return commonName != null && !commonName.trim().isEmpty();
    }

 
    public String toFriendlyString() {
        if (commonName != null && !commonName.trim().isEmpty()) {
            StringBuilder sb = new StringBuilder(commonName);
            if (organization != null && !organization.trim().isEmpty()) {
                sb.append(" (").append(organization).append(")");
            }
            return sb.toString();
        }
        return getShortName();
    }

    @Override
    public String toString() {
        return toDNString();
    }
}