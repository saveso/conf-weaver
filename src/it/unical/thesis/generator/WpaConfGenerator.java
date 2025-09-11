package it.unical.thesis.generator;

import it.unical.thesis.utils.FileUtils;

public class WpaConfGenerator {
    
    private final String ssid;
    private final int pmf;
    private final String identity;
    private final String password;

    public WpaConfGenerator(String ssid, int pmf, String identity, String password) {
        this.ssid = ssid;
        this.pmf = pmf;
        this.identity = identity;
        this.password = password;
    }

    public String generateContent() {
        return String.format("""
                network={
                ssid="%s"
                key_mgmt=WPA-EAP
                eap=PEAP
                identity="%s"
                password="%s" 
                phase1="tls_disable_time_checks=1"
                ieee80211w=%d
                }
                """, this.ssid, this.identity, this.password, this.pmf);
    }

    public boolean writeToFile(String filePath) {
        String content = generateContent();
        return FileUtils.writeToFile(filePath, content);
    }
    
}

/*
 	String content = String.format("""
			network={
			ssid="%s"
			key_mgmt=WPA-EAP
			eap=PEAP
			identity="tuo_username"
			password="tua_password" 
			# Permette certificati self-signed nella chain
			phase1="tls_disable_time_checks=1"
			# Oppure usa questo per essere ancora più permissivo
			# ca_cert=""  # Stringa vuota disabilita la verifica CA
			ieee80211w=%s
			}
			""", ssid, pmf);
 */


/*
 * 			network={
			key_mgmt=WPA-EAP
			eap=PEAP
			identity="utente"
			password="passwordfinta"
			phase2="auth=MSCHAPV2"
			ca_cert="/etc/ssl/certs/ca-certificates.crt"
			eapol_flags=3
			}
 */

