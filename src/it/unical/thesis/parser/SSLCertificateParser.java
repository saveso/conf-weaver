package it.unical.thesis.parser;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.unical.thesis.data.CertificateInfo;
import it.unical.thesis.data.DistinguishedName;

public class SSLCertificateParser {

	public static CertificateInfo parseCertificate(String certificateText) {
		return parseCertificate(Arrays.asList(certificateText.split("\n")));
	}

	public static CertificateInfo parseCertificate(List<String> lines) {
		List<CertificateInfo> certificates = parseMultipleCertificates(lines);
		return certificates.isEmpty() ? new CertificateInfo() : certificates.get(0);
	}

	public static List<CertificateInfo> parseMultipleCertificates(List<String> lines) {
		List<CertificateInfo> certificates = new ArrayList<>();
		Map<Integer, List<List<String>>> certificateBlocks = splitCertificatesByDepth(lines);

		for (Map.Entry<Integer, List<List<String>>> entry : certificateBlocks.entrySet()) {
			Integer depth = entry.getKey();
			for (List<String> block : entry.getValue()) {
				CertificateInfo info = parseSingleCertificate(block);
				info.setDepth(depth);
				certificates.add(info);
			}
		}

		certificates.sort(Comparator.comparing(CertificateInfo::getDepth));
		return certificates;
	}

	private static CertificateInfo parseSingleCertificate(List<String> lines) {
		CertificateInfo info = new CertificateInfo();
		String fullText = String.join("\n", lines);

		extractVersion(fullText, info);
		extractSerialNumber(lines, info);
		extractSignatureAlgorithm(fullText, info);
		extractIssuerAndSubject(lines, info);
		extractValidityDates(lines, info);
		extractPublicKeyInfo(fullText, lines, info);
		extractX509Extensions(lines, fullText, info);
		extractAuthorityInfoAccess(lines, info);

		return info;
	}

	private static void extractVersion(String fullText, CertificateInfo info) {
		Pattern versionPattern = Pattern.compile("Version:\\s*(\\d+)\\s*\\(0x\\d+\\)");
		Matcher versionMatcher = versionPattern.matcher(fullText);
		if (versionMatcher.find()) {
			try {
				info.setVersion(Integer.parseInt(versionMatcher.group(1)));
			} catch (NumberFormatException e) {
				info.setVersion(3);
			}
		}
	}

	private static void extractSignatureAlgorithm(String fullText, CertificateInfo info) {
		Pattern sigAlgPattern = Pattern.compile("Signature Algorithm:\\s*([\\w\\d]+(?:With[\\w\\d]+)?)");
		Matcher sigAlgMatcher = sigAlgPattern.matcher(fullText);
		if (sigAlgMatcher.find()) {
			info.setSignatureAlgorithm(sigAlgMatcher.group(1).trim());
		}
	}

	private static void extractIssuerAndSubject(List<String> lines, CertificateInfo info) {
		for (String line : lines) {
			String cleanLine = cleanLine(line);

			if (cleanLine.contains("Issuer:")) {
				String issuerString = extractFromLine(cleanLine, "Issuer:\\s*(.+)");
				if (issuerString != null) {
					info.setIssuer(new DistinguishedName(issuerString));
				}
			}

			if (cleanLine.contains("Subject:")) {
				String subjectString = extractFromLine(cleanLine, "Subject:\\s*(.+)");
				if (subjectString != null) {
					info.setSubject(new DistinguishedName(subjectString));
				}
			}
		}
	}

	private static void extractValidityDates(List<String> lines, CertificateInfo info) {
		for (String line : lines) {
			String cleanLine = cleanLine(line);

			if (cleanLine.contains("Not Before:")) {
				String notBefore = extractFromLine(cleanLine, "Not Before:\\s*(.+)");
				if (notBefore != null) {
					info.setNotBefore(notBefore.trim());
				}
			}

			if (cleanLine.contains("Not After")) {
				String notAfter = extractFromLine(cleanLine, "Not After\\s*:\\s*(.+)");
				if (notAfter != null) {
					info.setNotAfter(notAfter.trim());
				}
			}
		}
	}

	private static void extractPublicKeyInfo(String fullText, List<String> lines, CertificateInfo info) {
		Pattern keyAlgPattern = Pattern.compile("Public Key Algorithm:\\s*([\\w\\d]+)");
		Matcher keyAlgMatcher = keyAlgPattern.matcher(fullText);
		if (keyAlgMatcher.find()) {
			info.setKeyAlgorithm(keyAlgMatcher.group(1).trim());
		}

		Pattern keySizePattern = Pattern.compile("Public-Key:\\s*\\((\\d+)\\s*bit\\)");
		Matcher keySizeMatcher = keySizePattern.matcher(fullText);
		if (keySizeMatcher.find()) {
			try {
				info.setKeySize(Integer.parseInt(keySizeMatcher.group(1)));
			} catch (NumberFormatException e) {
				info.setKeySize(0);
			}
		}

		Pattern exponentPattern = Pattern.compile("Exponent:\\s*(\\d+)\\s*\\(0x([a-fA-F0-9]+)\\)");
		Matcher exponentMatcher = exponentPattern.matcher(fullText);
		if (exponentMatcher.find()) {
			info.setPublicKeyExponent(exponentMatcher.group(1));
		}

		extractModulus(lines, info);
	}

	private static void extractModulus(List<String> lines, CertificateInfo info) {
		StringBuilder modulusBuilder = new StringBuilder();
		boolean inModulusSection = false;

		for (String line : lines) {
			String cleanLine = cleanLine(line);

			if (cleanLine.contains("Modulus:")) {
				inModulusSection = true;
				continue;
			}

			if (inModulusSection) {
				if (cleanLine.matches("^[a-fA-F0-9:]+$")) {
					modulusBuilder.append(cleanLine.replace(":", ""));
				} else if (cleanLine.contains("Exponent:") || cleanLine.contains("X509v3")) {
					break;
				}
			}
		}

		if (modulusBuilder.length() > 0) {
			info.setPublicKeyModulus(modulusBuilder.toString());
		}
	}

	private static void extractX509Extensions(List<String> lines, String fullText, CertificateInfo info) {
		extractBasicConstraints(fullText, info);
		extractSubjectKeyIdentifier(lines, fullText, info);
		extractAuthorityKeyIdentifier(lines, info);
		extractCRLDistributionPoints(fullText, info);
		extractKeyUsage(fullText, info);
		extractExtendedKeyUsage(fullText, info);
		extractSubjectAltName(fullText, info);
		extractIssuerAltName(fullText, info);
		extractCertificatePolicies(fullText, info);
	}

	private static void extractBasicConstraints(String fullText, CertificateInfo info) {
		Pattern bcPattern = Pattern.compile("X509v3 Basic Constraints:\\s*(critical)?\\s*CA:(TRUE|FALSE)(?:,\\s*pathlen:(\\d+))?", 
				Pattern.CASE_INSENSITIVE);
		Matcher bcMatcher = bcPattern.matcher(fullText);
		if (bcMatcher.find()) {
			info.setBasicConstraintsCritical(bcMatcher.group(1) != null);
			info.setCA("TRUE".equalsIgnoreCase(bcMatcher.group(2)));

			if (bcMatcher.group(3) != null) {
				try {
					info.setPathLengthConstraint(Integer.parseInt(bcMatcher.group(3)));
				} catch (NumberFormatException e) {
				}
			}
		}
	}

	private static void extractSubjectKeyIdentifier(List<String> lines, String fullText, CertificateInfo info) {
		Pattern subjectKeyPattern = Pattern.compile("X509v3 Subject Key Identifier:\\s*([A-F0-9:]+)");
		Matcher subjectKeyMatcher = subjectKeyPattern.matcher(fullText);
		if (subjectKeyMatcher.find()) {
			info.setSubjectKeyIdentifier(subjectKeyMatcher.group(1).trim());
		} else {
			for (int i = 0; i < lines.size(); i++) {
				if (lines.get(i).contains("X509v3 Subject Key Identifier:")) {
					if (i + 1 < lines.size()) {
						String nextLine = cleanLine(lines.get(i + 1));
						if (nextLine.matches("[A-F0-9:]+")) {
							info.setSubjectKeyIdentifier(nextLine);
						}
					}
					break;
				}
			}
		}
	}

	private static void extractAuthorityKeyIdentifier(List<String> lines, CertificateInfo info) {
		StringBuilder authKeyId = new StringBuilder();
		boolean inAuthKeySection = false;

		for (String line : lines) {
			String cleanLine = cleanLine(line);

			if (cleanLine.contains("X509v3 Authority Key Identifier:")) {
				inAuthKeySection = true;
				continue;
			}

			if (inAuthKeySection) {
				if (cleanLine.startsWith("keyid:") || cleanLine.startsWith("DirName:") || 
						cleanLine.startsWith("serial:") || cleanLine.matches("^[A-F0-9:]+$")) {
					if (authKeyId.length() > 0) authKeyId.append("\n");
					authKeyId.append(cleanLine);
				} else if (cleanLine.contains("X509v3") || cleanLine.isEmpty()) {
					break;
				}
			}
		}

		if (authKeyId.length() > 0) {
			info.setAuthorityKeyIdentifier(authKeyId.toString());
		}
	}

	private static void extractCRLDistributionPoints(String fullText, CertificateInfo info) {
		Pattern crlPattern = Pattern.compile("URI:([^\\s\\n]+)");
		Matcher crlMatcher = crlPattern.matcher(fullText);
		if (crlMatcher.find()) {
			info.setCrlDistributionPoints(crlMatcher.group(1).trim());
		}
	}

	private static void extractKeyUsage(String fullText, CertificateInfo info) {
		Pattern keyUsagePattern = Pattern.compile("X509v3 Key Usage:(?:\\s*critical)?\\s*([^\\n]+)");
		Matcher keyUsageMatcher = keyUsagePattern.matcher(fullText);
		if (keyUsageMatcher.find()) {
			info.setKeyUsage(keyUsageMatcher.group(1).trim());
		}
	}

	private static void extractExtendedKeyUsage(String fullText, CertificateInfo info) {
		Pattern extKeyUsagePattern = Pattern.compile("X509v3 Extended Key Usage:(?:\\s*critical)?\\s*([^\\n]+)");
		Matcher extKeyUsageMatcher = extKeyUsagePattern.matcher(fullText);
		if (extKeyUsageMatcher.find()) {
			info.setExtendedKeyUsage(extKeyUsageMatcher.group(1).trim());
		}
	}

	private static void extractSubjectAltName(String fullText, CertificateInfo info) {
		Pattern sanPattern = Pattern.compile("X509v3 Subject Alternative Name:(?:\\s*critical)?\\s*([^\\n]+)");
		Matcher sanMatcher = sanPattern.matcher(fullText);
		if (sanMatcher.find()) {
			info.setSubjectAltName(sanMatcher.group(1).trim());
		}
	}

	private static void extractIssuerAltName(String fullText, CertificateInfo info) {
		Pattern ianPattern = Pattern.compile("X509v3 Issuer Alternative Name:(?:\\s*critical)?\\s*([^\\n]+)");
		Matcher ianMatcher = ianPattern.matcher(fullText);
		if (ianMatcher.find()) {
			info.setIssuerAltName(ianMatcher.group(1).trim());
		}
	}

	private static void extractCertificatePolicies(String fullText, CertificateInfo info) {
		Pattern policiesPattern = Pattern.compile("X509v3 Certificate Policies:(?:\\s*critical)?\\s*([^\\n]+(?:\\n\\s+[^\\n]+)*)");
		Matcher policiesMatcher = policiesPattern.matcher(fullText);
		if (policiesMatcher.find()) {
			info.setCertificatePolicies(policiesMatcher.group(1).trim().replaceAll("\\n\\s+", " "));
		}
	}

	private static String cleanLine(String line) {
		return line.replaceAll("\\[ALL\\]\\s*", "").trim();
	}

	private static String extractFromLine(String line, String pattern) {
		Pattern p = Pattern.compile(pattern);
		Matcher m = p.matcher(line);
		if (m.find()) {
			return m.group(1).trim();
		}
		return null;
	}

	private static void extractSerialNumber(List<String> lines, CertificateInfo info) {
		for (int i = 0; i < lines.size(); i++) {
			String line = cleanLine(lines.get(i));

			if (line.contains("Serial Number:")) {
				String serialFromSameLine = extractFromLine(line, "Serial Number:\\s*(.+)");
				if (serialFromSameLine != null && !serialFromSameLine.trim().isEmpty() && 
						!serialFromSameLine.contains("Signature")) {
					info.setSerialNumber(serialFromSameLine.trim());
					return;
				}

				StringBuilder serialBuilder = new StringBuilder();
				for (int j = i + 1; j < lines.size(); j++) {
					String nextLine = cleanLine(lines.get(j));

					if (nextLine.contains("Signature Algorithm:") || 
							nextLine.contains("Issuer:") || 
							nextLine.contains("Validity") ||
							nextLine.trim().isEmpty()) {
						break;
					}

					if (nextLine.matches("^\\s*[a-fA-F0-9:]+\\s*$")) {
						serialBuilder.append(nextLine.trim());
					} else {
						break;
					}
				}

				if (serialBuilder.length() > 0) {
					info.setSerialNumber(serialBuilder.toString());
					return;
				}
			}
		}
	}

	private static Map<Integer, List<List<String>>> splitCertificatesByDepth(List<String> lines) {
		Map<Integer, List<List<String>>> certificateBlocks = new HashMap<>();
		Set<Integer> hasFullSection = new HashSet<>();

		List<String> currentBlock = null;
		Integer currentDepth = null;
		boolean inCertificateSection = false;

		Pattern opensslDepth = Pattern.compile("OpenSSL: Peer certificate - depth\\s+(\\d+)");
		Pattern wpaPeerCert = Pattern.compile("CTRL-EVENT-EAP-PEER-CERT\\s+depth=(\\d+)\\s+subject='([^']*)'");

		for (String line : lines) {
			Matcher mDepth = opensslDepth.matcher(line);
			if (mDepth.find()) {
				if (inCertificateSection && currentBlock != null && currentDepth != null) {
					certificateBlocks.computeIfAbsent(currentDepth, k -> new ArrayList<>())
					.add(new ArrayList<>(currentBlock));
				}
				currentDepth = Integer.parseInt(mDepth.group(1));
				currentBlock = new ArrayList<>();
				inCertificateSection = false;
				continue;
			}

			if (line.trim().equals("Certificate:")) {
				inCertificateSection = true;
				if (currentBlock == null) {
					currentDepth = (currentDepth == null) ? 0 : currentDepth;
					currentBlock = new ArrayList<>();
				}
				currentBlock.add("Certificate:");
				hasFullSection.add(currentDepth);
				continue;
			}

			if (inCertificateSection && currentBlock != null) {
				if (line.startsWith("wlan0: CTRL-EVENT-EAP-PEER-CERT") ||
						line.startsWith("TLS: Certificate verification") ||
						line.startsWith("EAP: Status notification") ||
						opensslDepth.matcher(line).find()) {
					certificateBlocks.computeIfAbsent(currentDepth, k -> new ArrayList<>())
					.add(new ArrayList<>(currentBlock));
					currentBlock = null;
					inCertificateSection = false;
				} else {
					currentBlock.add(line);
				}
				continue;
			}

			Matcher mWpa = wpaPeerCert.matcher(line);
			if (mWpa.find()) {
				int d = Integer.parseInt(mWpa.group(1));
				String subj = normalizeWpaSubjectDn(mWpa.group(2));

				if (!hasFullSection.contains(d)) {
					List<String> synthetic = new ArrayList<>();
					synthetic.add("Certificate:");
					synthetic.add("Subject: " + subj);
					certificateBlocks.computeIfAbsent(d, k -> new ArrayList<>()).add(synthetic);
				}
			}
		}

		if (inCertificateSection && currentBlock != null && currentDepth != null) {
			certificateBlocks.computeIfAbsent(currentDepth, k -> new ArrayList<>()).add(currentBlock);
		}

		if (certificateBlocks.isEmpty()) {
			List<String> single = new ArrayList<>();
			boolean found = false;
			for (String l : lines) {
				if (!found && l.trim().equals("Certificate:")) {
					found = true;
				}
				if (found) single.add(l);
			}
			if (!single.isEmpty()) {
				certificateBlocks.computeIfAbsent(0, k -> new ArrayList<>()).add(single);
			}
		}

		return certificateBlocks;
	}

	private static String normalizeWpaSubjectDn(String dn) {
		if (dn == null) return "";
		String s = dn.trim();
		if (s.startsWith("/")) {
			s = s.substring(1);
			s = s.replace("/", ", ");
		}
		return s;
	}

	private static void extractAuthorityInfoAccess(List<String> lines, CertificateInfo info) {
		StringBuilder aiaBuilder = new StringBuilder();
		boolean inAIASection = false;

		for (String line : lines) {
			String cleanLine = cleanLine(line);

			if (cleanLine.contains("Authority Information Access")) {
				inAIASection = true;
				continue;
			}

			if (inAIASection) {
				if (cleanLine.startsWith("OCSP") || cleanLine.startsWith("CA Issuers")) {
					if (aiaBuilder.length() > 0) aiaBuilder.append("\n");
					aiaBuilder.append(cleanLine);
				} else if (cleanLine.contains("X509v3") || cleanLine.isEmpty()) {
					break;
				}
			}
		}

		if (aiaBuilder.length() > 0) {
			info.setAuthorityInfoAccess(aiaBuilder.toString().trim());
		}
	}
}