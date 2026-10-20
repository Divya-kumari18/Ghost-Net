package com.ghostnet.service;

import com.ghostnet.model.VulnerabilityFinding;
import com.ghostnet.model.VulnerabilityScan;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import org.xml.sax.InputSource;
import java.util.*;
import java.util.regex.Pattern;

/** Parses evidence within its host/port scope. Never resolves external XML entities. */
public final class NmapXmlParser {
    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}", Pattern.CASE_INSENSITIVE);
    private NmapXmlParser() {}
    public static List<VulnerabilityFinding> parse(String xml, VulnerabilityScan scan, boolean portsOnly) {
        try {
            var factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            var builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
            var doc = builder.parse(new InputSource(new StringReader(xml)));
            List<VulnerabilityFinding> findings = new ArrayList<>();
            NodeList hosts = doc.getElementsByTagName("host");
            for (int h = 0; h < hosts.getLength(); h++) {
                var host = (Element) hosts.item(h);
                String address = null;
                var addresses = host.getElementsByTagName("address");
                for (int a = 0; a < addresses.getLength(); a++) {
                    var item = (Element) addresses.item(a);
                    if (Set.of("ipv4", "ipv6").contains(item.getAttribute("addrtype"))) { address = item.getAttribute("addr"); break; }
                }
                if (address == null) continue;
                if (portsOnly) {
                    var ports = host.getElementsByTagName("port");
                    for (int p = 0; p < ports.getLength(); p++) {
                        var port = (Element) ports.item(p);
                        var states = port.getElementsByTagName("state");
                        if (states.getLength() == 0 || !"open".equals(((Element) states.item(0)).getAttribute("state"))) continue;
                        String service = port.getAttribute("protocol") + "/" + port.getAttribute("portid");
                        findings.add(VulnerabilityFinding.builder().scan(scan).hostIp(address)
                            .vulnerabilityName("Open Port: " + service).severity("info").status("open")
                            .description("Open service " + service + " on " + address + ". Exposure alone does not prove a vulnerability.")
                            .remediation("Verify intended exposure and restrict access where appropriate.").build());
                    }
                } else {
                    var scripts = host.getElementsByTagName("script");
                    for (int s = 0; s < scripts.getLength(); s++) {
                        var script = (Element) scripts.item(s);
                        String output = script.getAttribute("output") + "\n" + script.getTextContent();
                        String upper = output.toUpperCase(Locale.ROOT);
                        // Explicit negative results do not constitute evidence.
                        if (upper.contains("NOT VULNERABLE") || upper.contains("NOT_VULNERABLE")) continue;
                        var matcher = CVE.matcher(output);
                        Set<String> cves = new LinkedHashSet<>();
                        while (matcher.find()) cves.add(matcher.group().toUpperCase(Locale.ROOT));
                        if (cves.isEmpty() && !upper.contains("VULNERABLE")) continue;
                        if (cves.isEmpty()) cves.add("");
                        String context = script.getParentNode() instanceof Element parent && parent.getTagName().equals("port")
                            ? " [" + parent.getAttribute("protocol") + "/" + parent.getAttribute("portid") + "]" : "";
                        for (String cve : cves) findings.add(VulnerabilityFinding.builder().scan(scan).hostIp(address)
                            .cveId(cve.isEmpty() ? null : cve).vulnerabilityName(script.getAttribute("id") + context)
                            .severity("medium").status("open").description(output)
                            .remediation("Validate scanner evidence and apply the vendor mitigation.").build());
                    }
                }
            }
            return findings;
        } catch (Exception ex) { throw new IllegalArgumentException("Invalid Nmap XML; no findings accepted", ex); }
    }
}
