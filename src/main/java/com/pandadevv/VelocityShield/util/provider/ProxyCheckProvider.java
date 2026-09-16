package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

/**
 * proxycheck.io - free tier is 100 queries/day without a key, 1000/day with one.
 * https://proxycheck.io/
 */
public class ProxyCheckProvider extends VPNProvider {

    private final String apiKey;

    public ProxyCheckProvider(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
    }

    @Override
    public String name() {
        return "proxycheck";
    }

    @Override
    public boolean isConfigured() {
        return !apiKey.isEmpty() && !apiKey.equals("YOUR_PROXYCHECK_API_KEY");
    }

    @Override
    public String signupUrl() {
        return "https://proxycheck.io/";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        String url = "https://proxycheck.io/v2/" + ip + "?vpn=1&asn=1&risk=1"
            + (apiKey.isEmpty() ? "" : "&key=" + apiKey);

        JsonObject root = getJson(url, connectTimeout, readTimeout);

        String status = str(root, "status");
        if (status != null && !status.equalsIgnoreCase("ok")) {
            throw new IllegalStateException(
                "status=" + status + (str(root, "message") == null ? "" : " " + str(root, "message")));
        }

        JsonObject data = obj(root, ip);
        if (data == null) {
            throw new IllegalStateException("no data for address");
        }

        boolean proxy = bool(data, "proxy");
        String type = str(data, "type");
        boolean tor = type != null && type.equalsIgnoreCase("TOR");
        // proxycheck calls datacenter ranges "Hosting" / "Compromised Server" / "Business".
        boolean hosting = type != null
            && (type.toLowerCase().contains("hosting") || type.toLowerCase().contains("compromised"));

        StringBuilder detail = new StringBuilder(proxy ? "proxy=yes" : "proxy=no");
        if (type != null) detail.append(", type=").append(type);
        String risk = str(data, "risk");
        if (risk != null) detail.append(", risk=").append(risk);

        return ProviderResult.builder(name())
            .verdict(proxy ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail(detail.toString())
            .tor(tor)
            .hosting(hosting)
            .isp(str(data, "provider"))
            .asn(str(data, "asn"))
            .country(str(data, "isocode"))
            .build();
    }
}
