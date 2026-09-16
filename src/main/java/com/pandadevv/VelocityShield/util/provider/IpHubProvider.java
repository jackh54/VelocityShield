package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

import java.util.Map;

/**
 * iphub.info - needs a free key (1000 lookups/day).
 *
 * <p>block=0 residential, block=1 datacenter/VPN, block=2 suspicious but not certain.
 * Only block=1 is treated as a flag; block=2 on its own gets far too many innocents.
 * https://iphub.info/
 */
public class IpHubProvider extends VPNProvider {

    private final String apiKey;

    public IpHubProvider(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
    }

    @Override
    public String name() {
        return "iphub";
    }

    @Override
    public boolean isConfigured() {
        return !apiKey.isEmpty() && !apiKey.startsWith("YOUR_");
    }

    @Override
    public String signupUrl() {
        return "https://iphub.info/";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        JsonObject root = getJson("https://v2.api.iphub.info/ip/" + ip, connectTimeout, readTimeout,
            Map.of("X-Key", apiKey));

        if (!root.has("block")) {
            throw new IllegalStateException("no block field");
        }

        int block = root.get("block").getAsInt();
        boolean flagged = block == 1;

        return ProviderResult.builder(name())
            .verdict(flagged ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail("block=" + block + (block == 2 ? " (suspicious, not counted as VPN)" : ""))
            .hosting(block == 1)
            .isp(str(root, "isp"))
            .asn(str(root, "asn"))
            .country(str(root, "countryCode"))
            .build();
    }
}
