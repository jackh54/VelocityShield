package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

/**
 * vpnapi.io - needs a free key (1000 lookups/day).
 * https://vpnapi.io/
 */
public class VpnApiProvider extends VPNProvider {

    private final String apiKey;

    public VpnApiProvider(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
    }

    @Override
    public String name() {
        return "vpnapi";
    }

    @Override
    public boolean isConfigured() {
        return !apiKey.isEmpty() && !apiKey.startsWith("YOUR_");
    }

    @Override
    public String signupUrl() {
        return "https://vpnapi.io/";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        JsonObject root = getJson("https://vpnapi.io/api/" + ip + "?key=" + apiKey, connectTimeout, readTimeout);

        if (root.has("message")) {
            throw new IllegalStateException(str(root, "message"));
        }

        JsonObject security = obj(root, "security");
        if (security == null) {
            throw new IllegalStateException("no security block");
        }

        boolean vpn = bool(security, "vpn");
        boolean proxy = bool(security, "proxy");
        boolean tor = bool(security, "tor");
        boolean relay = bool(security, "relay");

        // iCloud Private Relay is not a VPN a cheater hides behind - note it, don't punish it.
        boolean flagged = vpn || proxy || tor;

        JsonObject network = obj(root, "network");
        JsonObject location = obj(root, "location");

        String detail = "vpn=" + vpn + ", proxy=" + proxy + (tor ? ", tor=true" : "")
            + (relay ? ", relay=true" : "");

        return ProviderResult.builder(name())
            .verdict(flagged ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail(detail)
            .tor(tor)
            .isp(network == null ? null : str(network, "autonomous_system_organization"))
            .asn(network == null ? null : str(network, "autonomous_system_number"))
            .country(location == null ? null : str(location, "country_code"))
            .build();
    }
}
