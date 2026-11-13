package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

import java.util.Map;

/**
 * VPNDetection - VPN, Tor, privacy relay (iCloud Private Relay) and hosting network.
 *
 * <p>Needs no API key and has no daily cap. A key from a paid plan adds the proxy flags
 * and the range-level hosting flag, which are read when present.
 * https://vpndetection.io/
 */
public class VpnDetectionProvider extends VPNProvider {

    private final String apiKey;

    public VpnDetectionProvider(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
    }

    @Override
    public String name() {
        return "vpndetection";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        Map<String, String> headers = apiKey.isEmpty() ? Map.of() : Map.of("X-Api-Key", apiKey);
        JsonObject root = getJson("https://api.vpndetection.io/" + ip, connectTimeout, readTimeout, headers);

        if (!root.has("is_vpn")) {
            throw new IllegalStateException(root.has("error") ? str(root, "error") : "response has no is_vpn field");
        }

        boolean vpn = bool(root, "is_vpn");
        boolean tor = bool(root, "is_tor");
        boolean relay = bool(root, "is_relay");
        // Paid plans only; absent on the keyless answer.
        boolean proxy = bool(root, "is_resproxy") || bool(root, "is_pubproxy")
            || bool(root, "is_dcproxy") || bool(root, "is_mobproxy");

        JsonObject asnObj = obj(root, "asn");
        JsonObject location = obj(root, "location");

        String asnType = asnObj == null ? null : str(asnObj, "type");
        boolean hosting = bool(root, "is_hosting") || "hosting".equalsIgnoreCase(asnType);

        String asnLabel = null;
        String org = null;
        if (asnObj != null) {
            String number = str(asnObj, "asn");
            org = str(asnObj, "name");
            asnLabel = ((number == null ? "" : "AS" + number) + " " + (org == null ? "" : org)).trim();
            if (asnLabel.isEmpty()) asnLabel = null;
        }

        boolean flagged = vpn || tor || relay || proxy || hosting;

        String detail = "vpn=" + vpn + ", relay=" + relay + ", hosting=" + hosting
            + (tor ? ", tor=true" : "") + (proxy ? ", proxy=true" : "")
            + (asnType == null ? "" : ", asn_type=" + asnType);

        return ProviderResult.builder(name())
            .verdict(flagged ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail(detail)
            .tor(tor)
            .hosting(hosting)
            .isp(org)
            .asn(asnLabel)
            .country(location == null ? null : str(location, "country"))
            .build();
    }
}
