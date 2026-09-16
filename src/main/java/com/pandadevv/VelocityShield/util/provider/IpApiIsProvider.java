package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

/**
 * ipapi.is - reports VPN, proxy, Tor, datacenter and known-abuser separately.
 *
 * <p>Needs a free API key (1000 lookups/day). The keyless free tier answers with geo
 * data only - no is_vpn/is_datacenter fields - so without a key this provider abstains
 * rather than voting "clean" on data it does not actually have.
 * https://ipapi.is/
 */
public class IpApiIsProvider extends VPNProvider {

    private final String apiKey;

    public IpApiIsProvider(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
    }

    @Override
    public String name() {
        return "ipapi.is";
    }

    @Override
    public boolean isConfigured() {
        return !apiKey.isEmpty() && !apiKey.startsWith("YOUR_");
    }

    @Override
    public String signupUrl() {
        return "https://ipapi.is/";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        String url = "https://api.ipapi.is/?q=" + ip + (apiKey.isEmpty() ? "" : "&key=" + apiKey);
        JsonObject root = getJson(url, connectTimeout, readTimeout);

        if (root.has("error")) {
            throw new IllegalStateException(str(root, "error"));
        }

        // The free/keyless response has none of the security fields. Voting "clean" off
        // that would be inventing an opinion, so abstain instead.
        if (!root.has("is_datacenter") && !root.has("is_vpn") && !root.has("is_proxy")) {
            throw new IllegalStateException("response has no security fields (free tier without key)");
        }

        boolean vpn = bool(root, "is_vpn");
        boolean proxy = bool(root, "is_proxy");
        boolean tor = bool(root, "is_tor");
        boolean datacenter = bool(root, "is_datacenter");
        boolean abuser = bool(root, "is_abuser");

        boolean flagged = vpn || proxy || tor || datacenter;

        // "asn" and "company" come back as an object on the paid tier and as a plain
        // string on the free one, so accept either.
        JsonObject asnObj = obj(root, "asn");
        JsonObject companyObj = obj(root, "company");
        JsonObject location = obj(root, "location");

        String asnType = asnObj == null ? null : str(asnObj, "type");
        boolean mobile = "mobile".equalsIgnoreCase(asnType);

        String asnLabel;
        if (asnObj != null) {
            String number = str(asnObj, "asn");
            String org = str(asnObj, "org");
            asnLabel = ((number == null ? "" : "AS" + number) + " " + (org == null ? "" : org)).trim();
            if (asnLabel.isEmpty()) asnLabel = null;
        } else {
            asnLabel = str(root, "asn");
        }

        String companyName = companyObj != null ? str(companyObj, "name") : str(root, "company");
        String country = location != null ? str(location, "country_code") : str(root, "country");

        String detail = "vpn=" + vpn + ", proxy=" + proxy + ", datacenter=" + datacenter
            + (tor ? ", tor=true" : "") + (abuser ? ", abuser=true" : "")
            + (asnType == null ? "" : ", asn_type=" + asnType);

        return ProviderResult.builder(name())
            .verdict(flagged ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail(detail)
            .tor(tor)
            .hosting(datacenter)
            .mobile(mobile)
            .isp(companyName)
            .asn(asnLabel)
            .country(country)
            .build();
    }
}
