package com.pandadevv.VelocityShield.util.provider;

import com.google.gson.JsonObject;

/**
 * ip-api.com - no key needed, 45 requests/minute from one address.
 *
 * <p>This is the provider that tells us a connection is a mobile carrier, which is the
 * single most useful signal for cutting false positives: phone and console players on
 * carrier-grade NAT get flagged as proxies by reputation services all the time.
 *
 * <p>The free endpoint is HTTP-only; HTTPS needs a paid plan.
 */
public class IpApiProvider extends VPNProvider {

    @Override
    public String name() {
        return "ip-api";
    }

    @Override
    protected ProviderResult doCheck(String ip, int connectTimeout, int readTimeout) throws Exception {
        String url = "http://ip-api.com/json/" + ip
            + "?fields=status,message,proxy,hosting,mobile,isp,org,as,countryCode";

        JsonObject root = getJson(url, connectTimeout, readTimeout);

        String status = str(root, "status");
        if (!"success".equalsIgnoreCase(status)) {
            throw new IllegalStateException(
                "status=" + status + (str(root, "message") == null ? "" : " " + str(root, "message")));
        }

        boolean proxy = bool(root, "proxy");
        boolean hosting = bool(root, "hosting");
        boolean mobile = bool(root, "mobile");

        // Datacenter ranges are not where real players live, so treat hosting as a flag too.
        boolean flagged = proxy || hosting;

        String detail = "proxy=" + proxy + ", hosting=" + hosting + ", mobile=" + mobile;

        return ProviderResult.builder(name())
            .verdict(flagged ? ProviderResult.Verdict.VPN : ProviderResult.Verdict.CLEAN)
            .detail(detail)
            .hosting(hosting)
            .mobile(mobile)
            .isp(str(root, "isp"))
            .asn(str(root, "as"))
            .country(str(root, "countryCode"))
            .build();
    }
}
