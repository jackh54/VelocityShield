package com.pandadevv.VelocityShield.util.provider;

/**
 * One provider's answer about one IP.
 *
 * <p>A provider that could not be reached returns {@link Verdict#ERROR}. Errors never
 * count as a vote in either direction - a dead API must not get somebody kicked, and it
 * must not clear somebody either.
 */
public class ProviderResult {

    public enum Verdict {
        /** The provider says this address is a VPN, proxy, Tor node or hosting range. */
        VPN,
        /** The provider says this address is a normal residential/mobile connection. */
        CLEAN,
        /** The provider did not answer, timed out, or returned something unparseable. */
        ERROR,
        /** The provider is turned off in the config, or has no API key. */
        DISABLED
    }

    private final String provider;
    private final Verdict verdict;
    private final double weight;
    private final String detail;
    private final long latencyMs;

    // Signals worth keeping separate from the yes/no, because they change the decision.
    private final boolean tor;
    private final boolean hosting;
    private final boolean mobile;

    private final String isp;
    private final String asn;
    private final String country;

    private ProviderResult(Builder builder) {
        this.provider = builder.provider;
        this.verdict = builder.verdict;
        this.weight = builder.weight;
        this.detail = builder.detail;
        this.latencyMs = builder.latencyMs;
        this.tor = builder.tor;
        this.hosting = builder.hosting;
        this.mobile = builder.mobile;
        this.isp = builder.isp;
        this.asn = builder.asn;
        this.country = builder.country;
    }

    public static Builder builder(String provider) {
        return new Builder(provider);
    }

    public static ProviderResult error(String provider, String reason, long latencyMs) {
        return builder(provider).verdict(Verdict.ERROR).detail(reason).latencyMs(latencyMs).build();
    }

    public static ProviderResult disabled(String provider, String reason) {
        return builder(provider).verdict(Verdict.DISABLED).detail(reason).build();
    }

    public String getProvider() { return provider; }
    public Verdict getVerdict() { return verdict; }
    public double getWeight() { return weight; }
    public String getDetail() { return detail; }
    public long getLatencyMs() { return latencyMs; }
    public boolean isTor() { return tor; }
    public boolean isHosting() { return hosting; }
    public boolean isMobile() { return mobile; }
    public String getIsp() { return isp; }
    public String getAsn() { return asn; }
    public String getCountry() { return country; }

    /** True when the provider actually answered, so its opinion can be counted. */
    public boolean answered() {
        return verdict == Verdict.VPN || verdict == Verdict.CLEAN;
    }

    public boolean flaggedVpn() {
        return verdict == Verdict.VPN;
    }

    public static class Builder {
        private final String provider;
        private Verdict verdict = Verdict.ERROR;
        private double weight = 1.0;
        private String detail = "";
        private long latencyMs = 0;
        private boolean tor;
        private boolean hosting;
        private boolean mobile;
        private String isp;
        private String asn;
        private String country;

        Builder(String provider) { this.provider = provider; }

        public Builder verdict(Verdict verdict) { this.verdict = verdict; return this; }
        public Builder weight(double weight) { this.weight = weight; return this; }
        public Builder detail(String detail) { this.detail = detail == null ? "" : detail; return this; }
        public Builder latencyMs(long latencyMs) { this.latencyMs = latencyMs; return this; }
        public Builder tor(boolean tor) { this.tor = tor; return this; }
        public Builder hosting(boolean hosting) { this.hosting = hosting; return this; }
        public Builder mobile(boolean mobile) { this.mobile = mobile; return this; }
        public Builder isp(String isp) { this.isp = isp; return this; }
        public Builder asn(String asn) { this.asn = asn; return this; }
        public Builder country(String country) { this.country = country; return this; }

        public ProviderResult build() { return new ProviderResult(this); }
    }
}
