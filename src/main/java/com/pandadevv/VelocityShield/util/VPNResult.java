package com.pandadevv.VelocityShield.util;

import com.pandadevv.VelocityShield.util.provider.ProviderResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The combined answer from every provider that was asked about one address,
 * plus the reason the plugin decided to allow or block.
 */
public class VPNResult {

    private final String ip;
    private final boolean blocked;
    private final double score;
    private final int vpnVotes;
    private final int answeredCount;
    private final String reason;
    private final List<ProviderResult> providers;
    private final long checkedAt;
    private final boolean fromCache;

    public VPNResult(String ip, boolean blocked, double score, int vpnVotes, int answeredCount,
                     String reason, List<ProviderResult> providers, long checkedAt, boolean fromCache) {
        this.ip = ip;
        this.blocked = blocked;
        this.score = score;
        this.vpnVotes = vpnVotes;
        this.answeredCount = answeredCount;
        this.reason = reason;
        this.providers = providers == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(providers));
        this.checkedAt = checkedAt;
        this.fromCache = fromCache;
    }

    public VPNResult asCached() {
        return new VPNResult(ip, blocked, score, vpnVotes, answeredCount, reason, providers, checkedAt, true);
    }

    public String getIp() { return ip; }
    public boolean isBlocked() { return blocked; }
    public double getScore() { return score; }
    public int getVpnVotes() { return vpnVotes; }
    public int getAnsweredCount() { return answeredCount; }
    public String getReason() { return reason; }
    public List<ProviderResult> getProviders() { return providers; }
    public long getCheckedAt() { return checkedAt; }
    public boolean isFromCache() { return fromCache; }

    /** First non-null ISP any provider reported. */
    public String getIsp() {
        return firstNonNull(ProviderResult::getIsp);
    }

    public String getAsn() {
        return firstNonNull(ProviderResult::getAsn);
    }

    public String getCountry() {
        return firstNonNull(ProviderResult::getCountry);
    }

    public boolean isMobile() {
        return providers.stream().anyMatch(ProviderResult::isMobile);
    }

    public boolean isHosting() {
        return providers.stream().anyMatch(ProviderResult::isHosting);
    }

    public boolean isTor() {
        return providers.stream().anyMatch(ProviderResult::isTor);
    }

    /** Human-readable connection type for staff, e.g. "Mobile carrier". */
    public String getConnectionType() {
        if (isTor()) return "Tor";
        if (isHosting()) return "Datacenter / hosting";
        if (isMobile()) return "Mobile carrier";
        return "Residential";
    }

    /** e.g. "2/4 flagged" */
    public String getVoteSummary() {
        return vpnVotes + "/" + answeredCount + " flagged";
    }

    private String firstNonNull(java.util.function.Function<ProviderResult, String> getter) {
        for (ProviderResult result : providers) {
            String value = getter.apply(result);
            if (value != null && !value.isBlank()) return value;
        }
        return null;
    }
}
