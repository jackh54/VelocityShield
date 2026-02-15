package com.pandadevv.VelocityShield.util;

import org.slf4j.Logger;

public class LogHelper {
    
    public static void logVpnCheck(Logger logger, String username, String ip, boolean isVpn, boolean isDebug) {
        if (isDebug) {
            if (isVpn) {
                logger.warn("VPN detected - Player: {}, IP: {}", username, ip);
            } else {
                logger.info("Clean connection - Player: {}, IP: {}", username, ip);
            }
        }
    }

    public static void logApiError(Logger logger, String service, String ip, Exception e, boolean isDebug) {
        if (isDebug) {
            logger.error("API request failed - Service: {}, IP: {}, Error: {}", 
                service, ip, e.getMessage());
        }
    }

    public static void logCacheHit(Logger logger, String ip, boolean isVpn, boolean isDebug) {
        if (isDebug) {
            logger.debug("Cache hit - IP: {}, VPN: {}", ip, isVpn);
        }
    }

    public static void logCacheMiss(Logger logger, String ip, boolean isDebug) {
        if (isDebug) {
            logger.debug("Cache miss - IP: {}", ip);
        }
    }

    public static void logWhitelistBypass(Logger logger, String username, String ip, boolean isDebug) {
        if (isDebug) {
            logger.info("Whitelisted IP bypass - Player: {}, IP: {}", username, ip);
        }
    }

    public static void logPermissionBypass(Logger logger, String username, boolean isDebug) {
        if (isDebug) {
            logger.info("Permission bypass - Player: {}", username);
        }
    }

    public static void logConfigError(Logger logger, String message, Exception e) {
        logger.error("Configuration error: {} - {}", message, e.getMessage());
    }

    public static void logRateLimitWait(Logger logger, String ip, boolean isDebug) {
        if (isDebug) {
            logger.debug("Rate limit reached, waiting before checking IP: {}", ip);
        }
    }
}
