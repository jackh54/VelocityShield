# VelocityShield

<div align="center">

![VelocityShield Logo](assets/logo.png)

*Protect your Velocity proxy server from VPN users with advanced detection and caching*

[![License](https://img.shields.io/github/license/pandadevv/velocityshield)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://adoptium.net/)
[![Velocity](https://img.shields.io/badge/Velocity-3.0.0%2B-blue)](https://velocitypowered.com/)

</div>

## 🚀 Features

- **Dual VPN Detection Services**: Utilizes both ProxyCheck.io and IP-API for reliable VPN detection
- **Smart Caching System**: Implements efficient IP caching to reduce API calls and improve performance
- **Rate Limiting**: Built-in rate limiting to prevent API abuse
- **Fallback System**: Configurable fallback service if the primary check fails
- **Async Processing**: Non-blocking VPN checks using CompletableFuture
- **Configurable Behavior**: Extensive configuration options to suit your needs

## 📋 Requirements

- Java 17 or higher
- Velocity 3.0.0 or higher
- (Optional but highly recommended) ProxyCheck.io API key for enhanced detection

## 🔧 Installation

1. Download the latest version of VelocityShield from the releases page
2. Place the JAR file in your Velocity server's `plugins` folder
3. Start/restart your Velocity server
4. Configure the plugin in `plugins/VelocityShield/config.yml`

## ⚙️ Configuration

```yaml
# VelocityShield Configuration
# Utilizes proxycheck.io and ip-api.com to check for VPNs
# https://proxycheck.io/

# API Configuration
proxycheck-api-key: "YOUR_PROXYCHECK_API_KEY"

# Kick Message
kick-message: |
  §c§lVPN Detected!
  
  §fPlease join without a VPN.
  §fIf this is a false positive, please open a ticket.

# Service Configuration
proxycheck-io-as-main-check: true    # Use proxycheck.io as the main check (recommended)
fallback-to-non-main: true          # Fallback to either ip-api.com or proxycheck.io if the main check fails
allow-join-on-failure: true         # Allow players to join if VPN check fails (e.g., API limit reached)

# Cache Configuration
enable-cache: true                  # Enable caching to reduce API requests (recommended)
cache-duration: 24                  # How long to cache results
cache-time-unit: "HOURS"           # Options: SECONDS, MINUTES, HOURS, DAYS

# Debug Configuration
debug: false                        # Enable debug mode for detailed logging

config-version: 1.1                 # Configuration version (do not modify)
```

### Configuration Details

- **proxycheck-api-key**: Your ProxyCheck.io API key. Required for using ProxyCheck.io service.
- **kick-message**: Custom message shown to players when they are kicked for using a VPN. Supports color codes (§).

- **proxycheck-io-as-main-check**: 
  - `true`: Uses ProxyCheck.io as primary service (recommended)
  - `false`: Uses IP-API as primary service

- **fallback-to-non-main**: 
  - `true`: If the main check fails, tries the other service
  - `false`: Only uses the main service

- **allow-join-on-failure**: 
  - `true`: Players can join if both services fail (e.g., API limit reached)
  - `false`: Players are blocked if both services fail

- **enable-cache**: Enables/disables the caching system to reduce API calls
- **cache-duration**: How long to cache IP check results
- **cache-time-unit**: Time unit for cache duration (SECONDS, MINUTES, HOURS, DAYS)

- **debug**: Enables detailed logging for troubleshooting
- **config-version**: Internal version number (do not modify)

## 🔑 API Keys

For optimal VPN detection, we recommend using ProxyCheck.io with an API key. You can get one at [ProxyCheck.io](https://proxycheck.io/).

## 🛡️ How It Works

VelocityShield employs a sophisticated dual-layer VPN detection system:

1. **Primary Check**: Uses either ProxyCheck.io or IP-API (configurable)
2. **Fallback Check**: If the primary check fails, uses the alternate service
3. **Caching**: Stores results to minimize API calls and improve response times
4. **Rate Limiting**: Ensures API limits are respected (10 requests per second)

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/CoolThing`)
3. Commit your changes (`git commit -m 'Add some Cool things'`)
4. Push to the branch (`git push origin feature/CoolThing`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Support

If you find VelocityShield useful, please consider giving it a star on GitHub!

## 📞 Contact

For support, feature requests, or bug reports, please [open an issue](../../issues) on GitHub. (or dm me on discord)

---

<div align="center">
Made with ❤️ by pandadevv
</div> 