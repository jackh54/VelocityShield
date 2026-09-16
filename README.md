# VelocityShield 🛡️

A powerful VPN detection plugin for Velocity proxy servers that helps protect your network from unwanted VPN connections.

[![License](https://img.shields.io/github/license/jackh54/velocityshield)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://www.oracle.com/java/)
[![Velocity](https://img.shields.io/badge/Velocity-3.4.0-blue.svg)](https://www.velocitypowered.com/)

## Features ✨

- **Dual VPN Detection**: Uses both proxycheck.io and ip-api.com for reliable VPN detection
- **Smart Fallback System**: Automatically switches between services if one fails
- **Efficient Caching**: Reduces API requests with configurable cache duration (default: 24 hours)
- **Whitelist System**: Easily manage trusted IPs via commands or file
- **Detailed Logging**: Track VPN detection events with timestamps
- **Modern Text Formatting**: Beautiful messages using Adventure's MiniMessage format
- **Permission System**: Control access to commands and bypasses
- **Statistics Dashboard**: View real-time plugin statistics and VPN blocks
- **IP Lookup Tool**: Manually check if any IP is a VPN/proxy
- **Tab Completion**: Full tab completion support for all commands
- **Configurable Timeouts**: Adjust API connection and read timeouts
- **Rate Limiting**: Built-in protection against API overload
- **Highly Configurable**: Customize every aspect through config.yml

## Installation 📥

1. Download the latest release from the [Releases](https://github.com/jackh54/velocityshield/releases) page
2. Place the JAR file in your Velocity server's `plugins` directory
3. Start or restart your Velocity server
4. Configure the plugin in `plugins/velocityshield/config.yml`
5. (Optional) Get a free API key from [proxycheck.io](https://proxycheck.io/) for better accuracy

## Configuration ⚙️

```yaml
# Every enabled provider is asked at the same time and the decision is made from
# the answers as a group. ip-api needs no key; proxycheck works without one at
# 100/day. The rest abstain unless you give them a free key.
providers:
  proxycheck:
    enabled: true
    weight: 1.0
    api-key: "YOUR_PROXYCHECK_API_KEY"
  ip-api:
    enabled: true
    weight: 1.0
  ipapi.is:
    enabled: false
    api-key: ""
  vpnapi:
    enabled: false
    api-key: ""
  iphub:
    enabled: false
    api-key: ""

consensus:
  min-vpn-votes: 2            # how many providers must agree before a kick
  min-score: 0.5              # share of answering providers (by weight)
  trust-mobile-networks: true # mobile carriers need a bigger majority
  mobile-min-vpn-votes: 3
  always-block-tor: true

allow-join-on-api-failure: true

# Optionally POST each result to your own endpoint so a support bot can show a
# player which services flagged them.
reporting:
  enabled: false
  url: ""
  api-key: ""
  api-key-header: "x-api-key"
  server-name: "proxy"
  mode: "flagged"             # blocked | flagged | all

# Cache Settings
enable-cache: true
cache-duration: 24
cache-time-unit: "HOURS"  # Options: SECONDS, MINUTES, HOURS, DAYS

# Debug Settings
enable-debug: false
```

## Commands 🎮

### Main Command
`/velocityshield` or `/vshield` or `/vs` - Main command with subcommands

**Subcommands:**
- `/vshield reload` - Reload the plugin configuration
- `/vshield stats` - View plugin statistics and uptime
- `/vshield lookup <ip>` - Check if an IP is a VPN/proxy
- `/vshield cache clear` - Clear the IP cache
- `/vshield whitelist <add|remove|list> [ip]` - Manage IP whitelist
- `/vshield help` - Show command help

### Legacy Commands (for backwards compatibility)
- `/vshieldwhitelist <add|remove> <ip>` - Manage whitelisted IPs

## Permissions 🔑

| Permission | Description |
|------------|-------------|
| `velocityshield.admin` | Access to all admin commands (reload, stats, lookup, cache) |
| `velocityshield.reload` | Allows reloading the plugin configuration |
| `velocityshield.whitelist` | Allows managing the IP whitelist |
| `velocityshield.bypass` | Allows bypassing VPN detection |

## API Integration 🤝

VelocityShield can query up to five reputation services and decides from their answers
as a group, rather than trusting whichever one replies first.

| Provider | Key required | Free limit | Notes |
|---|---|---|---|
| [proxycheck.io](https://proxycheck.io/) | Optional | 100/day, 1000/day with key | Proxy/VPN type and risk score |
| [ip-api.com](http://ip-api.com/) | No | 45/minute | The only one that reports **mobile carrier**, which is what stops phone and console players being kicked |
| [ipapi.is](https://ipapi.is/) | Yes | 1000/day | VPN, proxy, Tor, datacenter, abuser |
| [vpnapi.io](https://vpnapi.io/) | Yes | 1000/day | VPN, proxy, Tor, relay |
| [iphub.info](https://iphub.info/) | Yes | 1000/day | block=1 only; block=2 is ignored as too noisy |

**A provider that errors, times out or has no key abstains.** It is never counted as a
vote in either direction, so a service having a bad day cannot get a player kicked and
cannot clear one either.

### How the decision is made

1. Every enabled provider is queried in parallel.
2. A player is blocked only when at least `min-vpn-votes` providers flag the address
   **and** the weighted share of flags reaches `min-score`.
3. If the connection looks like a **mobile carrier**, `mobile-min-vpn-votes` is required
   instead. Carriers put thousands of real players behind a handful of addresses and are
   mislabelled constantly.
4. **Tor** exit nodes are always blocked.
5. If nobody answered, `allow-join-on-api-failure` decides.

`/vshield lookup <ip>` prints the full per-provider breakdown, so you can see exactly why
somebody was let in or kept out.

## Performance Optimization 🚀

- **Smart Caching**: 24-hour default cache reduces API calls by 90%+
- **Rate Limiting**: Automatic request throttling prevents API service overload
- **Async Processing**: Non-blocking VPN checks don't impact player join times
- **Efficient Cleanup**: Automatic cache maintenance and memory management
- **Thread Pool**: Dedicated executor service for concurrent checks

## What's New in v1.2.0 🎉

- ✅ **Multi-provider consensus** - up to five services queried in parallel; a player is
  only blocked when enough of them agree, which removes the single-service false positives
- ✅ **Mobile carrier protection** - carrier connections need a larger majority before a kick
- ✅ **Providers that fail now abstain** instead of being treated as a "clean" answer
- ✅ **Tor always blocked** regardless of vote count
- ✅ **Per-provider weights** so you can trust a paid service more than a free one
- ✅ **`/vshield lookup` shows the full breakdown** - which service said what, and why
- ✅ **Optional reporting webhook** - POST results to your own API so a support bot can
  show a player exactly which services flagged them
- ✅ **Non-blocking logins** - checks now run off the event thread via `EventTask`
- ✅ **Richer detection log** - the vote split and reason are written alongside each hit

## What's New in v1.1.0 🎉

- ✅ **Fixed bStats wave pattern** - Metrics now report correctly
- ✅ **New unified command system** - `/vshield` with tab completion
- ✅ **Statistics command** - View real-time plugin stats
- ✅ **IP lookup tool** - Manually check any IP for VPN/proxy
- ✅ **Cache management** - Clear cache on demand
- ✅ **Improved cache duration** - Default increased to 24 hours
- ✅ **Configurable timeouts** - Adjust API timeouts to your needs
- ✅ **Better error handling** - Improved logging and error messages
- ✅ **Updated dependencies** - Latest library versions for better performance
- ✅ **Memory leak fixes** - Proper shutdown of all resources

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support 💬

- Create an issue for bug reports or feature requests
- Join our [Discord server](https://discord.gg/CzJvE4G5cU) for community support
- Check the [Wiki](https://github.com/jackh54/velocityshield/wiki) for detailed documentation

## Credits 🙏

- [Velocity](https://www.velocitypowered.com/) - The proxy server
- [proxycheck.io](https://proxycheck.io/) - Primary VPN detection service
- [ip-api.com](https://ip-api.com/) - Fallback VPN detection service
- [Adventure](https://docs.advntr.dev/) - Text formatting library
- [bStats](https://bstats.org/) - Plugin metrics

---

Made with ❤️ by [PandaDevv](https://github.com/jackh54) 
