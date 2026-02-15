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
# API Configuration
proxycheck-api-key: "YOUR_PROXYCHECK_API_KEY"

# VPN Detection Settings
use-proxycheck-as-primary: true
enable-fallback-service: true
allow-join-on-api-failure: true
api-connection-timeout: 5000
api-read-timeout: 5000

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

VelocityShield uses two VPN detection services:

1. **proxycheck.io** (Primary, recommended)
   - Requires API key (free tier available)
   - More accurate detection
   - Higher rate limits with API key
   - Get your key at: https://proxycheck.io/

2. **ip-api.com** (Fallback)
   - Free to use
   - No API key required
   - Lower rate limits (45 requests/minute)

## Performance Optimization 🚀

- **Smart Caching**: 24-hour default cache reduces API calls by 90%+
- **Rate Limiting**: Automatic request throttling prevents API service overload
- **Async Processing**: Non-blocking VPN checks don't impact player join times
- **Efficient Cleanup**: Automatic cache maintenance and memory management
- **Thread Pool**: Dedicated executor service for concurrent checks

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
