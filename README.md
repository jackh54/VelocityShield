# VelocityShield 🛡️

A powerful VPN detection plugin for Velocity proxy servers that helps protect your network from unwanted VPN connections.

[![License](https://img.shields.io/github/license/jackh54/velocityshield)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://www.oracle.com/java/)
[![Velocity](https://img.shields.io/badge/Velocity-3.4.0-blue.svg)](https://www.velocitypowered.com/)

## Features ✨

- **Dual VPN Detection**: Uses both proxycheck.io and ip-api.com for reliable VPN detection
- **Smart Fallback System**: Automatically switches between services if one fails
- **Efficient Caching**: Reduces API requests with configurable cache duration
- **Whitelist System**: Easily manage trusted IPs
- **Detailed Logging**: Track VPN detection events with timestamps
- **Modern Text Formatting**: Beautiful messages using Adventure's text components
- **Permission System**: Control access to commands and bypasses
- **Configurable**: Highly customizable through config.yml

## Installation 📥

1. Download the latest release from the [Releases](https://github.com/jackh54/velocityshield/releases) page
2. Place the JAR file in your Velocity server's `plugins` directory
3. Start or restart your Velocity server
4. Configure the plugin in `plugins/velocityshield/config.yml`

## Configuration ⚙️

```yaml
# API Configuration
proxycheck-api-key: "YOUR_PROXYCHECK_API_KEY"

# VPN Detection Settings
use-proxycheck-as-primary: true
enable-fallback-service: true
allow-join-on-api-failure: true

# Cache Settings
enable-cache: true
cache-duration: 10
cache-time-unit: "SECONDS"  # Options: SECONDS, MINUTES, HOURS, DAYS

# Debug Settings
enable-debug: false
```

## Commands 🎮

| Command | Description | Permission |
|---------|-------------|------------|
| `/velocityshield` or `/vshield` | Reload the plugin configuration | `velocityshield.reload` |
| `/vshieldwhitelist` or `/vshieldwl` | Manage whitelisted IPs | `velocityshield.whitelist` |

### Whitelist Commands
- `/vshieldwhitelist add <ip>` - Add an IP to the whitelist
- `/vshieldwhitelist remove <ip>` - Remove an IP from the whitelist

## Permissions 🔑

| Permission | Description |
|------------|-------------|
| `velocityshield.reload` | Allows reloading the plugin configuration |
| `velocityshield.whitelist` | Allows managing the IP whitelist |
| `velocityshield.bypass` | Allows bypassing VPN detection |

## API Integration 🤝

VelocityShield uses two VPN detection services:

1. **proxycheck.io** (Primary)
   - Requires API key
   - More accurate detection
   - Higher rate limits with API key

2. **ip-api.com** (Fallback)
   - Free to use
   - No API key required
   - Lower rate limits

## Performance Optimization 🚀

- **Caching**: Reduces API requests by caching results
- **Rate Limiting**: Prevents API service overload
- **Async Processing**: Non-blocking VPN checks
- **Efficient Cleanup**: Automatic cache maintenance

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
- Join our [Discord server](https://discord.gg/your-discord) for community support
- Check the [Wiki](https://github.com/jackh54/velocityshield/wiki) for detailed documentation

## Credits 🙏

- [Velocity](https://www.velocitypowered.com/) - The proxy server
- [proxycheck.io](https://proxycheck.io/) - Primary VPN detection service
- [ip-api.com](https://ip-api.com/) - Fallback VPN detection service
- [Adventure](https://docs.advntr.dev/) - Text formatting library

---

Made with ❤️ by [PandaDevv](https://github.com/jackh54) 