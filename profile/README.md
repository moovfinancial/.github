<p align="center">
  <a href="https://moov.io">
    <img src="Moov-Logo.png" alt="Moov" width="80" />
  </a>
</p>

<h3 align="center">Thanks for stopping at <a href="https://moov.io">Moov's</a> home on GitHub</h3>

<p align="center">
  Flexible payment infrastructure to grow your business.
  <br />
  <a href="https://docs.moov.io"><strong>Documentation</strong></a> ·
  <a href="https://docs.moov.io/api"><strong>API Reference</strong></a> ·
  <a href="https://dashboard.moov.io/signup"><strong>Create an account</strong></a>
</p>

---

Accept payments, store funds, send payouts, and spend funds — all through one API, one integration, and one legal agreement.

Moov is a payments processor connected directly to the card networks (Visa, Mastercard, American Express, Discover), The Clearing House, and the Federal Reserve. No middleware, no intermediary processors. That direct connection means real-time data, better availability, and full visibility into every payment event.

Focus on building your product. We handle the rails, the compliance, and the complexity.

---

## 📦 SDKs

Official, actively maintained clients for the Moov API:

| Language | Repository |
|---|---|
| Go | [moov-go](https://github.com/moovfinancial/moov-go) |
| TypeScript / Node | [moov-typescript](https://github.com/moovfinancial/moov-typescript) |
| Python | [moov-python](https://github.com/moovfinancial/moov-python) |
| PHP | [moov-php](https://github.com/moovfinancial/moov-php) |
| Ruby | [moov-ruby](https://github.com/moovfinancial/moov-ruby) |
| .NET | [moov-dotnet](https://github.com/moovfinancial/moov-dotnet) |
| Java | [moov-java](https://github.com/moovfinancial/moov-java) |
| iOS | [moov-ios](https://github.com/moovfinancial/moov-ios) |
| Android | [moov-android](https://github.com/moovfinancial/moov-android) |

All SDKs are generated from the OpenAPI spec and kept in sync with each API release.

---

## 🤖 AI integration

| Tool | What it does |
|---|---|
| [Docs MCP server](https://docs.moov.io/guides/developer-tools/mcp-ai/docs-mcp/) | Search and read Moov docs from any AI coding tool. Install in Claude Code: `claude mcp add --transport http moov-docs https://docs.moov.io/mcp` |
| [Moov SDK MCP server](https://docs.moov.io/guides/developer-tools/mcp-ai/mcp/) | Live API operations via the TypeScript SDK |
| [moov-skills](https://github.com/moovfinancial/moov-skills) | Offline integration patterns for Claude Code, Cursor, Windsurf, Copilot, and other AI coding tools. Download topic-specific skills or a single full ruleset. |
| [llms.txt](https://docs.moov.io/llms.txt) | Machine-readable docs index for LLM tooling |

---

## 🚀 Getting started

1. **Sign up** — [dashboard.moov.io/signup](https://dashboard.moov.io/signup). Test mode is free and requires no approval.
2. **Read the docs** — [docs.moov.io](https://docs.moov.io). Start with the [quick start guide](https://docs.moov.io/guides/quick-start).
3. **Pick your SDK** — grab the client for your language above.
4. **Go to production** — contact us to enable live money movement: [moov.io/contact](https://moov.io/contact).

---

## 🛤️ Payment rails

| Rail | Use case |
|---|---|
| ACH (same-day + standard) | Accept and send funds using bank accounts |
| RTP | Instant credit push via TCH, 24/7 |
| FedNow | Instant credit push via Federal Reserve, 24/7 |
| Visa Direct / Mastercard Send | Pull and Push to debit card |
| Card acceptance | Online card payments, Tap to Pay |
| Card issuing | Virtual cards with spend controls |

---

## 🔧 Open source foundations

The platform is built on open source libraries maintained at [github.com/moov-io](https://github.com/moov-io). If you're working directly with payment file formats or compliance screening in your own stack, these libraries are available independently:

| Library | What it does |
|---|---|
| [moov-io/ach](https://github.com/moov-io/ach) | ACH file reader, writer, and validator — the most widely used Go ACH library |
| [moov-io/iso8583](https://github.com/moov-io/iso8583) | ISO 8583 message parsing and construction |
| [moov-io/watchman](https://github.com/moov-io/watchman) | OFAC, sanctions, and PEP screening with MCP support |
| [moov-io/wire](https://github.com/moov-io/wire) | Fedwire Funds Service file implementation |
| [moov-io/achgateway](https://github.com/moov-io/achgateway) | Production ACH submission and return processing |

These are separate from the commercial API — you can use them without a Moov account. If you need hosted money movement on top of that foundation, we are here to help.

---

## 🔗 Resources

| | |
|---|---|
| [API reference](https://docs.moov.io/api) | Full API documentation |
| [Changelog](https://docs.moov.io/changelog) | Release notes and API versioning |
| [Product roadmap](https://moov.io/platform/roadmap) | What we're building next |
| [Pricing](https://moov.io/pricing) | Transparent, usage-based pricing |
| [Security](https://trust.moov.io) | Security reports and compliance |
| [fintech_devcon](https://fintechdevcon.io) | The developer conference for fintech, hosted by Moov |

---

## 🤝 Contributing

Found a bug in an SDK? Open an issue or PR in the relevant repository. For API issues or account questions, email [help@moov.io](mailto:help@moov.io).
