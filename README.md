# misp-mcp

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-1.x-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An MCP (Model Context Protocol) server for [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform & Threat Intelligence Sharing). Enables LLMs to perform IOC lookups, manage events, discover correlations, and export threat intelligence directly from your MISP instance.

## Features

- **18 MCP Tools** - Full MISP API coverage: events, attributes, correlations, tags, exports, sightings, warninglists
- **3 MCP Resources** - Browse attribute types, instance statistics, and available taxonomies
- **3 MCP Prompts** - Guided workflows for IOC investigation, incident event creation, and threat reporting
- **SSL Flexibility** - Handles self-signed certificates common in MISP deployments
- **Export Formats** - CSV, STIX, Suricata, Snort, text, RPZ, and hash lists
- **Bulk Operations** - Add multiple IOCs to events in a single call
- **Correlation Engine** - Discover cross-event relationships through shared indicators

## Prerequisites

- Node.js 20 or later
- A running MISP instance with API access
- MISP API key (generated from MISP UI: Administration > List Auth Keys)

## Installation

```bash
git clone https://github.com/solomonneas/misp-mcp.git
cd misp-mcp
npm install
npm run build
```

## Configuration

Set the following environment variables:

```bash
export MISP_URL=https://misp.example.com
export MISP_API_KEY=your-api-key-here
export MISP_VERIFY_SSL=true  # Set to 'false' for self-signed certificates
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISP_URL` | Yes | - | MISP instance base URL |
| `MISP_API_KEY` | Yes | - | API authentication key |
| `MISP_VERIFY_SSL` | No | `true` | Set `false` for self-signed certs |

## Usage

### Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "misp": {
      "command": "node",
      "args": ["/path/to/misp-mcp/dist/index.js"],
      "env": {
        "MISP_URL": "https://misp.example.com",
        "MISP_API_KEY": "your-api-key-here",
        "MISP_VERIFY_SSL": "true"
      }
    }
  }
}
```

### Standalone

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key node dist/index.js
```

### Development

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key npm run dev
```

## Tools Reference

### Event Tools

| Tool | Description |
|------|-------------|
| `misp_search_events` | Search events by IOC value, type, tags, date range, organization |
| `misp_get_event` | Get full event details including attributes, objects, galaxies, related events |
| `misp_create_event` | Create a new event with threat level, distribution, and analysis status |
| `misp_update_event` | Update event metadata (info, threat level, analysis, publish state) |
| `misp_publish_event` | Publish an event to trigger alerts to sharing partners |
| `misp_tag_event` | Add or remove tags (TLP, MITRE ATT&CK, custom) from an event |

### Attribute Tools

| Tool | Description |
|------|-------------|
| `misp_search_attributes` | Search IOCs across all events with type, category, and correlation filters |
| `misp_add_attribute` | Add a single IOC to an event |
| `misp_add_attributes_bulk` | Add multiple IOCs to an event in one operation |
| `misp_delete_attribute` | Soft or hard delete an attribute |

### Correlation & Intelligence Tools

| Tool | Description |
|------|-------------|
| `misp_correlate` | Find all events and attributes matching a value, with cross-event correlations |
| `misp_get_related_events` | Discover events related through shared IOCs |
| `misp_describe_types` | Get all available attribute types and category mappings |

### Tag & Taxonomy Tools

| Tool | Description |
|------|-------------|
| `misp_list_tags` | List available tags with usage statistics |
| `misp_search_by_tag` | Find events or attributes by tag |

### Export Tools

| Tool | Description |
|------|-------------|
| `misp_export_iocs` | Export IOCs in CSV, STIX, Suricata, Snort, text, or RPZ format |
| `misp_export_hashes` | Export file hashes (MD5, SHA1, SHA256) for HIDS integration |

### Sighting & Warninglist Tools

| Tool | Description |
|------|-------------|
| `misp_add_sighting` | Report a sighting, false positive, or expiration for an IOC |
| `misp_check_warninglists` | Check if a value appears on known benign/false positive lists |

## Resources

| Resource URI | Description |
|-------------|-------------|
| `misp://types` | All supported attribute types, categories, and their mappings |
| `misp://statistics` | MISP instance statistics |
| `misp://taxonomies` | Available taxonomies (TLP, MITRE ATT&CK, etc.) |

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-ioc` | Deep IOC investigation: search, correlate, check warninglists, summarize threat context |
| `create-incident-event` | Guided event creation from an incident description with IOC ingestion |
| `threat-report` | Generate a threat intelligence report from MISP data |

## Usage Examples

### Search for an IOC

> "Search MISP for the IP address 203.0.113.50"

Uses `misp_search_events` and `misp_search_attributes` to find all events and attributes referencing this IP.

### Investigate a suspicious domain

> "Investigate evil-domain.com in MISP"

Triggers the `investigate-ioc` prompt workflow: searches for the domain, checks correlations, queries warninglists, and provides a structured threat assessment.

### Create an incident event

> "Create a MISP event for a phishing campaign targeting our finance team. The phishing emails came from attacker@evil.com and linked to https://evil-login.com/harvest"

Uses `misp_create_event` followed by `misp_add_attributes_bulk` to create a fully populated event.

### Export Suricata rules

> "Export all IOCs from the last 7 days as Suricata rules"

Uses `misp_export_iocs` with format "suricata" and last "7d".

### Check for false positives

> "Is 8.8.8.8 on any MISP warninglists?"

Uses `misp_check_warninglists` to verify if the value is a known benign indicator.

## Supported Attribute Types

| Type | Category | Example |
|------|----------|---------|
| `ip-src` | Network activity | Source IP address |
| `ip-dst` | Network activity | Destination IP address |
| `domain` | Network activity | Domain name |
| `hostname` | Network activity | Hostname |
| `url` | Network activity | Full URL |
| `email-src` | Payload delivery | Sender email address |
| `md5` | Payload delivery | MD5 file hash |
| `sha1` | Payload delivery | SHA1 file hash |
| `sha256` | Payload delivery | SHA256 file hash |
| `filename` | Payload delivery | File name |

Use `misp_describe_types` for the complete list of supported types and categories.

## Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run lint          # Type check
```

## Project Structure

```
misp-mcp/
  src/
    index.ts              # MCP server entry point
    config.ts             # Environment config + validation
    client.ts             # MISP REST API client
    types.ts              # MISP API type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    tools/
      events.ts           # Event CRUD tools
      attributes.ts       # Attribute management tools
      correlation.ts      # Correlation & intelligence tools
      tags.ts             # Tag and taxonomy tools
      exports.ts          # Export format tools
      sightings.ts        # Sighting tools
      warninglists.ts     # Warninglist checks
  tests/
    client.test.ts        # API client unit tests
    tools.test.ts         # Tool handler unit tests
  package.json
  tsconfig.json
  tsup.config.ts
  vitest.config.ts
  README.md
```

## License

MIT
