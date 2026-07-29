# Shadow SSO Documentation (Docusaurus)

This directory contains the Docusaurus-based documentation for Shadow SSO.

## Structure

```
docs-docusaurus/
├── index.md                    # Welcome page
├── getting-started/            # Installation and quickstart
│   ├── installation.md
│   ├── quickstart.md
│   └── configuration.md
├── deployment/                 # Deployment guides
│   ├── docker.md
│   ├── docker-compose.md
│   └── kubernetes.md
├── configuration/              # Configuration reference
│   └── reference.md
├── operations/                 # Operations and maintenance
│   ├── maintenance.md
│   ├── monitoring.md
│   └── security.md
├── features/                   # Feature documentation
│   ├── federation.md
│   ├── ldap.md
│   ├── service-accounts.md
│   └── mfa.md
├── api-reference/              # API documentation
│   ├── grpc.md
│   ├── graphql.md
│   └── cli.md
├── troubleshooting/            # Troubleshooting guides
│   └── common-issues.md
├── docusaurus.config.js        # Docusaurus configuration
├── sidebars.js                 # Sidebar configuration
└── package.json                # Dependencies
```

## Local Development

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
cd docs-docusaurus
npm install
```

### Development Server

```bash
npm start
```

This starts a local development server at `http://localhost:3000`. Most changes are reflected live without having to restart the server.

### Build

```bash
npm run build
```

This generates static content into the `build` directory and can be served using any static content hosting service.

### Deploy

#### GitHub Pages

```bash
GIT_USER=<your-github-username> USE_SSH=true npm run deploy
```

#### Other Hosting

After running `npm run build`, upload the contents of the `build` directory to your hosting provider.

## Documentation Structure

### Getting Started

- **Installation**: How to install Shadow SSO (Go install, build from source, Docker, Helm)
- **Quick Start**: 5-minute guide to get Shadow SSO running
- **Configuration Basics**: Essential configuration options

### Deployment

- **Docker**: Single container deployment
- **Docker Compose**: Multi-container orchestration
- **Kubernetes**: Production-grade deployment with Helm

### Configuration

- **Reference**: Complete configuration reference with all environment variables

### Operations

- **Maintenance**: Backup, restore, key rotation, upgrades
- **Monitoring**: Prometheus metrics, OpenTelemetry tracing, health checks
- **Security**: Security best practices, compliance, incident response

### Features

- **Federation**: OAuth2/OIDC federation with Google, GitHub, Apple, etc.
- **LDAP**: LDAP/Active Directory integration
- **Service Accounts**: Machine identities and JWT authentication
- **MFA**: Multi-factor authentication (TOTP, Email, Push, SMS)

### API Reference

- **gRPC API**: High-performance service API
- **GraphQL API**: Administrative API
- **CLI Reference**: ssoctl command-line tool

### Troubleshooting

- **Common Issues**: Solutions to frequently encountered problems

## Writing Documentation

### Frontmatter

Every markdown file should have frontmatter:

```yaml
---
id: unique-id
title: Page Title
sidebar_label: Sidebar Label
---
```

### Admonitions

Use Docusaurus admonitions for callouts:

```markdown
:::note
This is a note
:::

:::tip
This is a tip
:::

:::info
This is an info box
:::

:::caution
This is a caution
:::

:::warning
This is a warning
:::

:::danger
This is a danger warning
:::
```

### Code Blocks

Use fenced code blocks with language tags:

````markdown
```bash
docker run -d --name ssso ghcr.io/pilab-dev/shadow-sso-backend:v1
```

```yaml
services:
  ssso:
    image: ghcr.io/pilab-dev/shadow-sso-backend:v1
```

```go
func main() {
    fmt.Println("Hello, Shadow SSO!")
}
```
````

### Links

Use relative links for internal documentation:

```markdown
[Installation Guide](/getting-started/installation)
```

Use absolute links for external resources:

```markdown
[GitHub Repository](https://github.com/pilab-dev/shadow-sso)
```

### Images

Place images in `static/img/` and reference them:

```markdown
![Architecture Diagram](/img/architecture.png)
```

## Customization

### Theme

Edit `src/css/custom.css` to customize the theme.

### Logo and Favicon

Place logo files in `static/img/`:
- `logo.svg` - Main logo
- `favicon.ico` - Favicon
- `shadow-sso-social-card.jpg` - Social media card

### Search

Configure Algolia search in `docusaurus.config.js`:

```javascript
algolia: {
  appId: 'YOUR_APP_ID',
  apiKey: 'YOUR_API_KEY',
  indexName: 'shadow-sso',
}
```

## Contributing

1. Make your changes to the markdown files
2. Test locally with `npm start`
3. Build with `npm run build` to check for errors
4. Submit a pull request

## License

This documentation is part of Shadow SSO and is licensed under the MIT License.
