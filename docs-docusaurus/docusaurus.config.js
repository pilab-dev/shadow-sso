// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const {themes as prismThemes} = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Shadow SSO',
  tagline: 'A Robust and Flexible OAuth 2.0 and OpenID Connect Implementation for Go',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://docs.shadow-sso.dev',
  // Set the /<baseUrl>/ pathname under which your site is served
  baseUrl: '/',

  // GitHub pages deployment config.
  organizationName: 'pilab-dev',
  projectName: 'shadow-sso',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang.
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/pilab-dev/shadow-sso/tree/main/docs-docusaurus/',
          showLastUpdateTime: true,
          showLastUpdateAuthor: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/shadow-sso-social-card.jpg',
      navbar: {
        title: 'Shadow SSO',
        logo: {
          alt: 'Shadow SSO Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docs',
            position: 'left',
            label: 'Documentation',
          },
          {
            href: 'https://github.com/pilab-dev/shadow-sso',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Getting Started',
                to: '/getting-started/installation',
              },
              {
                label: 'Configuration',
                to: '/configuration/reference',
              },
              {
                label: 'Deployment',
                to: '/deployment/docker',
              },
            ],
          },
          {
            title: 'Features',
            items: [
              {
                label: 'Federation',
                to: '/features/federation',
              },
              {
                label: 'LDAP/AD',
                to: '/features/ldap',
              },
              {
                label: 'Service Accounts',
                to: '/features/service-accounts',
              },
              {
                label: 'MFA',
                to: '/features/mfa',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/pilab-dev/shadow-sso',
              },
              {
                label: 'API Reference',
                to: '/api-reference/grpc',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Progressive Innovation LAB. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'json', 'yaml', 'go', 'protobuf'],
      },
      algolia: {
        // Algolia search - configure with your own credentials
        // appId: 'YOUR_APP_ID',
        // apiKey: 'YOUR_API_KEY',
        // indexName: 'shadow-sso',
        // contextualSearch: true,
      },
      announcementBar: {
        id: 'support_us',
        content:
          'If you like Shadow SSO, give us a ⭐ on <a target="_blank" rel="noopener noreferrer" href="https://github.com/pilab-dev/shadow-sso">GitHub</a>!',
        backgroundColor: '#fafbfc',
        textColor: '#091E42',
        isCloseable: true,
      },
    }),
};

module.exports = config;
