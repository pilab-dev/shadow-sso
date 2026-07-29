/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'Shadow SSO',
  tagline: 'A Robust and Flexible OAuth 2.0 and OpenID Connect Implementation for Go',
  url: 'https://docs.shadow-sso.dev',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  organizationName: 'pilab-dev',
  projectName: 'shadow-sso',
  themeConfig: {
    navbar: {
      title: 'Shadow SSO',
      logo: {
        alt: 'Shadow SSO Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'doc',
          docId: 'index',
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
              to: '/docs/getting-started/installation',
            },
            {
              label: 'Configuration',
              to: '/docs/configuration/reference',
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
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Progressive Innovation LAB.`,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/pilab-dev/shadow-sso/tree/main/docs-docusaurus/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
};
