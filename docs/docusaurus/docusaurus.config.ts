import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: "Sig Documentation",
  tagline: "Docs for the Sig project",
  favicon: "img/favicon.ico",

  // Set the production url of your site here
  url: "https://sig.fun",
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/",

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "Syndica", // Usually your GitHub org/user name.
  projectName: "sig.fun", // Usually your repo name.

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  markdown: {
    mermaid: true,
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          routeBasePath: "/",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  staticDirectories: ["public", "static"],

  plugins: ["@docusaurus/theme-live-codeblock", "@docusaurus/theme-mermaid"],

  themeConfig: {
    // Replace with your project's social card
    image: "img/sig-logo.svg",
    navbar: {
      title: "Docs",
      logo: {
        alt: "Sig Logo",
        src: "img/sig-logo.svg",
      },
      items: [
        {
          href: "https://github.com/Syndica/sig",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    docs: {
      sidebar: {
        autoCollapseCategories: true,
        hideable: true,
      },
    },
    footer: {
      style: "dark",
      links: [],
      copyright: `Copyright © ${new Date().getFullYear()} Syndica.`,
    },
    prism: {
      theme: prismThemes.palenight,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "json", "http", "zig"],
    },
    liveCodeBlock: {
      /**
       * The position of the live playground, above or under the editor
       * Possible values: "top" | "bottom"
       */
      playgroundPosition: "bottom",
    },
    sitemap: {
      changefreq: "weekly",
      priority: 0.5,
      ignorePatterns: ["/tags/**"],
      filename: "sitemap.xml",
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
