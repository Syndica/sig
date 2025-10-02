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

  onBrokenLinks: "ignore",
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
  headTags: [
    // Standard favicon
    {
      tagName: "link",
      attributes: { rel: "shortcut icon", href: "img/favicon.ico" },
    },
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        href: "img/favicon.ico",
        type: "image/x-icon",
      },
    },

    // Modern favicon sizes
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        type: "image/png",
        sizes: "16x16",
        href: "img/favicon-16x16.png",
      },
    },
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        type: "image/png",
        sizes: "32x32",
        href: "img/favicon-32x32.png",
      },
    },
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        type: "image/png",
        sizes: "48x48",
        href: "img/favicon-48x48.png",
      },
    },

    // Apple touch icons
    {
      tagName: "link",
      attributes: {
        rel: "apple-touch-icon",
        sizes: "180x180",
        href: "img/favicon-192x192.png",
      },
    },
    {
      tagName: "link",
      attributes: {
        rel: "apple-touch-icon",
        sizes: "152x152",
        href: "img/favicon-192x192.png",
      },
    },
    {
      tagName: "link",
      attributes: {
        rel: "apple-touch-icon",
        sizes: "120x120",
        href: "img/favicon-192x192.png",
      },
    },

    // Android/Chrome
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        type: "image/png",
        sizes: "192x192",
        href: "img/favicon-192x192.png",
      },
    },
    {
      tagName: "link",
      attributes: {
        rel: "icon",
        type: "image/png",
        sizes: "512x512",
        href: "img/favicon-512x512.png",
      },
    },

    // Microsoft
    {
      tagName: "meta",
      attributes: { name: "msapplication-TileColor", content: "#3675F8" },
    },
    {
      tagName: "meta",
      attributes: {
        name: "msapplication-TileImage",
        content: "img/favicon-48x48.png",
      },
    },

    // Theme color
    {
      tagName: "meta",
      attributes: { name: "theme-color", content: "#3675F8" },
    },
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
      copyright: `© Copyright ${new Date().getFullYear()} Syndica Inc.`,
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
