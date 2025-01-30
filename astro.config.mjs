// @ts-check
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import tailwind from "@astrojs/tailwind";
import expressiveCode from "astro-expressive-code";
import icon from "astro-icon";
import remarkToc from "remark-toc";

import cloudflare from "@astrojs/cloudflare";

// https://astro.build/config
export default defineConfig({
  site: "https://bradley.chatha.dev",

  markdown: {
    remarkPlugins: [[remarkToc, { heading: "summary" }]],
  },

  integrations: [
    sitemap({
      i18n: {
        defaultLocale: "en",
        locales: {
          en: "en-GB",
        },
      },
    }),
    tailwind(),
    expressiveCode({
      defaultLocale: "en-GB",
      themes: ["github-dark"],
    }),
    icon(),
  ],

  output: "static",
  adapter: cloudflare(),
});
