// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';

const modusOperandiTinted = JSON.parse(
  readFileSync(new URL('./src/themes/modus-operandi-tinted.json', import.meta.url), 'utf8'),
);
const modusVivendiTinted = JSON.parse(
  readFileSync(new URL('./src/themes/modus-vivendi-tinted.json', import.meta.url), 'utf8'),
);

export default defineConfig({
  site: 'https://seg6.space',
  trailingSlash: 'always',
  markdown: {
    remarkPlugins: [remarkMath],
    rehypePlugins: [rehypeKatex],
    shikiConfig: {
      themes: {
        light: modusOperandiTinted,
        dark: modusVivendiTinted,
      },
    },
  },
});
