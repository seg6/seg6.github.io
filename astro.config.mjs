// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig, fontProviders } from 'astro/config';
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
  fonts: [
    {
      name: 'DM Sans Variable',
      cssVariable: '--font-sans',
      provider: fontProviders.local(),
      display: 'block',
      fallbacks: ['sans-serif'],
      options: {
        variants: [{
          src: ['@fontsource-variable/dm-sans/files/dm-sans-latin-wght-normal.woff2'],
          weight: '100 1000',
          style: 'normal',
        }],
      },
    },
    {
      name: 'Fantasque Sans Mono',
      cssVariable: '--font-mono',
      provider: fontProviders.local(),
      display: 'block',
      fallbacks: ['monospace'],
      options: {
        variants: [{
          src: ['./src/assets/fonts/FantasqueSansMono-Regular.woff2'],
          weight: 400,
          style: 'normal',
        }],
      },
    },
    {
      name: 'STIX Two Text',
      cssVariable: '--font-serif',
      provider: fontProviders.local(),
      display: 'block',
      fallbacks: ['serif'],
      options: {
        variants: [
          { src: ['@fontsource/stix-two-text/files/stix-two-text-latin-400-normal.woff2'], weight: 400, style: 'normal' },
          { src: ['@fontsource/stix-two-text/files/stix-two-text-latin-400-italic.woff2'], weight: 400, style: 'italic' },
          { src: ['@fontsource/stix-two-text/files/stix-two-text-latin-600-normal.woff2'], weight: 600, style: 'normal' },
        ],
      },
    },
  ],
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
