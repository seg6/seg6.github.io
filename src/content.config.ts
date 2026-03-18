import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    math: z.boolean().optional().default(false),
    mermaid: z.boolean().optional().default(false),
    toc: z.boolean().optional().default(true),
    comments: z.boolean().optional().default(true),
  }),
});

export const collections = { posts };
