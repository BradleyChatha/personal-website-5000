import { defineCollection, z } from "astro:content";
import { glob, file } from "astro/loaders";

const blogPost = defineCollection({
  loader: glob({ pattern: "**/[^_]*.md", base: "collections/blog/" }),
  schema: z.object({
    slug: z.string(),
    title: z.string(),
    published: z.coerce.date(),
    updated: z.coerce.date(),
    order: z.number(),
  }),
});

const blogGroup = defineCollection({
  loader: glob({ pattern: "**/_group.md", base: "collections/blog/" }),
  schema: z.object({
    slug: z.string(),
    title: z.string(),
    order: z.number(),
  }),
});

export const collections = { blogPost, blogGroup };
