import { getCollection } from "astro:content";
import { dirname } from "node:path";

export type BlogGroup = {
  slug: string;
  title: string;
  posts: BlogPost[];
  raw: any;
};

export type BlogPost = {
  slug: string;
  title: string;
  published: Date;
  updated: Date;
  rawFilePath: string;
  raw: any;
};

const blogPostsRaw = await getCollection("blogPost");
const blogGroupsRaw = await getCollection("blogGroup");

export const blogGroups = blogGroupsRaw
  .sort((a, b) => a.data.order - b.data.order)
  .map((group) => {
    const groupDir = dirname(group.filePath!);
    return {
      slug: group.data.slug,
      title: group.data.title,
      raw: group,
      posts: blogPostsRaw
        .filter((post) => dirname(post.filePath!) === groupDir)
        .sort((a, b) => a.data.order - b.data.order)
        .map((post) => {
          return {
            slug: post.data.slug,
            title: post.data.title,
            published: post.data.published,
            updated: post.data.updated,
            rawFilePath: post.filePath!,
            raw: post,
          } satisfies BlogPost;
        }),
    } satisfies BlogGroup;
  });
