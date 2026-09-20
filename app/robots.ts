import type { MetadataRoute } from 'next';

/**
 * Keep the whole deployment out of search indexes.
 *
 * A hosted recon dashboard has nothing worth indexing and two good reasons not
 * to be: the pages hold somebody else's attack surface, and an indexed scan
 * endpoint is an invitation for automated abuse. The `robots` metadata in
 * `layout.tsx` already sets the per-page header; this covers crawlers that
 * read robots.txt before requesting anything at all.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      disallow: '/',
    },
  };
}
