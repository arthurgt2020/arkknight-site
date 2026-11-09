import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const attack = z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).default([]);
const risk = z.object({ likelihood: z.number().int().min(1).max(5), impact: z.number().int().min(1).max(5) });
const tlp = z.enum(['CLEAR', 'GREEN']).default('CLEAR');

const experience = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/experience' }),
  schema: z.object({
    company: z.string(),
    role: z.string(),
    start: z.coerce.date(),
    end: z.coerce.date().optional(),
    location: z.string().optional(),
    highlights: z.array(z.string()).default([]),
    order: z.number().default(0),
  }),
});

const projects = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/projects' }),
  schema: z.object({
    title: z.string(),
    summary: z.string(),
    stack: z.array(z.string()).default([]),
    outcomes: z.array(z.string()).default([]),
    links: z.array(z.object({ label: z.string(), url: z.string().url() })).default([]),
    featured: z.boolean().default(false),
    status: z.enum(['active', 'completed', 'planned']).default('active'),
    date: z.coerce.date(),
  }),
});

const certifications = defineCollection({
  loader: glob({ pattern: '**/*.{md,yaml,yml,json}', base: './src/content/certifications' }),
  schema: z.object({
    name: z.string(),
    issuer: z.string(),
    date: z.coerce.date(),
    credentialId: z.string().optional(),
    verifyUrl: z.string().url().optional(),
  }),
});

const posts = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

const intel = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/intel' }),
  schema: z.object({
    title: z.string(),
    type: z.enum(['actor-profile', 'campaign', 'advisory', 'incident-analysis', 'report', 'intel-drop']),
    drop: z.number().int().optional(),
    risk: risk.optional(),
    linkedinUrl: z.string().url().optional(),
    actor: z.string().optional(),
    aliases: z.array(z.string()).default([]),
    motivation: z.enum(['espionage', 'financial', 'hacktivism', 'destructive', 'unknown']).optional(),
    sectors: z.array(z.string()).default([]),
    regions: z.array(z.string()).default([]),
    attack,
    tlp: z.enum(['CLEAR', 'GREEN']).default('CLEAR'),
    summary: z.string(),
    date: z.coerce.date(),
    draft: z.boolean().default(false),
  }),
});

const hunts = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/hunts' }),
  schema: z.object({
    title: z.string(),
    hypothesis: z.string(),
    attack,
    dataSources: z.array(z.string()).default([]),
    languages: z.array(z.enum(['KQL', 'CQL', 'SPL', 'Sigma', 'YARA', 'EQL', 'SQL', 'Other'])).default([]),
    queriesRepoPath: z.string().optional(),
    drop: z.number().int().optional(),
    risk: risk.optional(),
    linkedinUrl: z.string().url().optional(),
    status: z.enum(['draft', 'published', 'validated', 'retired']).default('published'),
    date: z.coerce.date(),
    draft: z.boolean().default(false),
  }),
});

const weekly = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/weekly' }),
  schema: z.object({
    title: z.string(),
    region: z.string(),
    periodStart: z.coerce.date(),
    periodEnd: z.coerce.date(),
    date: z.coerce.date(),
    tlp,
    summary: z.string(),
    threatLevel: z.string().optional(),
    pages: z.number().int().optional(),
    pdf: z.string().optional(),
    linkedinUrl: z.string().url().optional(),
    draft: z.boolean().default(false),
  }),
});

const research = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/research' }),
  schema: z.object({
    title: z.string(),
    actor: z.string(),
    summary: z.string(),
    date: z.coerce.date(),
    tlp,
    claimsUnverified: z.boolean().default(false),
    attack,
    linkedinUrl: z.string().url().optional(),
    draft: z.boolean().default(false),
  }),
});

const platform = z.enum(['linkedin', 'x', 'tiktok', 'instagram', 'youtube']);

const redkuppi = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/redkuppi' }),
  schema: z.object({
    episode: z.number(),
    title: z.string(),
    summary: z.string(),
    publishDate: z.coerce.date(),
    youtubeId: z.string().optional(),
    links: z.array(z.object({ platform, url: z.string().url() })).default([]),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

const social = defineCollection({
  loader: glob({ pattern: '**/*.{md,yaml,yml}', base: './src/content/social' }),
  schema: z.object({
    title: z.string(),
    platforms: z.array(platform).min(1),
    scheduledAt: z.coerce.date().optional(),
    status: z.enum(['draft', 'approved', 'scheduled', 'published']).default('draft'),
    campaign: z.string().optional(),
    sourceRef: z.string().optional(),
  }),
});

export const collections = { experience, projects, certifications, posts, intel, hunts, weekly, research, redkuppi, social };
