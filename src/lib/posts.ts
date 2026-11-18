import { execSync } from 'node:child_process';
import { getCollection, type CollectionEntry } from 'astro:content';

export type NumberedPost = CollectionEntry<'posts'> & { number: string };

export function readingMinutes(body: string = '') {
  const words = body.trim().split(/\s+/).length;
  return Math.max(1, Math.ceil(words / 220));
}

export function formatDate(date: Date) {
  return date.toLocaleDateString('en-GB', {
    day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC',
  }).toLowerCase();
}

export function formatMonth(date: Date) {
  return date.toLocaleDateString('en-GB', { month: 'short', year: 'numeric', timeZone: 'UTC' }).toLowerCase();
}

export type ShapeBlock = ['p' | 'c' | 'i' | 'h', number];

export function postShape(body: string = ''): ShapeBlock[] {
  const lines = body.split('\n');
  const depths = lines.filter(line => /^#{1,6} /.test(line)).map(line => line.indexOf(' '));
  const top = depths.length ? Math.min(...depths) : 0;
  const shape: ShapeBlock[] = [];
  for (let at = 0; at < lines.length; at++) {
    const line = lines[at].trim();
    if (!line) continue;
    const fence = /^(```|~~~|\$\$)/.exec(line)?.[1];
    if (fence) {
      const start = at;
      if (!(fence === '$$' && line.length > 2 && line.endsWith('$$'))) {
        do at++; while (at < lines.length && !lines[at].trim().startsWith(fence));
      }
      shape.push(['c', Math.max(1, at - start - 1)]);
    } else if (/^#{1,6} /.test(line)) {
      if (line.indexOf(' ') === top) shape.push(['h', 0]);
    } else if (/^(!\[|<(figure|img|video|iframe)\b)/.test(line)) {
      while (at + 1 < lines.length && lines[at + 1].trim()) at++;
      shape.push(['i', 8]);
    } else {
      let chars = line.length;
      while (at + 1 < lines.length && lines[at + 1].trim() && !/^(```|~~~|#{1,6} )/.test(lines[at + 1].trim())) chars += lines[++at].length;
      shape.push(['p', Math.max(1, Math.round(chars / 80))]);
    }
  }
  return shape;
}

export function shapeLength(shape: ShapeBlock[]) {
  return shape.reduce((sum, [, lines]) => sum + lines, 0);
}

export function formatStamp(date: Date) {
  return `${String(date.getUTCMonth() + 1).padStart(2, '0')}.${date.getUTCFullYear()}`;
}

export async function getNumberedPosts(): Promise<NumberedPost[]> {
  const posts = (await getCollection('posts')).sort(
    (a, b) => a.data.date.getTime() - b.data.date.getTime(),
  );
  return posts
    .map((post, index) => ({ ...post, number: String(index + 1).padStart(3, '0') }))
    .reverse();
}

let cachedBuild: string | undefined;

export function buildHash() {
  if (cachedBuild === undefined) {
    try {
      cachedBuild = execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] })
        .toString()
        .trim();
    } catch {
      cachedBuild = '';
    }
  }
  return cachedBuild;
}
