export function readingMinutes(body: string = '') {
  const words = body.trim().split(/\s+/).length;
  return Math.max(1, Math.ceil(words / 220));
}

export function formatDate(date: Date) {
  return date.toLocaleDateString('en-GB', {
    day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC',
  }).toLowerCase();
}
