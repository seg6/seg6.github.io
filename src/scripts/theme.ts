export function token(name: string): [number, number, number] {
  const hex = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return [1, 3, 5].map(at => parseInt(hex.slice(at, at + 2), 16) / 255) as [number, number, number];
}

export function onTheme(fn: () => void) {
  fn();
  document.addEventListener('theme:changed', fn);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', fn);
}

export const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
