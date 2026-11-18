import { reducedMotion } from './theme';

interface ByteExports {
  memory: WebAssembly.Memory;
  reset(seed: number): void;
  run(count: number): void;
  pixels(): number;
  register(which: number): number;
}

interface Line { at: number | null; text: string }

const SIZE = 64;
const FULL = Math.floor(6_400_000 / 60);
const SLOW = 120;
const WINDOW = 17;

const hex = (value: number, digits = 2) => value.toString(16).toUpperCase().padStart(digits, '0');

export async function createByte(parts: { screen: HTMLCanvasElement; registers: HTMLElement; listing: HTMLElement; run: HTMLButtonElement; step: HTMLButtonElement; slow: HTMLButtonElement }) {
  const [{ instance }, lines] = await Promise.all([
    WebAssembly.instantiateStreaming(fetch('/wasm/byte.wasm'), {}),
    fetch('/wasm/byte-plasma.json').then(response => response.json() as Promise<Line[]>),
  ]);
  const byte = instance.exports as unknown as ByteExports;
  const context = parts.screen.getContext('2d')!;
  const image = context.createImageData(SIZE, SIZE);
  const source = lines.slice(0, lines.findIndex(line => line.text.startsWith('sine:')));
  const lineAt = new Map(source.flatMap((line, index) => line.at === null ? [] : [[line.at, index] as const]));
  let running = !reducedMotion;
  let slow = false;
  let visible = true;

  function paint() {
    image.data.set(new Uint8Array(byte.memory.buffer, byte.pixels(), SIZE * SIZE * 4));
    context.putImageData(image, 0, 0);
    const pc = byte.register(0);
    parts.registers.innerHTML = `<span>pc <b>${hex(pc, 4)}</b></span>`
      + ['a', 'x', 'y'].map((name, which) => `<span>${name} <b>${hex(byte.register(which + 1))}</b></span>`).join('')
      + `<span>frame <b>${byte.register(6)}</b></span>`;
    const current = lineAt.get(pc) ?? 0;
    const from = Math.max(0, Math.min(source.length - WINDOW, current - Math.floor(WINDOW / 2)));
    parts.listing.replaceChildren(...source.slice(from, from + WINDOW).map((line, offset) => {
      const row = document.createElement('span');
      if (from + offset === current) row.className = 'on';
      row.textContent = `${line.at === null ? '    ' : hex(line.at, 4)}  ${line.text}\n`;
      return row;
    }));
  }
  const advance = (count: number) => { byte.run(count); paint(); };
  const press = (button: HTMLButtonElement, value: boolean) => button.setAttribute('aria-pressed', String(value));
  const setRunning = (value: boolean) => { running = value; press(parts.run, value); };

  parts.run.addEventListener('click', () => setRunning(!running));
  parts.slow.addEventListener('click', () => { slow = !slow; press(parts.slow, slow); if (slow) setRunning(true); });
  parts.step.addEventListener('click', () => { setRunning(false); advance(1); });
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; }).observe(parts.screen);

  byte.reset(1);
  setRunning(running);
  advance(FULL * 2);

  let last = 0;
  function tick(now: number) {
    requestAnimationFrame(tick);
    if (!running || !visible || now - last < 1000 / 60 - 2) return;
    last = now;
    advance(slow ? SLOW : FULL);
  }
  requestAnimationFrame(tick);
}
