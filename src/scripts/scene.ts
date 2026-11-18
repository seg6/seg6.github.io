const BAYER = [
  0, 32, 8, 40, 2, 34, 10, 42,
  48, 16, 56, 24, 50, 18, 58, 26,
  12, 44, 4, 36, 14, 46, 6, 38,
  60, 28, 52, 20, 62, 30, 54, 22,
  3, 35, 11, 43, 1, 33, 9, 41,
  51, 19, 59, 27, 49, 17, 57, 25,
  15, 47, 7, 39, 13, 45, 5, 37,
  63, 31, 55, 23, 61, 29, 53, 21,
].map(value => (value + 0.5) / 64);

const LATITUDE = 52.52;
const LONGITUDE = 13.405;
const RADIANS = Math.PI / 180;
const track = { left: 0.06, right: 0.94 };

type Rgb = [number, number, number];

export interface Sun {
  x: number;
  y: number;
  radius: number;
  up: boolean;
  daylight: number;
}

export interface Sprite {
  x: number;
  depth: number;
  bitmap: string[];
  phase: number;
  speed?: number;
  screen?: { x: number; y: number };
}

export interface SceneOptions {
  cell: number;
  horizon: number;
  sun?: (width: number, height: number, horizon: number, date: Date) => Sun;
  sprites?: Sprite[];
  skyline?: boolean;
  onFrame?: (date: Date) => void;
}

export function berlinSun(date: Date) {
  const start = Date.UTC(date.getUTCFullYear(), 0, 0);
  const day = (date.getTime() - start) / 86_400_000;
  const declination = -23.44 * Math.cos((2 * Math.PI * (day + 10)) / 365);
  const utcHours = date.getUTCHours() + date.getUTCMinutes() / 60 + date.getUTCSeconds() / 3600;
  const hourAngle = (((utcHours + LONGITUDE / 15 - 12) * 15 + 540) % 360) - 180;
  const elevation = Math.asin(
    Math.sin(LATITUDE * RADIANS) * Math.sin(declination * RADIANS)
    + Math.cos(LATITUDE * RADIANS) * Math.cos(declination * RADIANS) * Math.cos(hourAngle * RADIANS),
  ) / RADIANS;
  const riseAngle = Math.acos(Math.max(-1, Math.min(1, -Math.tan(LATITUDE * RADIANS) * Math.tan(declination * RADIANS)))) / RADIANS;
  return { elevation, hourAngle, riseAngle, noonElevation: 90 - LATITUDE + declination };
}

const smooth = (from: number, to: number, value: number) => {
  const t = Math.min(1, Math.max(0, (value - from) / (to - from)));
  return t * t * (3 - 2 * t);
};

export function skySun(width: number, height: number, horizon: number, date: Date): Sun {
  const { elevation, hourAngle, riseAngle, noonElevation } = berlinSun(date);
  const across = (hourAngle + riseAngle) / (2 * riseAngle);
  const radius = Math.max(6, Math.min(width, height) * 0.038);
  return {
    x: width * (track.left + across * (track.right - track.left)),
    y: horizon - Math.sin(Math.PI * across) * horizon * 0.92 * (Math.max(26, noonElevation) / 62),
    radius,
    up: across > -0.03 && across < 1.03,
    daylight: smooth(-8, 10, elevation),
  };
}

export function skyMoon(width: number, height: number, horizon: number, date: Date) {
  const { hourAngle, riseAngle } = berlinSun(date);
  const across = ((((hourAngle - riseAngle) % 360) + 360) % 360) / (360 - 2 * riseAngle);
  return {
    x: width * (track.left + across * (track.right - track.left)),
    y: horizon - Math.sin(Math.PI * across) * horizon * 0.66,
    radius: Math.max(7, Math.min(width, height) * 0.044),
    up: !skySun(width, height, horizon, date).up,
  };
}

function hash(x: number, y: number) {
  const n = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
  return n - Math.floor(n);
}

function parseColor(value: string): Rgb {
  const probe = document.createElement('canvas').getContext('2d');
  if (!probe) return [0, 0, 0];
  probe.fillStyle = value;
  probe.fillRect(0, 0, 1, 1);
  const [r, g, b] = probe.getImageData(0, 0, 1, 1).data;
  return [r, g, b];
}

export function createScene(canvas: HTMLCanvasElement, options: SceneOptions) {
  const ctx = canvas.getContext('2d')!;
  const { cell } = options;
  const sunFor = options.sun ?? skySun;
  const sprites = options.sprites ?? [];
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  let width = 0;
  let height = 0;
  let horizon = 0;
  let frame: ImageData | undefined;
  let lit: Rgb = [255, 255, 255];
  let unlit: Rgb = [0, 0, 0];
  let dark = false;
  let sun: Sun = { x: 0, y: 0, radius: 1, up: false, daylight: 0 };
  let moon = { x: 0, y: 0, radius: 1, up: false };
  let lastFrame = 0;
  let lastTick = performance.now();
  let running = false;
  let roofs = new Int16Array(0);
  let tower = { x: 0, shaft: 0, ball: 0, radius: 0, tip: 0 };
  const pointer = { x: -1, y: -1, active: false };
  const ripples: { x: number; y: number; born: number }[] = [];

  const state = {
    offset: 0,
    loop: false,
  };

  const now = () => new Date(Date.now() + state.offset);

  function readTheme() {
    const styles = getComputedStyle(document.documentElement);
    lit = parseColor(styles.getPropertyValue('--dither-lit'));
    unlit = parseColor(styles.getPropertyValue('--dither-unlit'));
    dark = styles.colorScheme === 'dark';
  }

  function resize() {
    const wide = canvas.clientWidth >= 900;
    track.left = wide ? 0.5 : 0.08;
    track.right = wide ? 0.95 : 0.92;
    width = Math.max(1, Math.ceil(canvas.clientWidth / cell));
    height = Math.max(1, Math.ceil(canvas.clientHeight / cell));
    horizon = Math.round(height * options.horizon);
    canvas.width = width;
    canvas.height = height;
    frame = ctx.createImageData(width, height);
    if (options.skyline) buildSkyline();
  }

  function buildSkyline() {
    roofs = new Int16Array(width);
    const unit = Math.max(1, horizon / 150);
    let x = 0, n = 0;
    while (x < width) {
      const wide = Math.round((5 + hash(n, 1) * 13) * unit);
      const tall = hash(n, 2) < 0.14 ? 1 : Math.round((2 + hash(n, 3) * hash(n, 3) * 8) * unit);
      for (let i = x; i < Math.min(width, x + wide); i++) roofs[i] = tall;
      x += wide;
      n++;
    }
    const dome = Math.round(width * 0.535), radius = Math.round(5 * unit);
    for (let i = -radius - 2; i <= radius + 2; i++) {
      const at = dome + i;
      if (at < 0 || at >= width) continue;
      const curve = Math.abs(i) <= radius ? Math.round(Math.sqrt(radius * radius - i * i)) : 0;
      roofs[at] = Math.max(roofs[at], Math.round(6 * unit) + curve + (i === 0 ? Math.round(3 * unit) : 0));
    }
    tower = { x: Math.round(width * 0.69), shaft: 0, ball: Math.round(31 * unit), radius: Math.max(3, Math.round(4 * unit)), tip: Math.round(54 * unit) };
  }

  function city(x: number, up: number, night: boolean, seconds: number) {
    const dx = Math.abs(x - tower.x);
    const unlitSky = dark || night;
    const solid = unlitSky ? 2 : 1;
    if (dx <= tower.radius) {
      if (up === tower.tip && dx === 0) return night && seconds % 2.4 < 1.2 ? 2 : solid;
      const fromBall = up - tower.ball;
      if (dx * dx + fromBall * fromBall <= tower.radius * tower.radius + 1) return solid;
      if (up <= tower.ball && dx <= (up < 4 ? 2 : up < 16 ? 1 : 0)) return solid;
      if (up > tower.ball && up < tower.tip && dx === 0) return solid;
    }
    const roof = roofs[x];
    if (up > roof) return 0;
    if (unlitSky && (up === roof || roofs[x - 1] < up || roofs[x + 1] < up)) return 2;
    if (night && roof > 3 && up < roof && up > 1 && (up & 1) === 0 && (x & 1) === 0 && hash(x, up) > 0.8) return 2;
    return 1;
  }

  function put(out: Uint8ClampedArray, x: number, y: number, color: Rgb) {
    if (x < 0 || y < 0 || x >= width || y >= height) return;
    const i = (y * width + x) * 4;
    out[i] = color[0];
    out[i + 1] = color[1];
    out[i + 2] = color[2];
  }

  function draw(time = performance.now()) {
    if (!frame) return;
    const date = now();
    const seconds = time / 1000;
    sun = sunFor(width, height, horizon, date);
    moon = options.sun ? { ...moon, up: false } : skyMoon(width, height, horizon, date);
    const { daylight } = sun;
    while (ripples.length && seconds - ripples[0].born > 5) ripples.shift();

    const out = frame.data;
    for (let y = 0; y < height; y++) {
      const above = y < horizon;
      const depth = above ? 0 : (y - horizon + 1) / (height - horizon);
      for (let x = 0; x < width; x++) {
        let value: number;
        if (above) {
          const fall = y / horizon;
          value = dark
            ? (0.07 + daylight * 0.43 + fall * fall * (0.05 + daylight * 0.27)) * 0.38
            : 0.07 + daylight * 0.79 + fall * fall * 0.1;
          if (sun.up) {
            const dx = x - sun.x;
            const dy = y - sun.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (distance < sun.radius) value = 2;
            else value += Math.exp(-(distance - sun.radius) / (sun.radius * 1.3)) * (dark ? 0.3 : -0.5);
          }
          if (moon.up) {
            const dx = x - moon.x;
            const dy = y - moon.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (distance < moon.radius) {
              const bx = dx - moon.radius * 0.46;
              const by = dy + moon.radius * 0.14;
              value = bx * bx + by * by > moon.radius * moon.radius * 0.72 ? 2 : -1;
            } else {
              value += Math.exp(-(distance - moon.radius) / (moon.radius * 1.5)) * (dark ? -0.2 : -0.6);
            }
          }
          if (daylight < 0.5 && value > -0.5) {
            const star = hash(x, y);
            if (star > 0.9965) value += (1 - daylight * 2) * (0.6 + 0.4 * Math.sin(seconds * 1.5 + star * 900));
          }
          if (options.skyline) {
            const stands = city(x, horizon - y, daylight < 0.4, seconds);
            if (stands) value = stands === 2 ? 2 : -1;
          }
        } else {
          const scale = 1 / (depth + 0.06);
          const swell = Math.sin(scale * 5 + seconds * 0.9 + Math.sin(x * 0.009 * scale + seconds * 0.5) * 2.2);
          const chop = Math.sin(x * 0.11 * (0.4 + scale * 0.12) + seconds * 1.3 + scale * 2);
          const wave = swell * 0.65 + chop * 0.35;
          value = (0.05 + daylight * 0.27 - depth * 0.1 + wave * (0.06 + daylight * 0.08)) * (dark ? 0.57 : 1) + (dark ? 0 : 0.03 + daylight * 0.17);
          if (options.skyline) {
            const down = y - horizon;
            const reach = (Math.abs(x - tower.x) <= 1 ? tower.tip : roofs[x]) * 0.55;
            if (down < reach && wave > -0.55) value -= (dark ? 0.1 : 0.06 + daylight * 0.16) * (1 - down / reach);
          }
          if (sun.up) {
            const spread = sun.radius * (0.8 + depth * 1.8);
            const glint = Math.exp(-((x - sun.x) * (x - sun.x)) / (spread * spread));
            value += glint * Math.max(0, wave + 0.25) * (dark ? 0.7 : 0.5) * (1 - depth * 0.85) * (0.4 + daylight * 0.6);
          }
          if (moon.up) {
            const spread = moon.radius * (0.7 + depth * 1.4);
            const glint = Math.exp(-((x - moon.x) * (x - moon.x)) / (spread * spread));
            value += glint * Math.max(0, wave + 0.2) * 0.35 * (1 - depth * 0.85);
          }
          if (pointer.active && pointer.y >= horizon) {
            const dx = x - pointer.x;
            const dy = (y - pointer.y) * 2.4;
            const distance = Math.sqrt(dx * dx + dy * dy);
            value += Math.sin(distance * 0.55 - seconds * 7) * Math.exp(-distance / 16) * 0.3;
          }
          for (const ripple of ripples) {
            const age = seconds - ripple.born;
            const dx = x - ripple.x;
            const dy = (y - ripple.y) * 2.4;
            const distance = Math.sqrt(dx * dx + dy * dy);
            const front = age * 26;
            value += Math.sin((distance - front) * 0.5) * Math.exp(-Math.abs(distance - front) / 9) * Math.exp(-age * 0.9) * 0.6;
          }
        }
        const color = value > BAYER[(y & 7) * 8 + (x & 7)] ? lit : unlit;
        const i = (y * width + x) * 4;
        out[i] = color[0];
        out[i + 1] = color[1];
        out[i + 2] = color[2];
        out[i + 3] = 255;
      }
    }

    const ink = dark ? lit : unlit;
    const fill = dark ? unlit : lit;
    for (const sprite of [...sprites].sort((a, b) => a.depth - b.depth)) {
      const size = 1 + Math.round(sprite.depth * 2);
      const bob = Math.round(Math.sin(seconds * 1.1 + sprite.phase) * (0.5 + sprite.depth * 1.5));
      const rows = sprite.bitmap.length;
      const columns = sprite.bitmap[0].length;
      const across = sprite.speed ? ((((sprite.x + seconds * sprite.speed) % 1.2) + 1.2) % 1.2) - 0.1 : sprite.x;
      const left = Math.round(across * width - (columns * size) / 2);
      const top = Math.round(horizon + sprite.depth * (height - horizon) * 0.9) + bob - rows * size;
      for (let row = 0; row < rows; row++) {
        for (let column = 0; column < columns; column++) {
          const mark = sprite.bitmap[row][column];
          if (mark === '.') continue;
          for (let sy = 0; sy < size; sy++) {
            for (let sx = 0; sx < size; sx++) {
              put(out, left + column * size + sx, top + row * size + sy, mark === '1' ? ink : fill);
            }
          }
        }
      }
      sprite.screen = { x: across * width * cell, y: top * cell };
    }

    ctx.putImageData(frame, 0, 0);
    options.onFrame?.(date);
  }

  function tick(time: number) {
    const elapsed = time - lastTick;
    lastTick = time;
    if (state.loop) state.offset += elapsed * 960;
    if (time - lastFrame >= 66) {
      lastFrame = time;
      draw(time);
    }
    if (running) requestAnimationFrame(tick);
  }

  function sync() {
    const shouldRun = !document.hidden && (!reduceMotion.matches || state.loop);
    if (shouldRun && !running) {
      running = true;
      lastTick = performance.now();
      requestAnimationFrame(tick);
    } else if (!shouldRun) {
      running = false;
      draw();
    }
  }

  function toCells(event: { clientX: number; clientY: number }) {
    const box = canvas.getBoundingClientRect();
    return { x: (event.clientX - box.left) / cell, y: (event.clientY - box.top) / cell };
  }

  window.addEventListener('pointermove', event => {
    const at = toCells(event);
    pointer.x = at.x;
    pointer.y = at.y;
    pointer.active = true;
  });
  document.documentElement.addEventListener('pointerleave', () => { pointer.active = false; });
  new ResizeObserver(() => { resize(); draw(); }).observe(canvas);
  document.addEventListener('theme:changed', () => { readTheme(); draw(); });
  document.addEventListener('visibilitychange', sync);
  reduceMotion.addEventListener('change', sync);
  if (reduceMotion.matches) setInterval(() => draw(), 60_000);

  readTheme();
  resize();
  draw();
  sync();

  return {
    state,
    now,
    draw,
    sync,
    toCells,
    get sun() { return sun; },
    get moon() { return moon; },
    get size() { return { width, height, horizon, cell }; },
    ripple(x: number, y: number) {
      if (y < horizon) return;
      ripples.push({ x, y, born: performance.now() / 1000 });
      if (ripples.length > 6) ripples.shift();
      if (!running) draw();
    },
  };
}

export type Scene = ReturnType<typeof createScene>;
