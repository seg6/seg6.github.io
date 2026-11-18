import { onTheme, token } from './theme';

interface TracerExports {
  memory: WebAssembly.Memory;
  _initialize?(): void;
  setup(width: number, height: number): void;
  render(camX: number, camY: number, camZ: number, lightX: number, lightY: number, lightZ: number, recursion: number): number;
  move_sphere(index: number, x: number, y: number, z: number): void;
}

export interface TracerOptions {
  onFrame?: (info: { width: number; height: number; ms: number }) => void;
}

const SPHERES = [[0, -1, 3], [-2, 0, 4], [2, 0, 4]];

const BAYER = [
  0, 32, 8, 40, 2, 34, 10, 42, 48, 16, 56, 24, 50, 18, 58, 26,
  12, 44, 4, 36, 14, 46, 6, 38, 60, 28, 52, 20, 62, 30, 54, 22,
  3, 35, 11, 43, 1, 33, 9, 41, 51, 19, 59, 27, 49, 17, 57, 25,
  15, 47, 7, 39, 13, 45, 5, 37, 63, 31, 55, 23, 61, 29, 53, 21,
].map(value => (value + 0.5) / 64);

export async function createTracer(canvas: HTMLCanvasElement, options: TracerOptions = {}) {
  const wasi = new Proxy({}, { get: () => () => 52 });
  const { instance } = await WebAssembly.instantiateStreaming(fetch('/wasm/raytracer.wasm'), { wasi_snapshot_preview1: wasi });
  const tracer = instance.exports as unknown as TracerExports;
  tracer._initialize?.();

  const context = canvas.getContext('2d')!;
  const state = { yaw: 0, pitch: 0.12, lightX: 0, lightY: 1, spheres: SPHERES.map(position => [...position]) };
  const PIVOT = [0, -0.4, 3.6];
  const FLOOR = [0, -5001, 0];
  const recursion = 3;
  let dither = false;
  let budget = 30000;
  let lit = [255, 255, 255], unlit = [0, 0, 0];
  let image: ImageData | undefined;
  let drag: { x: number; y: number; yaw: number; pitch: number; sphere: number; from: number[] } | null = null;
  let visible = true;
  let dirty = true;

  const toView = ([x, y, z]: number[]) => {
    const dx = x - PIVOT[0], dy = y - PIVOT[1], dz = z - PIVOT[2];
    const cy = Math.cos(state.yaw), sy = Math.sin(state.yaw), cp = Math.cos(state.pitch), sp = Math.sin(state.pitch);
    const x1 = dx * cy - dz * sy, z1 = dx * sy + dz * cy;
    return [x1 + PIVOT[0], dy * cp + z1 * sp + PIVOT[1], -dy * sp + z1 * cp + PIVOT[2]];
  };
  const toWorld = ([x, y, z]: number[]) => {
    const dx = x - PIVOT[0], dy = y - PIVOT[1], dz = z - PIVOT[2];
    const cy = Math.cos(state.yaw), sy = Math.sin(state.yaw), cp = Math.cos(state.pitch), sp = Math.sin(state.pitch);
    const y1 = dy * cp - dz * sp, z1 = dy * sp + dz * cp;
    return [dx * cy + z1 * sy + PIVOT[0], y1 + PIVOT[1], -dx * sy + z1 * cy + PIVOT[2]];
  };

  onTheme(() => {
    lit = token('--dither-lit').map(channel => channel * 255);
    unlit = token('--dither-unlit').map(channel => channel * 255);
    dirty = true;
  });

  const aspect = () => canvas.clientWidth / canvas.clientHeight;
  const camZ = () => -1.6 - Math.max(0, 1.3 - aspect()) * 6;

  function draw() {
    const cell = Math.max(canvas.clientWidth < 600 ? 2.5 : 4, Math.sqrt(canvas.clientWidth * canvas.clientHeight / budget));
    const width = Math.max(48, Math.round(canvas.clientWidth / cell / 2) * 2);
    const height = Math.max(32, Math.round(canvas.clientHeight / cell / 2) * 2);
    if (!image || image.width !== width || image.height !== height) {
      canvas.width = width;
      canvas.height = height;
      image = context.createImageData(width, height);
      tracer.setup(width, height);
    }
    [...state.spheres, FLOOR].forEach((sphere, index) => { const [x, y, z] = toView(sphere); tracer.move_sphere(index, x, y, z); });
    const started = performance.now();
    const rgb = new Uint8Array(tracer.memory.buffer, tracer.render(0, 0.2, camZ(), state.lightX, state.lightY, 3, recursion), width * height * 3);
    const ms = performance.now() - started;
    const rgba = image.data;
    for (let y = 0, from = 0, to = 0; y < height; y++) {
      for (let x = 0; x < width; x++, from += 3, to += 4) {
        let r = rgb[from], g = rgb[from + 1], b = rgb[from + 2];
        if (dither) {
          const light = ((0.299 * r + 0.587 * g + 0.114 * b) / 255 - 0.08) * 1.4;
          [r, g, b] = light > BAYER[(y & 7) * 8 + (x & 7)] ? lit : unlit;
        }
        rgba[to] = r; rgba[to + 1] = g; rgba[to + 2] = b; rgba[to + 3] = 255;
      }
    }
    context.putImageData(image, 0, 0);
    if (ms > 14 && budget > 9000) budget *= 0.8;
    dirty = false;
    options.onFrame?.({ width, height, ms });
  }

  const onViewport = (event: { clientX: number; clientY: number }) => {
    const box = canvas.getBoundingClientRect();
    return [((event.clientX - box.left) / box.width - 0.5) * aspect(), 0.5 - (event.clientY - box.top) / box.height];
  };
  const pick = ([u, v]: number[]) => {
    let nearest = -1, nearestDepth = Infinity;
    state.spheres.forEach((sphere, index) => {
      const [x, y, z] = toView(sphere);
      const depth = z - camZ();
      if (depth > 0 && Math.hypot(x / depth - u, (y - 0.2) / depth - v) < 1 / depth && depth < nearestDepth) { nearest = index; nearestDepth = depth; }
    });
    return nearest;
  };

  canvas.addEventListener('pointerdown', event => {
    const sphere = pick(onViewport(event));
    drag = { x: event.clientX, y: event.clientY, yaw: state.yaw, pitch: state.pitch, sphere, from: sphere < 0 ? [] : toView(state.spheres[sphere]) };
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener('pointermove', event => {
    const box = canvas.getBoundingClientRect();
    const [u, v] = onViewport(event);
    state.lightX = u * 6;
    state.lightY = v * 5 + 2.4;
    if (!drag) {
      canvas.style.cursor = pick([u, v]) < 0 ? '' : 'move';
    } else if (drag.sphere >= 0) {
      const depth = drag.from[2] - camZ();
      const moved = toWorld([drag.from[0] + (event.clientX - drag.x) / box.height * depth, drag.from[1] - (event.clientY - drag.y) / box.height * depth, drag.from[2]]);
      moved[1] = Math.max(-1, moved[1]);
      state.spheres[drag.sphere] = moved;
    } else {
      state.yaw = drag.yaw + (event.clientX - drag.x) / box.height * 2.4;
      state.pitch = Math.max(0.02, Math.min(1.35, drag.pitch + (event.clientY - drag.y) / box.height * 2));
    }
    dirty = true;
  });
  canvas.addEventListener('touchstart', event => {
    const touch = event.touches[0];
    if (event.touches.length === 1 && pick(onViewport(touch)) >= 0) event.preventDefault();
  }, { passive: false });
  const release = () => { drag = null; };
  canvas.addEventListener('pointerup', release);
  canvas.addEventListener('pointercancel', release);
  new ResizeObserver(() => { dirty = true; }).observe(canvas);
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; }).observe(canvas);

  function frame() {
    requestAnimationFrame(frame);
    if (visible && dirty) draw();
  }
  requestAnimationFrame(frame);

  return {
    setDither(value: boolean) { dither = value; dirty = true; },
  };
}
