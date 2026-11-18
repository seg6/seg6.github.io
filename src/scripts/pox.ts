export interface PoxRun {
  onOutput(text: string): void;
  onDone(ms: number): void;
  onStatus(text: string): void;
}

export function createPox() {
  let worker: Worker | undefined;
  let ready = false;
  let current: PoxRun | undefined;

  function start() {
    ready = false;
    worker = new Worker('/wasm/pox-worker.js');
    worker.onmessage = ({ data }) => {
      if (data.type === 'ready') { ready = true; current?.onStatus('running'); }
      else if (data.type === 'out') current?.onOutput(data.text);
      else if (data.type === 'failed') current?.onStatus('could not start python');
      else if (data.type === 'done') { const run = current; current = undefined; run?.onDone(data.ms); }
    };
    return worker;
  }

  return {
    get busy() { return current !== undefined; },
    run(source: string, handlers: PoxRun) {
      current = handlers;
      handlers.onStatus(ready ? 'running' : 'downloading python (about 10 MB)');
      (worker ?? start()).postMessage({ source });
    },
    stop() {
      worker?.terminate();
      worker = undefined;
      current = undefined;
    },
  };
}

export function parsePpm(text: string): ImageData | undefined {
  if (!text.startsWith('P3')) return;
  const numbers = text.slice(2).trim().split(/\s+/).map(Number);
  const [width, height, max] = numbers;
  if (!width || !height || numbers.length < 3 + width * height * 3) return;
  const image = new ImageData(width, height);
  for (let pixel = 0; pixel < width * height; pixel++) {
    for (let channel = 0; channel < 3; channel++) image.data[pixel * 4 + channel] = numbers[3 + pixel * 3 + channel] / max * 255;
    image.data[pixel * 4 + 3] = 255;
  }
  return image;
}
