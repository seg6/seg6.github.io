const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/v0.26.4/full/';
importScripts(`${PYODIDE}pyodide.js`);

const SESSION = `
import sys
sys.path.insert(0, '/pox')
sys.setrecursionlimit(6000)
from pox.__main__ import Pox
from pox.interpreter import Interpreter

class Stream:
    def __init__(self):
        self.parts, self.size = [], 0
    def write(self, text):
        self.parts.append(text)
        self.size += len(text)
        if self.size > 2048:
            self.flush()
    def flush(self):
        if self.parts:
            post(''.join(self.parts))
            self.parts, self.size = [], 0

def pox_run(source):
    out, sys.stdout = sys.stdout, Stream()
    try:
        Pox().run(source, Interpreter())
    except BaseException as error:
        print(error)
    finally:
        sys.stdout.flush()
        sys.stdout = out
`;

const ready = (async () => {
  const [pyodide, bundle] = await Promise.all([
    loadPyodide({ indexURL: PYODIDE }),
    fetch('/wasm/pox.json').then(response => response.json()),
  ]);
  for (const [path, source] of Object.entries(bundle.files)) {
    pyodide.FS.mkdirTree(`/pox/${path}`.split('/').slice(0, -1).join('/'));
    pyodide.FS.writeFile(`/pox/${path}`, source);
  }
  pyodide.globals.set('post', text => self.postMessage({ type: 'out', text }));
  pyodide.runPython(SESSION);
  self.postMessage({ type: 'ready' });
  return pyodide.globals.get('pox_run');
})();

ready.catch(error => self.postMessage({ type: 'failed', text: String(error) }));

self.onmessage = async event => {
  const run = await ready;
  const started = performance.now();
  run(event.data.source);
  self.postMessage({ type: 'done', ms: performance.now() - started });
};
