import { berlinSun, createScene, type Scene, type SceneOptions } from './scene';

export function initScenePage(options: Pick<SceneOptions, 'horizon' | 'sprites' | 'skyline' | 'onFrame'>) {
  const canvas = document.querySelector<HTMLCanvasElement>('[data-scene]');
  if (!canvas) return;

  const clock = document.querySelector<HTMLElement>('[data-scene-clock]');
  const sunLabel = document.querySelector<HTMLElement>('[data-scene-sun]');
  const loopButton = document.querySelector<HTMLButtonElement>('[data-scene-loop]');
  const nowButton = document.querySelector<HTMLButtonElement>('[data-scene-now]');
  const timeFormat = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Berlin', hour: '2-digit', minute: '2-digit', hour12: false,
  });

  let built: Scene | undefined;
  const scene = createScene(canvas, {
    cell: 4,
    horizon: options.horizon,
    sprites: options.sprites,
    skyline: options.skyline,
    onFrame(date) {
      if (clock) clock.textContent = timeFormat.format(date);
      if (sunLabel) {
        const { elevation } = berlinSun(date);
        const degrees = Math.abs(Math.round(elevation));
        sunLabel.textContent = elevation >= 0 ? `sun ${degrees}° up` : `sun ${degrees}° below`;
      }
      if (nowButton && built) nowButton.hidden = built.state.offset === 0 || built.state.loop;
      options.onFrame?.(date);
    },
  });

  built = scene;

  loopButton?.addEventListener('click', () => {
    scene.state.loop = !scene.state.loop;
    if (!scene.state.loop) scene.state.offset = 0;
    loopButton.setAttribute('aria-pressed', String(scene.state.loop));
    scene.sync();
  });
  nowButton?.addEventListener('click', () => {
    scene.state.offset = 0;
    scene.draw();
  });

  const onControl = (event: Event) => event.target instanceof Element && event.target.closest('a, button, .scene-id, .scene-links, .scene-meta');
  window.addEventListener('pointerdown', event => {
    if (onControl(event)) return;
    const at = scene.toCells(event);
    if (at.y >= scene.size.horizon) scene.ripple(at.x, at.y);
  });

  return scene;
}
