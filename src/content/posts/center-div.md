---
title: "we finally learned to center a div, then browsers added sidebars"
description: "an extension for centering a page in the browser window instead of the webview."
date: 2026-08-04
toc: false
viewportAxis: true
---

Centering a div used to require this little ritual:

```css
.thing {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}
```

These days, it is almost disappointingly easy:

```css
body {
  display: grid;
  min-height: 100dvh;
  place-items: center;
}
```

I used that for the `.site` div you're reading. It looked centered until I opened it in a browser with the sidebar visible.

The site still uses regular webview centering. The window-centering behavior described below is not active here.

This is a fairly specific itch. I use one browser window tiled directly in front of me, usually with its sidebar open. When a site deliberately centers a narrow layout, I want it at the dead center of that window, not the space left over beside the sidebar.

![extension off](/img/center-div/extension-off.gif)

The `.site` div was still perfectly centered, just inside the wrong rectangle. I figured the fix would be simple enough: JavaScript knows the width of both the webview and the browser window.

```js
window.innerWidth // the webview
window.outerWidth // the whole browser window
const browserChrome = window.outerWidth - window.innerWidth;
```

With the sidebar on the left, I could move `.site` back by half of that difference:

```js
const shift = -browserChrome / 2;
```

```css
.site {
  translate: var(--window-center-shift, 0px);
}
```

The sidebar still narrows the webview and the page still reflows normally. This only repositions the container that was already centered. If there is not enough visible space for it, the correction should stop rather than hide content.

That worked, right up until I opened DevTools.

# devtools ruins the easy fix

Mine is docked on the right, so the width difference now included browser UI on both sides. It gave me the total, but no way to tell how that total was split.

What finally gave me the missing coordinate was the pointer. A trusted pointer event knows where it is on the screen and where it is inside the webview, which is enough to locate the webview inside the window:

```js
const viewportLeft = event.screenX - event.clientX * scale;
const viewportRight = viewportLeft + innerWidth * scale;

const left = viewportLeft - window.screenX;
const right = window.screenX + outerWidth - viewportRight;
const shift = (right - left) / (2 * scale);
```

Firefox exposes the same viewport position directly. Chromium does not, so the correction starts with a chosen sidebar position and becomes exact as soon as the pointer enters the page.

# center, actually

I moved the experiment into [**center, actually**](https://github.com/seg6/center-div), a browser extension. It tries to find the centered element itself; if it guesses wrong, you can pick one. This is where the preference belongs: opt-in, rather than chosen by a site for everyone. The [demo](https://seg6.space/center-div/) is the simplest place to see the difference.

![extension-on](/img/center-div/extension-on.gif)
