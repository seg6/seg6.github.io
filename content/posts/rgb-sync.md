+++
title = "Gave My RGB Fans a Job: 38-Pixel Screen Mirror"
description = ""
date = 2025-12-24

[extra]
lang = "en"
toc = false
comment = false
math = false
+++

<iframe
  src="https://www.youtube.com/embed/gGB5INrGfZs?si=JD11j49CDIb4Kzzm"
  title="YouTube video player"
  frameborder="0"
  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
  referrerpolicy="strict-origin-when-cross-origin"
  allowfullscreen>
</iframe>

I recently picked up a second-hand build with a Ryzen 7 7800X3D and an RTX 5070 Ti. It's a massive upgrade for me, and I've been enjoying throwing heavy workloads at it.

![The Setup](/img/rgb-sync/setup.png)

The case came with RGB everywhere: RAM, pump, and the fans. I wanted to do something with it other than a rainbow cycle or static color, so I wrote a Python script to mirror the screen onto the components. The idea is that blue sky at the top of the frame means the top components go blue, while lava at the bottom means the bottom fans go red.

# The Wiring Constraint

The catch is that the fans are daisy-chained; meaning bottom intake, top exhaust, and rear exhaust all on one controller. I can't address them individually, so if I send a color, the entire perimeter lights up at once. This means no proper pixel map is possible (at least until I fix this issue), just a *best-effort* layout that works around the wiring.

# Spatial Logic

I built a simple tool to click through a grid and assign LEDs to screen coordinates. The pump samples left-center at 35% width, the RAM samples dead center around 55–65%, and the fans are mapped to the far right edge at 85%.

Even though the fans are electrically a single unit, they mostly sit on the right side of the case. Mapping them to the right edge of the screen creates a somewhat convincing flow from the CPU block outward to the exhaust.

![The LED mapping tool](/img/rgb-sync/led-mapping-tool.png)

It turned out to be surprisingly nice-looking! I sometimes catch myself watching the case shift colors and smiling. :)
