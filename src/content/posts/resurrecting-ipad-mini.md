---
title: "bringing the modern web to the original ipad mini"
description: "resurrecting ios 6 with a native remote browser"
date: 2026-07-21
toc: true
---

I recently visited my parents and found the first generation iPad mini they
bought me when I was ten years old. More than a decade later, it is still a
beautiful piece of hardware. Small, light, sturdy, and from a time before every
iPad was trying to become a laptop.

Then I turned it on and remembered why I stopped using it. It was running iOS
9.3.5, which is brutal on the A5 chip. Every tap had weight, animations
stuttered, and opening an app felt like an event. Apple really killed this
device with iOS 9.

I wanted to turn it into a smooth, distraction free reading device, so I took
the nostalgic route through the legacy jailbreak toolchain. I jailbroke it
with [Carbon](http://carbon.sep.lol/), used
[Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) to enter kDFU mode,
downgraded to iOS 8.4.1, installed OpenSSH, and used CoolBooter to boot iOS
6.1.3.

The difference was absurd. iOS 6 on the A5 is butter smooth. I transferred a
few books with iFile and had exactly what I wanted: a small tablet with a still
good display and the lovely skeuomorphic iBooks app.

Everything was perfect until the reading workflow left the book.

Reading is not really offline anymore. Finding articles, checking references,
downloading PDFs, opening links, and asking an LLM about something confusing
all happen on the web. That is where an otherwise delightful iPad from 2012
falls apart.

# the webkit wall

Installing [modern root certificates](https://repo.invoxiplaygames.uk/certificates/)
helps with a small part of the problem, but it cannot give Safari the
JavaScript, CSS, media, and browser APIs expected by current websites. Every
third-party browser on iOS 6 is attached to the same system WebKit, so changing
the app does not change the engine.

A remote desktop would technically solve that, but it would still feel like a
desktop squeezed into an iPad: tiny controls, mouse semantics, awkward
scrolling, and a window manager wasting the screen. I wanted something that
felt like Safari, not a computer viewed through Safari.

The useful split was obvious in hindsight. The iPad already has a great touch
interface and hardware H.264 decoding. What it needs from another machine is a
modern browser engine.

Since I was on vacation, this also felt like the perfect pet project to hand to
an LLM and see how far it could get. Out of that experiment, Surf was born.

<iframe
  src="https://www.youtube.com/embed/jVOAqYKFwg8?si=s_ePhvAhW003pQ1B"
  title="YouTube video player"
  frameborder="0"
  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
  referrerpolicy="strict-origin-when-cross-origin"
  allowfullscreen>
</iframe>

# a browser split across two machines

Surf has a native Objective-C client and a Go backend. The backend runs a
current Chrome, Edge, or Chromium build on a 64-bit Windows, macOS, or Linux
host. Chromium owns the website: JavaScript, layout, cookies, media, and modern
TLS. The old device owns the browser around it: tabs, navigation, keyboard,
files, sharing, and touch.

```text
native ios browser
        │ touch, keyboard, tabs, navigation
        ▼
certificate-pinned tls + websockets
        │
        ▼
go backend -- chrome devtools protocol -- chromium
        ▲                                      │
        └──────────── h.264 + audio ───────────┘
```

Surf captures only Chromium's active tab. Chromium's `tabCapture` API supplies
video and audio, and WebCodecs encodes the page as H.264 at a source-clocked 60
frames per second. Page rendering and compositing remain GPU accelerated when
the host has a usable GPU.

The final video encode deliberately prefers software AVC. That sounds
backwards on a machine with a hardware encoder, but modern platform encoders
can produce streams whose reference-frame and buffering behavior overwhelms
much older decoders. Chromium's software encoder produces a simpler stream
that the A5 can decode smoothly at 60 FPS while keeping text remarkably sharp.

The iPad decodes the stream with VideoToolbox and presents it on the display
clock. It reports the exact space left by its native browser chrome, so the
backend does not pretend every phone and tablet has one of a few hard-coded
resolutions. Rotation and fullscreen resize the live surface without replacing
the browser session.

Ordinary TLS and WebSockets are already fast enough for this on my network. No
custom UDP transport is necessary; the iPad spends its limited resources on
things it remains good at (video decode, UIKit, audio, and touch) while the host
does the expensive web work.

# making it feel native

Only the page is video. The frequently touched parts are UIKit.

Surf has an omnibox, native tabs, bookmarks, history, downloads, uploads,
sharing, saved servers, diagnostics, and synchronized page/native fullscreen.
iPads get a top toolbar and persistent tab strip. iPhones and iPod touches get
a compact bottom toolbar and a Pages view with tab previews. The interface
matches the installed era, including a skeuomorphic treatment on iOS 6.

Input is also real touch rather than remote-desktop imitation. Surf sends the
physical contacts from UIKit and maps them into Chromium's visual viewport as
native touch events. Chromium therefore owns scrolling inertia, tap
activation, pinch zoom, Pointer Events, and each website's gesture handlers.
GitHub keeps moving after a flick, TikTok can change videos on a vertical
swipe, and switching between Desktop and Mobile Websites never turns the iPad
into a mouse.

Editable focus inside the page brings up the native iOS keyboard, including
for password fields, shadow-root inputs, and composition text. This sounds
like a small detail until a login form refuses to work; then it is the
difference between a video demo and a browser.

One rootful package contains `armv7` and `arm64` slices for jailbroken iPhones,
iPod touches, and iPads from iOS 6 through iOS 14. The original iPad mini on
iOS 6.1.3 remains my primary test device, so the wider compatibility list is
still experimental until more of it has been exercised on real hardware.

# pairing something from 2012

Surf does not fall back to plaintext just because the client is old. The host
creates a persistent TLS identity and the iOS app pins its certificate
fingerprint. Pairing is closed until the owner creates one single-use
invitation.

A device can scan a QR code containing the server address, identity, and a
one-time secret. Manual pairing uses an address and six-digit code, followed by
a six-word identity comparison. Each device keeps its own key in the iOS
Keychain and can be revoked independently.

LAN access gives the lowest latency. For roaming, Surf can carry that same
certificate-pinned TLS connection inside a Cloudflare WebSocket, so Cloudflare
provides reachability without terminating the trusted Surf connection.

# wrapping up

The iPad is useful again, but not because its hardware somehow became modern.
Surf changed the division of labor. A current computer handles Chromium and
the web; the iPad handles the interface.

It is an unreasonable amount of infrastructure to put behind a tablet from
2012. It is also exactly the kind of unreasonable that makes old computers
feel alive again.

Surf is open source at [github.com/seg6/surf](https://github.com/seg6/surf).
