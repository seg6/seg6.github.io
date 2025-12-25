+++
title = "The Frontend Auth Middleware: Cross-Origin Iframes Without Third-Party Cookies"
description = ""
date = 2025-12-25

[extra]
lang = "en"
toc = true
comment = false
math = false
+++

A few years ago, I worked on a multi-tenant platform. The setup:

- Users could deploy apps to their own subdomains (`alice-app1.platform.app`, `alice-app2.platform.app`, `bob-todo.platform.app`)
- Users could also browse and *install* apps published by other users, kind of like an app store
- The main dashboard lived on `platform.io`, where users managed their account, installed apps, and accessed everything
- We wanted to embed these apps in iframes on the dashboard so users could interact with them without leaving the page

The platform handled auth globally. A user could have multiple apps (`alice-app1.platform.app`, `alice-app2.platform.app`), and they all used the same credentials. Apps didn't implement their own auth, the platform's routing layer validated requests and served the app if the user had access. The challenge was getting that validation to work when apps were embedded in iframes on `platform.io`, since cookies don't cross origins.

The goal: when a user views an embedded app, they should be authenticated automatically. No login page inside the iframe. They're already logged into `platform.io` and that should be enough.

I ended up solving this with service workers, and I'm still pretty happy with how it turned out. Writing it up here in case it's useful to anyone in a similar situation.

**A note on scope:** this describes a fairly specific setup. You need to control both the parent domain *and* the platform routing layer for the embedded subdomains (even if you don't control the actual app code running on them). If you're trying to embed a third-party site you have no control over, this won't help.

# Why This Is Hard

When you embed `alice-app1.platform.app` in an iframe on `platform.io`, the browser treats them as separate origins. Your session cookie on `platform.io` doesn't exist on `alice-app1.platform.app`. The iframe shows a login page.

```
platform.io (logged in, has session cookie)
└── iframe: alice-app1.platform.app (different origin, no cookies, sees login page)
```

The obvious solutions all have problems:

**Third-party cookies** used to solve this, but Safari blocks them entirely and Chrome has moved to a "User Choice" prompt that makes third-party cookies far too unreliable to depend on for a core platform feature.

**Passing a token in the URL** (`alice-app1.platform.app/?token=xyz`) works, but now your auth token is in browser history, server logs, and potentially referrer headers. Not great.

**Shared cookies across subdomains** would be nice, but `platform.app` is on the [Public Suffix List](https://publicsuffix.org/). The browser treats `alice-app1.platform.app` and `bob-todo.platform.app` as completely separate sites. Meaning, they can't share cookies with each other or any parent domain.

You might think: why not host apps under `platform.io` instead, like `alice-app1.apps.platform.io`? Then cookies could be shared by defining them on `*.platform.io`. But remember, users can install apps from *other* users. If someone publishes an app with an XSS vulnerability, and you install it, that vulnerability now runs in your browser. If apps lived under `platform.io`, that XSS could steal your `platform.io` session cookies, giving an attacker full access to your account, billing, API keys, everything. The PSL isolation is an important security consideration here.

**postMessage + localStorage** is what you'd normally reach for here. The parent sends a token via postMessage, the iframe stores it in localStorage, and JavaScript on each page reads it and attaches it to outgoing requests. But this requires the embedded app to include code that participates in this flow. We don't control what users deploy to their subdomains, they bring their own code. We can't require every app to implement our auth handshake. And to add to that, we already had a lot of apps in use on the platform.

# The Setup

Here's what I had to work with:

1. I controlled `platform.io` (the parent page with the dashboard)
2. Users deployed their own code to `*.platform.app` subdomains
3. I controlled the routing layer for `*.platform.app` at the platform level, which meant I could reserve certain paths (like `/__platform/*`) that the platform handled before user code ever saw the request
4. I did *not* control what users deployed to their apps

That third point is important: even though `alice-app1.platform.app` runs user code, requests to `alice-app1.platform.app/__platform/*` are handled by the platform. This is a common pattern, similar to `/.well-known/` paths for SSL verification or `/_next/` for Vercel internals.

This reserved path was my way in.

# The Idea

Service workers can intercept HTTP requests and modify them, including adding headers. If I could install a service worker on `alice-app1.platform.app`, it could inject an auth token into every request automatically, without the user's app code needing to know about it.

The problem: service workers are origin-scoped. You can only register a service worker from the same origin it will control. I can't register a worker on `alice-app1.platform.app` from `platform.io`.

But I *can* serve a service worker from `alice-app1.platform.app/__platform/v0/embed/`, because I control that path.

As for the flow: to the user, this looks like a standard iframe load. Under the hood, we are running a "bootloader" page:

1. Parent page (`platform.io`) creates an iframe pointing to the bootloader: `alice-app1.platform.app/__platform/v0/embed/`
2. The bootloader registers a service worker with `scope: '/'`.
3. Once the worker is ready, the iframe signals the parent via `postMessage`.
4. Parent sends the auth secret back via `postMessage`.
5. The iframe passes the secret to the service worker, which stores it in `CacheStorage`.
6. Iframe navigates to `/`. Now every request, including the initial document request for the user's app, goes through the service worker, which injects the auth header.
7. User sees their app, authenticated.

# The Code

The key pieces, trimmed down. Full code is in [this gist](https://gist.github.com/seg6/79a2bef9a49c7d6b519ad994a25a7bad).

## Embed Page (The Bootloader)

First, lock down service worker registration so user code can't interfere:

```js
// stage 1
// 1. overload the service worker register function
const register = navigator.serviceWorker.register;

navigator.serviceWorker.register = function(script_url, options) {
    if (script_url == '/service-worker.js') {
        return register.call(navigator.serviceWorker, script_url, options);
    } else {
        return Promise.reject(new Error('embed runtime: registration of custom service workers is not allowed'));
    }
}
```

Then register the worker and set up the handshake:

```js
// stage 2
// 1. register the embed service worker
// 2. register a listener to the current window to receive messages from the parent page
// 3. notify the parent page that the service worker is now activated
navigator.serviceWorker.register('/service-worker.js', { scope: '/' })
    .then(registration => {
        registration.unregister = function() {
            // no-op: unregister does nothing and just resolves
            return Promise.resolve();
        };

        window.addEventListener('message', embed_runtime_parent_handler);

        window.parent.postMessage({
            type:  'service_worker_registered',
            data: null,
        }, 'https://platform.io');
    });
```

When the parent sends the secret, pass it to the service worker:

```js
function embed_runtime_secret_key_handler(event, event_data) {
    fetch('/__platform/v0/embed-handshake', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret_key: event_data.secret_key })
        })
        .then(response => response.json())
        .then(data => {
            if ('redirect' in event_data)
                window.location.href = event_data.redirect;
        });
}
```

## Service Worker

The worker stores the secret and injects it into all same-origin requests:

```js
const SECRET_CACHE_NAME = 'secret-key-cache';
const SECRET_HANDSHAKE_ROUTE = '/__platform/v0/embed-handshake';

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    if (url.pathname === SECRET_HANDSHAKE_ROUTE) {
        event.respondWith(handle_secret_handshake_route(event.request));
    } else if (url.origin === location.origin) {
        event.respondWith(fetch_with_secret_key(event.request));
    } else {
        event.respondWith(fetch(event.request));
    }
});

async function fetch_with_secret_key(request) {
    const cache = await caches.open(SECRET_CACHE_NAME);
    const cached_response = await cache.match(SECRET_HANDSHAKE_ROUTE);

    let secret_key;
    if (cached_response) {
        const cached_data = await cached_response.json();
        secret_key = cached_data.secret_key;
    }

    if (secret_key) {
        const new_headers = new Headers(request.headers);
        new_headers.append('X-Secret-Key', secret_key);
        return fetch(new Request(request, { headers: new_headers }));
    }
    return fetch(request);
}
```

# It Works!

The reserved path gives me a foothold on origins I don't otherwise control. I can't touch user code, but I can serve my own code at `/__platform/*`.

Service workers, once registered, persist across navigations. The worker registers with `scope: '/'`, so it intercepts all requests on that origin, including requests to routes defined by the user's app.

**A note on security:** Because the service worker stores the secret in `CacheStorage`, JavaScript running on the subdomain can technically read it. But since we use unique, per-app secrets, this only "exposes" the app to itself.

## Things to Get Right

If you're implementing something like this:

- **Validate postMessage origins.** We should never accept a secret without checking `event.origin`.
- **Handling Safari/ITP.** Safari may purge Service Workers and CacheStorage if the user doesn't visit the subdomain for 7 days. Because our "bootloader" runs every time the iframe is initialized, it automatically re-registers and re-syncs the secret, making the solution resilient to ITP's aggressive cleanup.
- **Use short-lived tokens.** The injected secret shouldn't be a master key. It should be a session token that the backend can rotate.

---

This came out of a real constraint: I needed seamless auth across origins, couldn't modify user code, and third-party cookies weren't an option. The "reserved path pattern" gave me just enough control to bootstrap a service worker, and the service worker handled the rest.
