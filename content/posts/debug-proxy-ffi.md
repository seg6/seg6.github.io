+++
title = "Hijacking Chrome's Network Tab to Debug an Electron App"
description = ""
date = 2025-12-26

[extra]
lang = "en"
toc = true
comment = false
math = false
+++

A while back I was working on a local-first productivity app. Think notes, files, AI chat, all running on your machine with no cloud required. The frontend was Svelte running in Electron, but the core of the app lived in a Rust backend compiled as a native Node module using Neon FFI. Storage, search, embeddings, AI inference. All Rust.

The architecture was straightforward: frontend calls JavaScript functions like `js__store_create_resource` or `js__ai_send_chat_message`, those calls cross the FFI boundary into Rust, Rust does its thing with SQLite and ML models and whatever else, and returns the result. Clean separation. Rust handles the heavy lifting, JavaScript handles the UI.

This was a fast-moving project. Early stage, small team, lots of experimentation. Features got added, APIs changed, entire subsystems got rewritten. The kind of environment where you're making decisions on the fly and figuring out the "right" way to do things later. Proper observability? Structured logging? Sure, that was on the roadmap. Somewhere there.

Then the app started hanging.

# Flying Blind

Not crashing. Just... freezing. The UI would lock up for 10, 20, sometimes 30+ seconds. No error messages, no crash reports. Just a stuck app and a user staring at a frozen screen wondering if they should force quit.

And I had no idea what was causing it.

Was it a database query? A file operation? Something in the AI pipeline? The Rust code had grown complex. Worker threads, async channels, SQLite queries, embedding models. Any of it could be the culprit.

Here's the thing about native FFI calls: they're invisible. When JavaScript calls a Rust function, from the browser's perspective, nothing happens. There's no network request. There's no entry in DevTools. The call just... disappears into native land and comes back whenever it feels like it.

I couldn't see what functions were being called. I couldn't see what arguments were passed. I couldn't see how long each call took. The entire Rust backend was a black box.

I could scatter `console.log` statements everywhere. I could add timestamps before and after every call. I could instrument the Rust code with tracing spans. But this was a fire that needed to be out *now*, not after spending a week setting up proper observability infrastructure.

So I wrote a hack.

# Hijacking the Network Tab

Chrome DevTools has a beautiful Network tab. It shows every HTTP request with timing, headers, payload, response. What if I could make my native calls show up there?

The plan:
1. Spin up a local HTTP server in the Electron preload process
2. Wrap every native function with a proxy that makes an HTTP POST instead
3. The server receives the request, calls the *actual* native function, returns the result
4. Now every FFI call shows up in the Network tab

For streaming callbacks (like AI chat responses that come in chunks), I'd use Server-Sent Events to pipe the data back.

# Building It

The app already had a clean initialization pattern. All native functions went through an `initSFFS` function that loaded the native module and wrapped the functions with a handle:

```js
const sffs = require('@deta/backend')

let handle = sffs.js__backend_tunnel_init(
  rootPath, appPath, localAiMode, languageSetting,
  numWorkerThreads, numProcessorThreads,
  eventBusCallback
)

const with_handle = (fn) => (...args) => fn(handle, ...args)

// Normal mode: direct FFI calls
return {
  js__store_search_resources: with_handle(sffs.js__store_search_resources),
  js__ai_send_chat_message: with_handle(sffs.js__ai_send_chat_message),
  // ... etc
}
```

I added a flag: `--enable-debug-proxy`. When set, instead of returning direct wrappers, I'd return HTTP proxy functions.

## Debug Server

```js
const setupDebugServer = () => {
  server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST, GET')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    const [_, fn, action, callId] = req.url.split('/')

    if (req.method === 'GET' && action === 'stream') {
      handleSSE(res, callId)
    } else if (req.method === 'POST') {
      handlePostRequest(req, res, fn)
    } else {
      res.writeHead(404)
      res.end()
    }
  })

  server.listen(0, 'localhost', () => {
    console.log(`Debug server running on port ${server.address().port}`)
  })
}
```

Nothing fancy. A basic HTTP server that routes POST requests to function calls and GET requests to SSE streams.

## Proxy Functions

Instead of calling the native function directly, the proxy makes an HTTP request:

```js
const createProxyFunction = (key) => {
  return async (...args) => {
    const isChat = key === 'js__ai_send_chat_message'
    const callId = isChat ? Math.random().toString(36).slice(2, 11) : undefined

    if (isChat) {
      setupSSE(key, callId, args[2]) // args[2] is the callback
    }

    const response = await fetch(`http://localhost:${server.address().port}/${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args, callId })
    })

    if (!response.ok) {
      throw new Error(`HTTP error status: ${response.status}`)
    }

    return response.json()
  }
}
```

The server receives this, calls the real native function, and returns the result:

```js
const handlePostRequest = (req, res, fn) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const { args, callId } = JSON.parse(body)
    try {
      if (fn === 'js__ai_send_chat_message') {
        args[2] = createProxyCallback(callId)
      }
      const result = await sffs[fn](handle, ...args)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: error.message }))
    }
  })
}
```

## Streaming Callbacks via SSE

Some functions take callbacks. AI chat, for example, streams responses chunk by chunk. I couldn't just serialize a callback function over HTTP.

The solution: Server-Sent Events. Before making the POST request, the client opens an SSE connection. The server replaces the original callback with one that emits to the SSE stream:

```js
const handleSSE = (res, callId) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  })

  const emitter = new EventEmitter()
  callbackEmitters.set(callId, emitter)

  emitter.on('data', (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`)
  })

  res.on('close', () => {
    callbackEmitters.delete(callId)
  })
}

const createProxyCallback = (callId) => {
  return (data) => {
    const emitter = callbackEmitters.get(callId)
    if (emitter) emitter.emit('data', data)
  }
}
```

On the client side, an EventSource listens for these events and calls the original callback:

```js
const setupSSE = (key, callId, originalCallback) => {
  const eventSource = new EventSource(
    `http://localhost:${server.address().port}/${key}/stream/${callId}`
  )

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data)
    originalCallback(data)
  }

  eventSource.onerror = () => {
    eventSource.close()
  }
}
```

## Putting It Together

The initialization now branches based on the debug flag:

```js
return {
  ...Object.fromEntries(
    Object.entries(sffs)
      .filter(([key, value]) =>
        typeof value === 'function' &&
        key.startsWith('js__') &&
        key !== 'js__backend_tunnel_init'
      )
      .map(([key, value]) => [
        key,
        ENABLE_DEBUG_PROXY ? createProxyFunction(key) : with_handle(value)
      ])
  ),
  js__backend_event_bus_register
}
```

Same API surface. When debug proxy is off, direct FFI calls. When it's on, everything goes through HTTP.

# What I Found

With `--enable-debug-proxy`, I opened DevTools and watched my Network tab light up:

- `POST /js__store_search_resources` - 847ms
- `POST /js__store_get_resource` - 12ms
- `POST /js__store_search_resources` - 23,847ms ← there's the problem

I could see exactly which function was hanging, what arguments were passed, and how long each call took.

The 23-second search had a malformed query that was causing a full table scan. Found it in minutes, fixed it, moved on.

![Network tab showing FFI calls](/img/debug-proxy-ffi/network-tab.png)

![Inspecting the payload](/img/debug-proxy-ffi/network-tab-payload.png)

---

Sometimes the right debugging tool is the one you build yourself in a moment of frustration. The hack stuck around and became a real feature and the rest of the team started using it too :)
