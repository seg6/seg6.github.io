---
title: "more people should build browsers"
description: "i want to see more strange browsers"
date: 2026-10-31
toc: true
---

I think more people should build browsers.

Not necessarily browsers that compete with Chrome, or browsers that try to do everything. Small browsers. Strange browsers. Browsers built around a particular way of reading, working, researching, or just moving around the internet.

<figure class="juno-demo" id="juno-demo" data-video-demo>
  <div class="juno-demo-stage">
    <video
      controls
      playsinline
      preload="none"
      poster="/media/juno/paper-machine.webp"
      width="1920"
      height="1080"
      aria-label="juno demo: folding websites into a paper concertina and opening them again"
      aria-describedby="juno-demo-caption"
    >
      <source src="/media/juno/paper-machine.mp4" type="video/mp4" />
      <a href="/media/juno/paper-machine.mp4">Watch the juno demo.</a>
    </video>
    <button
      class="juno-demo-play"
      type="button"
      data-video-play
      hidden
      aria-label="play juno demo with sound"
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M4 2.5 13 8l-9 5.5z" />
      </svg>
      <span>play with sound</span>
    </button>
  </div>
  <figcaption id="juno-demo-caption">
    <span><strong>juno</strong>, a strange browser.</span>
    <span>playing: ready/problems by boy pablo</span>
  </figcaption>
</figure>

There are probably quite a few good ideas about browsing that nobody has tried yet. Not necessarily because they're impossible, but because building a browser is a fairly unreasonable thing to ask someone to do.

You need access to a rendering engine, of course. But you also need to deal with what's above it: navigation, profiles, permissions, downloads, popups, session restoration, and the security boundary between websites and your application. A lot of work stands between having an idea about how browsing should feel and getting to try it with real websites.

That work makes sense for the companies building general purpose browsers. It makes much less sense for someone who just wants to find out whether a different way of organizing pages might be useful, or interesting.

I'd like to see that distance being shorter. And I think using Electron is a reasonable way to do it.

I didn't arrive at that from the outside. Before this, I worked on [Surf](https://deta.surf), a research browser built on Electron. A decent amount of the discourse around it came down to two complaints: Electron is bloated, or a browser built on it can't be made safe. Both are fair questions, and they deserve better answers than "it's fine, actually." This post is my attempt at those answers, and at describing what I'd want the next person building a strange browser to start with.

# the browser is more than its engine

When people talk about building a browser, much of the conversation gravitates toward the engine. Chromium, Firefox, WebKit, and the massive amount of engineering work involved in keeping the modern web working.

That's important work, and it's also work that most people experimenting with browsing interfaces have no particular reason to redo.

A thought experiment: Suppose you're trying to make research feel less like collecting tabs indefinitely.

You're reading three articles about the same subject. You want to take a paragraph from one, maybe keep the source attached, put it beside a note, and return to the whole arrangement tomorrow. Maybe the useful unit in your browser is the research project, with its pages, files, and notes living together.

Or maybe you want a browser built entirely around keyboard navigation. Or one where websites live on a spatial canvas. Or something that treats browsing as a collection of trails you can leave and return to.

These are substantial changes to the browsing experience. But none of them necessarily require changing how Chromium renders a website.

Most of the interesting work, in this context, lies above the engine. The issue is that you still need the machinery underneath those experiments. And getting that machinery into a usable state can consume much of the time you wanted to spend on the idea.

# the cost of trying something weird

I think this has consequences for the kinds of browsers we get.

When building something requires a large investment of time and resources, you're naturally more careful about what you choose to build. You want evidence that people will use it. You want a recognizable product, a plausible audience, and some confidence that the work will pay off.

Those aren't bad instincts, they're fairly reasonable responses to expensive development. But some ideas are difficult to evaluate before you've actually used them.

You might invent a new way to arrange pages, spend a week living with it, discover that it's irritating, and throw half of it away. And then you might try something completely different. That kind of experimentation is much easier when the cost of getting started is low.

We've seen how much accessible development tools can change other areas of software. Game engines let small teams concentrate on the game they want to make instead of writing a renderer first (not necessarily a fan of what's out there, but you get the idea).

In a similar fashion, web frameworks make it practical to build and discard application ideas without implementing the same infrastructure every time (definitely not a fan of what's out there).

Making something easier to build doesn't guarantee that people will invent wonderful things with it. But it changes who can participate, how many experiments are affordable, and how unusual those experiments can be.

I strongly believe that browsers would benefit from more of that.

# yes, electron

Electron has an understandable reputation problem. Say you're building something with it and the conversation can reach RAM usage before you've explained what the thing does.

Some of that criticism is deserved. I've used plenty of desktop applications that seem to need a small data center to display a list of items. I would also like my computer to have some memory and processing power left for whatever else I was actually doing.

But a browser is a particularly interesting place to make the usual complaint! You're shipping an entire browser engine! Yes. That was going to come up somewhere in the implementation.

If you've chosen Chromium, Electron gives you a way to embed it and build the surrounding application with web technologies.

Rendering websites is already the central workload. HTML, CSS, JavaScript, networking, media, and the machinery needed to run the modern web were going to be part of the application regardless of how you drew the tab bar.

Electron also [inherits Chromium's multiprocess architecture](https://www.electronjs.org/docs/latest/tutorial/process-model). A privileged main process manages the application and its renderers. The renderers display web content. There's a recognizable browser architecture underneath the desktop application framework.

More concretely, [WebContentsView](https://www.electronjs.org/docs/latest/api/web-contents-view) gives you website contents you can position and manage separately from your interface. Electron exposes APIs for navigation, sessions, permissions, popups, and downloads, alongside menus, dialogs, and desktop integration.

You still have to implement quite a deal of browser behaviors. Electron doesn't hand you a complete browser, rather it gives you useful building blocks without requiring a Chromium fork.

And you can build the surrounding interface in Svelte, Vue, or another web framework, inspect it with familiar tools, and change the interaction without waiting for a large native build.

That's particularly valuable when you don't yet know what the interface should be.

Surf worked this way. It had a Svelte interface and a native core written in Rust: storage, search, embeddings, and AI work lived in Rust, while Electron connected the interface to those capabilities. (Some of what it took to debug that arrangement ended up in [my post about native Electron calls](/posts/debug-proxy-ffi/).)

I like that arrangement because it lets me spend more time on the behavior I'm trying to create. I can experiment with an interface, replace it, or throw it away without replacing the machinery underneath.

And I don't think an Electron browser has to be considered a prototype waiting to be rewritten in a more respectable stack. If it performs well, handles untrusted content safely, and meets the requirements, it can simply be the browser.

# node still has a cost

None of this means Electron is free.

Electron also brings Node, and the runtime and application code running in it have real costs. Loading dependencies takes time. Large JavaScript object graphs take memory and eventually need garbage collection. Moving data between processes and repeatedly serializing it can become expensive, and believe me, it does become expensive.

Properly sandboxed website renderers don't each initialize their own Node environment, but the privileged side of the application still has work to do. You can make that part much heavier than it needs to be.

Opinion formed through experience, for substantial computation and large collections of state, I'd keep Node focused on orchestration and move the expensive work into a native core when profiling justifies it. For me, that usually means Rust.

That's what [Neon](https://neon-rs.dev/) was useful for in Surf. The Rust core was compiled into a native Node module, with JavaScript calling a defined set of functions. If your implementation or an existing library is in C++, [Node-API](https://nodejs.org/api/n-api.html) provides a native addon interface for that too. Neon is specifically the Rust option.

For local search, that might mean keeping the index and its working memory in Rust, then returning the results the interface needs. A search is a useful operation to expose across that boundary. Thousands of tiny calls that repeatedly allocate and convert objects would rather defeat the point.

The point isn't that Electron has no overhead. It's that the development advantages may be worth the overhead for the browser you're trying to make.

# making browsers easier shouldn't make them less safe

There's a much more serious objection towards using Electron to build a browser than memory use.

A browser deliberately runs code written by strangers. Some of those strangers, and nowadays, maybe AI agents as well, would like access to your machine.

Electron adds native capabilities through Node, preloads, and IPC. Exposing those capabilities carelessly is dangerous. Its own [security documentation](https://www.electronjs.org/docs/latest/tutorial/security) says that "Electron is not a web browser" and explicitly warns about displaying arbitrary untrusted content.

Electron's warning is meant to be taken very seriously, but it doesn't mean Electron is fundamentally unsuitable for building a browser. It means that embedding arbitrary websites requires a security model that Electron doesn't implement for you. The mechanisms for isolating untrusted content are there, the responsibility for applying them consistently belongs to the browser.

A tab navigates. A page redirects. A login flow opens another window. A saved HTML file gets a preview. Every one of these needs a clear answer about what code is running and what it can access.

Imagine giving an internal notes page access to your resource database through a preload. Then imagine navigating that same view to a remote website while leaving the privileged preload attached. The original separation might've initially looked reasonable, but clearly, the navigation behavior defeated it.

Permissions need the same care as well. Grants belong to a browsing profile and requesting origin, with the embedding site considered for cross-origin frames. Both [permission checks and requests](https://www.electronjs.org/docs/latest/api/session#sessetpermissioncheckhandlerhandler) need to consult the same authority. A prompt is useless if the check handler has already granted access.

Privileged IPC needs to validate the sending frame, its exact origin, and the request itself. Filesystem access, downloads, screen capture, and native integrations need explicit boundaries rather than convenient shortcuts.

I'd want tests that actively try to cross those boundaries through navigation, popups, and embedded content. Giving a website a new native capability should require careful review.

This is also part of what making browser development accessible ought to mean.

People shouldn't have to rediscover every dangerous edge case independently just to explore a different interface. Good reusable browser infrastructure could take responsibility for much of that machinery and provide carefully constrained ways to extend it.

# the fork has a maintenance bill too

There are good reasons to work directly on Chromium.

You might need changes deep inside the engine, control over behavior Electron doesn't expose, or integration that becomes awkward through an embedding API. Extension compatibility is one concrete limitation: Electron supports only a [subset of Chrome's extension APIs](https://www.electronjs.org/docs/latest/api/extensions). If compatibility with existing Chrome extensions is essential, Chromium's browser infrastructure becomes a much more reasonable foundation.

But owning a fork comes with its own costs.

Your changes need to survive upstream updates. Builds, packaging, platform differences, regressions, and security fixes become part of the work. Those obligations can consume a great deal of time, particularly for a small team.

There's also the middle option of a native shell around [CEF](https://github.com/chromiumembedded/cef), which supplies Chromium embedding APIs and prebuilt distributions. You don't need to maintain a Chromium fork to use it, and you can host a web interface there too.

The choice depends on what the application needs. Electron offers a familiar development environment and integrated desktop APIs, at the cost of Node's additional runtime and the constraints of Electron's Chromium integration.

I wouldn't choose Electron for every browser. But I would compare those maintenance costs against the work I actually wanted to do.

Maintaining a Chromium fork to rearrange tabs and experiment with a different reading workflow could be a very expensive way to acquire access to code I barely intended to touch.

# build the boring parts once

This is what led me to put together `koto`, a reusable browser core built on Electron.

The idea is to take the machinery that keeps appearing in browser projects: website views, profiles, navigation, permissions, downloads, session persistence, and the boundary between websites and the application. And then make it available without prescribing the interface around it.

The core doesn't depend on a particular UI framework. It doesn't decide whether pages should appear as tabs, panes, cards, or something else. An application supplies the interface and uses the core to manage actual websites.

It also doesn't assume a database, a search implementation, or a native language: those choices belong to the application.

As a fun experiment, to try out `koto`, I put together the browser that you saw the demo of earlier: **juno**, where websites become sheets in a hinged paper concertina. You pull a sheet open and it becomes an interactive website. Fold it away and it becomes part of the stack.

I don't think folding websites into a paper machine is necessarily the future of browsing.

That's rather the point.

I wanted to be able to build something unusual without spending the entire project implementing the browser around it. And I wanted the underlying machinery to be useful for someone else's completely different idea.

Koto is extremely early work. There are still important responsibilities around security review, performance, packaging, and updates. But it has been a useful way to explore the question that motivated this post: how much of the difficult browser work can be made reusable, so that people can spend their time experimenting with what browsing could be?

# more people should get to try

I spend a lot of time thinking about the friction between deciding to do something and getting the computer to cooperate.

A browser sits directly in that path for an enormous amount of work. It shapes how we find information, move between tasks, preserve context, and interact with software.

And yet the familiar collection of tabs, an address bar, and a few panels is still the dominant way we organize all of that activity.

I'm not convinced we've exhausted the possibilities.

Maybe the next useful idea comes from a team building a research browser. Maybe it comes from someone who wants a better way to read. Maybe it's a tiny personal project made by someone who finds conventional browser interfaces annoying in a very specific way.

Most experiments won't become successful products. Some won't even be particularly useful. And that's entirely fine. Making experimentation cheaper means we can afford to discover what doesn't work, too.

I'd like browser development to become something more people can reasonably attempt, rather than something that requires the resources of a browser company before the interesting work can begin.

This is not because we need another hundred versions of Chrome. Because I'd like to see what people come up with when building a browser stops being the hard part.
