---
title: "yes, i'd build a browser in electron"
description: "chromium is a fairly reasonable dependency when the thing you're building is a browser."
date: 2026-10-31
toc: true
---

Electron has a reputation problem. Say you're building something with it and the conversation can reach RAM usage before you've explained what the thing does.

Some of that criticism is deserved. I've used plenty of desktop applications that seem to need a small data center to display a list of messages. I would also like my computer to have some memory left for whatever I was actually doing.

But a browser is a particularly funny place to make the usual complaint. You're shipping an entire browser engine! Yes. That was going to come up somewhere in the implementation.

I think Electron is a reasonable foundation for a browser, including one you intend people to use every day. The security work is substantial, and there are good reasons to choose something else. There is also a fairly strong case for choosing it on purpose.

# you were going to need chromium anyway

Well, a browser engine, at least. If you've chosen Chromium, Electron gives you a way to embed it and build the surrounding application with web technologies.

This is a much better fit than the RAM joke suggests. Rendering websites is already the central workload. HTML, CSS, JavaScript, networking, media, the machinery needed to run the modern web: you were going to bring a lot of this along regardless of how you drew the tab bar.

Electron also [inherits Chromium's multiprocess architecture](https://www.electronjs.org/docs/latest/tutorial/process-model). A privileged main process manages the application and its renderers. The renderers display web content. There is a recognizable browser architecture underneath the desktop application framework.

More concretely, [WebContentsView](https://www.electronjs.org/docs/latest/api/web-contents-view) gives you website contents you can position and manage separately from the interface. Navigation, popups, sessions, permissions, and downloads have APIs the application can work with. You get those alongside menus, dialogs, and the rest of the desktop integration. That's the part I'd choose Electron for: having the browser surfaces and the surrounding application in one familiar development environment. You still have to decide how they behave.

It also doesn't make the overhead disappear. Your interface can still be wasteful, you can keep too many views alive, and you can accidentally make switching tabs an exercise in memory allocation. I don't have a comparative benchmark against an equivalent native shell, so I can't claim comparable memory use or startup time. A fair comparison would need the same pages and hardware, including a busy tab session and the cost of suspending and restoring tabs.

# the interesting part might be above the engine

Suppose you're trying to make research feel less like collecting tabs indefinitely.

You're reading three articles about the same subject. You want to take a passage from one, keep the source attached, put it beside a note, and return to the whole arrangement tomorrow. Maybe the useful unit in your browser is the research project, with its pages, files, and notes living together.

That's a fairly substantial change to how a browser feels. Most of the experiment concerns navigation, state, layout, storage, and interaction. You need a dependable engine underneath it, and a way to keep changing the surrounding experience until it works.

This is where Electron becomes interesting to me. You can build that interface in Svelte or another web framework, inspect it with familiar tools, and try a different interaction without first becoming an expert in a large browser codebase.

I've worked on this kind of application. The project behind [my post about debugging native Electron calls](/posts/debug-proxy-ffi/) had a Svelte interface and a native core written in Rust. Storage, search, embeddings, and AI work lived in Rust. Electron provided the environment connecting the interface to those capabilities.

That matters when the interaction itself is still an open question. You might need to implement an idea, use it for a week, realize that it is annoying, and throw half of it away. Making that cycle affordable changes how much you're willing to try.

And I think more people should be able to participate in those experiments. Someone with good ideas about reading, organizing information, or keyboard navigation should have a reasonably short path from an idea to a working browser they can live in. There is a lot of useful work available above the rendering engine.

# node still has a cost

The Chromium argument only gets you so far. Electron also brings Node, and the runtime and the application code running in it have real costs. Loading dependencies takes time. Large JavaScript object graphs take memory and eventually need garbage collection. Moving the same data between processes and repeatedly serializing it can become expensive.

Properly sandboxed website renderers don't each initialize their own Node environment, but the privileged side of the application still has work to do. You can make that part much heavier than it needs to be.

For substantial computation and large collections of state, I'd keep Node focused on orchestration and move the work into the native core. For me, that usually means Rust, guided by where the profiles show the cost.

That's what [Neon](https://neon-rs.dev/) was useful for in the application I mentioned earlier. The Rust core was compiled into a native Node module, with JavaScript calling a defined set of functions. If your implementation or an existing library is in C++, [Node-API](https://nodejs.org/api/n-api.html) provides a native addon interface for that too. Neon is specifically the Rust option.

For local search, that means keeping the index and its working memory in Rust, then returning the results the interface needs. A search is a useful operation to expose across that boundary. Thousands of tiny calls that repeatedly allocate and convert objects would rather defeat the point.

You also have to get the threading right. A synchronous Rust function can block Electron's main thread just as effectively as a JavaScript function. The expensive work needs to run on worker threads or in another process, with the result delivered asynchronously. Changing the implementation language doesn't move the work to a different thread for you.

The same Rust core could sit behind a native shell. Here it lets me keep the development environment I like while moving substantial work out of JavaScript. Node's baseline overhead remains, and managing the lifetime of website tabs is still a separate problem. I'd [profile](https://www.electronjs.org/docs/latest/tutorial/performance) the result before making claims about the savings.

# yes, the security objection is serious

A browser deliberately runs code written by strangers. Some of those strangers would quite like access to your files.

Electron adds native capabilities through Node, preloads, and IPC. Exposing those capabilities carelessly is dangerous. Its own [security documentation](https://www.electronjs.org/docs/latest/tutorial/security) says that "Electron is not a web browser" and explicitly warns about displaying arbitrary untrusted content. That warning belongs in this discussion.

The protections do exist. Electron supports [sandboxed renderers](https://www.electronjs.org/docs/latest/tutorial/sandbox), where privileged operations have to be delegated through controlled communication. Context isolation separates a page's JavaScript environment from the preload's environment. Disabling Node integration keeps Node APIs out of the website's JavaScript context. These address different parts of the problem; having one enabled doesn't make the others redundant.

The difficult work is preserving those protections through everything the browser can do.

A tab navigates. A page redirects. A login flow opens another window. A saved HTML file gets a preview. A generated app wants to become interactive. Each of these needs a clear answer about what code is running and what it is allowed to access.

Imagine giving an internal notes page access to your resource database through its preload. Then imagine navigating that same view to a remote website while leaving the privileged preload attached. The original division between internal pages and websites looked reasonable. The navigation behavior defeated it.

I'd keep privileged interface views permanently assigned to that role, with external pages opening in separate, sandboxed views. Saved HTML and generated apps belong on the untrusted side too. Redirects and popups need to preserve that separation. A few reassuring settings in the constructor don't establish that the rest of the application does.

Permissions need the same care. Grants belong to a browsing profile and requesting origin, with the embedding site considered for cross-origin frames. Both [permission checks and requests](https://www.electronjs.org/docs/latest/api/session#sessetpermissioncheckhandlerhandler) need to consult that policy. A prompt is useless if the check handler has already granted access. Privileged IPC also needs to validate the sending frame, its exact origin, and the request itself.

I would want the privileged surface to stay small, the permissions to be explicit, and tests that try to cross the boundary through navigation, popups, and embedded content. A new layout should be easy to experiment with. Giving a website a new native capability should require careful review.

There will still be features that cross both areas. File uploads, downloads, page capture, and integrations all do. You have to account for that in the design rather than gradually exposing the entire native core to make the interface convenient.

Whether a particular browser gets this right takes testing and security review. I find those much more useful than deciding how safe it is from the framework name in its package file.

# the fork has a maintenance bill too

There are good reasons to work directly on Chromium. You may need changes deep inside the engine, control over behavior Electron doesn't expose, or integration that becomes awkward through an embedding API. At some point, those requirements can justify owning a fork.

Extension compatibility is one concrete limit: Electron supports only a [subset of Chrome's extension APIs](https://www.electronjs.org/docs/latest/api/extensions). If broad compatibility with existing Chrome extensions is central to the browser, that weighs heavily in favor of starting from Chromium's browser infrastructure.

That ownership has a cost. Your changes need to survive upstream updates. Builds, packaging, platform differences, and regressions all become part of the work. A small team has to decide how much of its time it wants to spend there.

There is also the middle option of a native shell around [CEF](https://github.com/chromiumembedded/cef), which supplies Chromium embedding APIs and prebuilt distributions. You don't need to maintain a Chromium fork to use it, and you can host a web interface there too. The comparison then comes down to the application integration Electron provides and whether it's worth Node's additional cost to your project.

Electron moves some of that work upstream, and introduces its own dependency. You depend on its Chromium integration, exposed APIs, and release process. Its [support policy](https://www.electronjs.org/docs/latest/tutorial/electron-timelines) covers a limited set of recent releases, so upgrades have to remain part of normal development and reach users through a maintained update channel. Shipping an old engine indefinitely would undermine the whole argument.

I would compare those maintenance costs against the changes I actually needed to make. Maintaining a Chromium fork to rearrange tabs and build a better reading workflow could be a very expensive way to acquire access to code I barely intended to touch.

# i'd like more people to try

I spend a lot of time thinking about the friction between deciding to do something and getting the computer to cooperate. A browser sits directly in that path for an enormous amount of work. Small improvements to navigation or context can make a surprising difference when you use them all day.

There should be room for more people to explore that space. Especially small teams with a particular idea about how they want to use a computer, and enough stubbornness to make a browser around it.

Electron can lower the cost of doing that. The resulting browser still has to earn trust, perform well, handle hostile content, and keep up with security updates. Those are ongoing responsibilities for anyone shipping one.

But I don't think you have to treat the result as a prototype waiting to be rewritten in a more respectable stack. If it meets the requirements, it can simply be the browser.

I would happily choose Electron for that job. And then spend the time I saved trying to make the browser worth using.
