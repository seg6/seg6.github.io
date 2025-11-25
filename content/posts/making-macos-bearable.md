+++
title = "Making macOS Bearable"
description = ""
date = 2025-12-09

[extra]
lang = "en"
toc = true
comment = false
math = false
+++

# Intro

Ideally, a computer system should feel like an extension of your body. When you pick up a cup of coffee, you don't consciously think, "I need to engage my bicep, extend my forearm, and grasp with my fingers." You just think "drink coffee," and your body complies.

I've spent the better part of eight years on various flavors of Arch Linux, and over that time I settled into a local minimum: a system configuration where I can enter a flow state, forget I'm using a computer at all, and just focus on the work. The machine disappears.

Recently, I started using macOS (my workplace issued me an M4 Pro MacBook, and I can't yet put Asahi Linux on it), and with this change, that neural link was severed. Stock macOS gives me something like motion sickness whenever I try to accomplish anything. There's just too much friction in Spaces, Mission Control, window management, all of it.

So I set out to fix this for myself.

# The "Where's Waldo" Problem

Apple wants you to use Mission Control. They want you to swipe up with three fingers, see a scattered mosaic of every window you have open, and then use your eyes to scan for the one you want.

![mission control](/img/macos-bearable/mission-control.png)

**This is terrible!!!**

Visual search is the most expensive cognitive task you can perform while focused on doing something. Every time you have to scan the screen to find a window, you are breaking context.

My hierarchy of navigation is as follows:
1.  **Shortcuts:** I know exactly where something is. I press a key, and I am there.
2.  **Fuzzy Finding:** I know *what* I want, but not where it is. I type three letters into Raycast, and it appears.
3.  **Visual Search:** This is the fallback I try to never use.

# Encoding Location with Aerospace

The default macOS window model is "floating." Windows pile on top of each other, you drag them around manually, and Spaces lets you swipe between virtual desktops that have no enforced structure. It's flexible, but flexibility without constraints is just chaos.

To fix this, I use Aerospace. It's a tiling window manager that replaces the native "Spaces" concept with rigid, deterministic workspaces.

![aerospace](/img/macos-bearable/aerospace.png)

Aerospace allows me to spatially encode my software. I don't need to "check" where Spotify is. Spotify is on Workspace 9. Always. My browser is on Workspace 1. My terminal is on Workspace 2.

```toml
[workspace-to-monitor-force-assignment]
7 = 'secondary'
8 = 'secondary'
9 = 'secondary'

[[on-window-detected]]
if.app-id = 'com.mitchellh.ghostty'
run = 'move-node-to-workspace 2'
```

This turns navigation into muscle memory. `Cmd-2` is not "Switch to Terminal"; `Cmd-2` is just the physical reflex of "I want to code." I don't look. I just hit the key combination, and the active workspace changes.

# Development Workspace

Inside Workspace 2 lives Ghostty, running Tmux.

But standard Tmux keybinds are too clunky. The default `Ctrl-b` prefix doesn't spark joy to use. I use root bindings (`-n`) to bypass the prefix entirely where I see it fit.

I don't use panes; I use full windows as "views." `Alt-1` switches to the first window. `Alt-2` switches to the second. But here is the logic that makes it flow:

```tmux
bind -n M-1 if-shell 'tmux select-window -t 1' '' 'new-window -t 1'
```

If window 1 doesn't exist, it creates it. I don't "manage" windows; I just go to where I want to be, and the system accommodates me.

To glue it all together, I wrote a custom Rust tool called `ws`.

![ws session switcher in action](/img/macos-bearable/ws.gif)

When I hit `Alt-s`, a fuzzy finder pops up *over* my current work. I pick a project, and `ws` instantly attaches to that session or spins up a new environment with my editor (`helix`) and file manager (`fx`) ready to go. It maintains a stack-based history, so I can jump to a project, fix a bug, and hit "Back" to return to exactly where I was.

# The Language of Motion

Humans are incredibly good at language. We are hardwired for syntax, grammar, and structure. We are *not* hardwired to hunt for pixels on a glowing rectangle.

This is why I use modal editing. It stops text manipulation from being a manual labor task, e.g. dragging a mouse, holding backspace, and turns it into a conversation. If I want to change the text inside some quotes, I don't drag a cursor; I speak the command: `ci"` (change inside quotes). It is linguistic. I am speaking to the editor in a language we both understand.

The problem with modern OS design is that it abandons this linguistic efficiency for visual clutter.

# Bypassing the Mouse

Of course, I still use the mouse. I’m not a zealot. But for 90% of web browsing, lifting my hand to the mouse is unnecessary friction.

I use Vimium in the browser.

![vimium](/img/macos-bearable/vimium.png)

When I want to click a link, I don't aim; I just look at it. Two letters appear over the link, I type them, and it clicks. It feels telepathic. I look at the element, and the element activates.

I recently added Homerow to the mix, which brings this same "look and type" navigation to the entire macOS UI. It allows me to click system dialogs or toolbar buttons without ever leaving the home row.

---

By layering Aerospace, Tmux, and modal editing, I’ve tried to replicate that "extension of the body" feeling. The goal isn't to be a "power user" for the sake of it. The goal is to remove the lag between thinking "I want to do X" and the computer actually doing it.

The [dotfiles](https://github.com/seg6/dotfiles/tree/macbook) and the relevant [Hacker News](https://news.ycombinator.com/item?id=46213385) discussion.
