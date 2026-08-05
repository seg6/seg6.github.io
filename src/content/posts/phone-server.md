---
title: "my server is a phone now"
description: "rooting a CMF Phone 1 to run my personal infrastructure at home."
date: 2026-08-04
toc: true
---

For a while, my personal infrastructure lived on a small Hetzner VPS. It ran a few web apps, [a remote browser called Surf](/posts/resurrecting-ipad-mini/), Caddy, and the usual supporting cast. Nothing particularly serious. It worked, I just didn't like paying for it.

One of the apps I run, Surf, made the compromise difficult to ignore. The cheapest shared machines were fine until Chrome had real work to do, at which point they felt starved. Dedicated CPU machines fix that, but cost enough each month to make a personal browser feel like a questionable financial commitment.

Buying another machine wasn't an appealing escape hatch either. [DRAM prices have gone completely stupid](https://www.trendforce.com/presscenter/news/20260331-12995.html), so putting together a new box with a comfortable amount of memory felt especially ill timed. I looked at used mini PCs and briefly considered turning my desktop into a server whenever I wasn't using it. Then I remembered the CMF Phone 1 I already own.

Eight ARM cores, 8 GB of RAM, 128 GB of flash, Wi-Fi 6, a 5G modem, and a built in battery backup, that is all attached to an SoC that I feel is overqualified for sitting in a drawer. And I had already paid for it. After dusting it off and playing with it for a while, I decided to turn the phone into the server.

Today it runs Surf and its managed Chrome instance, my personal finance tracker, a screen sharing service, and a handful of smaller web apps. They survive reboots, deploy from Git, and remain reachable when the phone moves between networks, so this is now the machine that actually replaced the VPS.

# the first bad idea: replacing android

The cleanest version of this idea seemed to be flashing a normal Linux distribution. The CMF Phone 1 has a postmarketOS device port, it boots, and the device page has enough green boxes to make a reckless person optimistic. I ended up being that person.

What I paid less attention to was everything marked broken: Wi-Fi, Bluetooth, hardware acceleration, and most of the other things that make the phone useful as a small server. I got as far as the postmarketOS splash screen and a black display. At that point I had neither a server nor a phone.

Recovering stock Nothing OS turned into its own side quest. The flashing utility needed Windows, so I installed Windows in QEMU, fought USB passthrough and MediaTek drivers, watched the flashing tool hang, then eventually moved the process to an actual Windows installation and restored the factory images.

There was a moment in the middle of this where the phone was soft bircked and only showed a black screen and I genuinely thought I had converted a perfectly good device into a paperweight.

It came back, and lesson learned: Android already has working drivers for every piece of this hardware. Wi-Fi, power management, the battery, the GPU, the modem, and every weird vendor detail already work. Throwing all of that away in pursuit of a more conventional userspace was the wrong trade.

I didn't actually need the phone to become a normal Linux machine. I needed it to run Linux applications reliably while Android continued doing the hardware specific work it is good at.

# termux is the host operating system

The second attempt kept stock Android and treated Termux as the host environment.

Termux gives me OpenSSH, runit, Caddy, Cloudflared, package management, and normal enough Unix tooling. Termux:Boot starts the supervisor and SSH after a reboot. Tailscale gives the phone a stable private address, so from any machine on my tailnet I can just run:

```sh
ssh cmf
```

Termux is not a virtual machine. Its processes still execute against Android's Linux kernel, but its Bionic based userspace is different enough from an ordinary Debian installation that existing Linux application images cannot simply be dropped into it. That split ended up being useful, though: Termux could remain the small host control plane while each application brought the Linux filesystem it expected.

The actual services are supervised by runit. Android's battery management is very good at its normal job and very bad for a device pretending to be a server, so I had my Ansible build also apply an Android host profile: it installs a persistent wake lock, disables light and deep idle, exempts Termux, Termux:Boot, and Tailscale from background restrictions, disables the child process limiter, prevents Wi-Fi suspension, and configures Tailscale as the always on VPN.

The recovery chain matters more than any individual setting. Android boots, always on VPN brings Tailscale back, Termux:Boot starts runit, runit starts every resident service, and health checks verify the local and public paths. The phone can reboot without waiting for me to notice.

```text
Android boot
  -> Tailscale always-on VPN
  -> Termux:Boot
  -> runit
  -> resident services
  -> local and public health checks
```

This isn't a conventional Linux server. There is no systemd, no normal Docker daemon, and no reason to pretend otherwise. But it is a Linux kernel with a very capable userland sitting on top of it, and that turns out to be enough.

# the second bad idea: proot

Most of my applications already shipped as Linux ARM64 OCI images. `proot-distro` made those surprisingly easy to run under Debian without changing the applications themselves.

PRoot intercepts filesystem and process operations in userspace and makes a regular Termux process believe it lives inside a Debian root filesystem. It isn't a container boundary. Everything still shares Android's kernel, network namespace, and Termux UID. But as an application compatibility layer, it is extremely useful because it needs neither root nor a special kernel.

The ordinary web services initially ran fine this way. Each of my applications got a verified root filesystem, a loopback port, and a runit service. Caddy ran directly in Termux and routed hostnames to those ports.

The performance/latency sensitive Surf browser workload was the exception. Starting processes, opening libraries, walking paths, reading browser profiles, and shuffling capture data all crossed PRoot's userspace translation layer. There was CPU available, but Chrome could not reach it efficiently. So I rooted the phone, not to replace Android, but to mount the same Debian filesystem properly and enter it with a real `chroot`.

Runit still owned the lifecycle from Termux, configuration still came from the same place, and application data still lived in Termux storage. The workload simply reached Android's kernel through native syscalls instead of PRoot. The improvement was not subtle!

Once that path was solid, leaving the smaller residents under PRoot stopped making much sense. They now run the same way. My workstation resolves each ARM64 image to an exact digest and exports its filesystem; Ansible verifies and installs it on the phone. A small root helper creates a private mount namespace, binds the required paths, enters the filesystem with `chroot`, drops privileges, and starts the original image entrypoint.

Neither Docker nor a compiler needs to exist on the phone. These are still compatibility environments rather than security boundaries: the residents share Android's kernel and network stack, while the private mount namespaces mainly keep mounts and cleanup predictable.

I also spent far too long trying to bridge Debian's graphics stack to the phone's Mali GPU through VirGL and Android Vulkan. I got hardware compositing checkmarks alongside corrupt pages and worse performance... The boring software rendered path turned out to perform better.

# infrastructure! not a pile of shell history

By this point the phone could run everything, but I didn't want a pet server assembled from commands I would forget in a week. I moved the entire host into an Ansible managed state: versions, service definitions, routes, power settings, secrets, and health checks all live in one private repository.

The deployment flow is roughly:

```text
release or OCI image
  -> checksum/digest pinned in Git
  -> Ansible over SSH
  -> versioned files on the phone
  -> atomic current symlink
  -> runit service
  -> local health check
  -> public edge check
```

Releases are pinned by digest or checksum and installed into versioned directories behind an atomic `current` symlink. A failed checksum or health check stops the deployment, rollback means reverting the pin and applying again. Application data lives separately from releases.

After the small manual bootstrap: install the three Android apps, root the phone, grant Termux superuser access, and authorize SSH, the same repository owns the rest. From my workstation, bringing the host to the declared state is deliberately simple:

```sh
make phone
make phone-status
make phone-edge-check
```

Applying it again does not replace unchanged runtime files or restart healthy residents. More importantly, the configuration is useful if this phone dies: another rootable ARM64 phone can be brought toward the same state without reconstructing a shell history.

Secrets are not stored on the phone's Git checkout, because there is no Git checkout. Ansible Vault values live encrypted in the infrastructure repository. The vault password is derived by asking my 1Password SSH agent to sign a fixed challenge, so the private key stays in 1Password and the phone never needs access to it. During deployment, Ansible renders only the runtime values each service needs into Termux's private storage.

# getting traffic to a phone behind home internet

The next problem to tackle was ingress. My home connection does not come with the kind of static server setup a VPS gives you, and I don't want to expose SSH or a collection of random application ports through the router. I also wanted the phone to remain a phone in one important sense: I should be able to unplug it, take it somewhere else, connect it to the internet, and still have my server.

The HTTP applications use a Cloudflare Tunnel. Cloudflared makes one outbound connection from the phone, Cloudflare sends each hostname through it, and Caddy routes the request to the correct loopback service.

```text
Internet
  -> Cloudflare Tunnel
  -> Caddy on 127.0.0.1
  -> application on 127.0.0.1
```

There is no inbound router rule for those services. Cloudflared only needs an outbound connection, so if I move the phone to another network, the tunnel reconnects and the hostnames follow it. Tailscale does the same for administration. The phone's battery can bridge the move, and the public services do not care which Wi-Fi happens to be underneath them.

The Surf remote browser backend needed a different path though. Its direct connection is latency sensitive, terminates its own TLS, and the old iPad that connects to it pins the server identity. At home, Cloudflare DDNS keeps a DNS only record pointed at the current public address and the router forwards one port to Surf. On the LAN, the iPad connects directly to the phone.

That still left roaming. A normal Cloudflare Tunnel terminates TLS at Cloudflare, which is exactly what Surf's pinned connection does not want. The solution was to wrap the complete Surf TLS stream inside an ordinary WebSocket. Cloudflare sees and forwards the WebSocket, but the actual authenticated Surf connection remains encrypted end to end inside it.

This obviously adds latency, from outside home I usually see roughly another network round trip, and the iPad connection was around 60 ms when I first tested it. But it works through a tunnel that only needs outbound connectivity, on an operating system from 2012, without installing Tailscale on the iPad.

That was the moment the phone setup became slightly ridiculous in the best way. I left it plugged in at home, went to the office, SSHed from my MacBook through Tailscale into my workstation and the phone, and used the original iPad through the phone hosted Surf instance. The VPS was no longer, it felt liberating.

# what is actually running

The machine has two layers. Android and Termux own the hardware, networking, ingress, and supervision. The Linux residents get the filesystem they expect and otherwise stay out of the host's way.

| layer | responsibility | pieces |
| --- | --- | --- |
| Android / Termux host | hardware, networking, ingress, supervision | runit, Tailscale, Caddy, Cloudflared, DDNS, operations dashboard |
| rooted Linux residents | application compatibility and workloads | Surf and Chrome, Finances, Screen Share, some other apps |

The demanding workload is Surf, which brings a modern Chromium browser to old iPhones and iPads. The phone runs desktop Chrome (recent arm64 release of Chrome) and the Surf backend inside its Debian runtime, an iPad mini receives H.264 video and audio while sending touch, keyboard, tab, and navigation commands back. Surf is why I cared so much about syscall overhead and latency in the first place.

Alongside it, the phone hosts my personal finance tracker. It records recurring income and expenses, one time transactions, monthly spending limits, and projects my balance forward day by day. Unlike the replaceable application artifacts, its SQLite database contains state I care about, so it has automated off device backups and a tested restore path.

None of those names are baked into some grand "phone server framework." A new resident is another immutable artifact, a runit definition, an explicit data contract, a health check, and optionally a Caddy route.

The latest addition is observability. I can still SSH in, inspect runit, tail logs, check public routes, and query Android directly, but I no longer have to do that merely to see what's going on with the machine at a glance: One native service collects CPU usage for all eight cores, memory, storage, uptime, battery, thermals, local and public reachability, and every discovered runit resident. It keeps bounded history and serves an embedded Vue interface at `https://dash.cmf`, reachable only over the LAN or tailnet.

![dashboard](/img/phone-server/system-dashboard.png)

The log view discovers the same service directories at runtime, so adding another resident doesn't require teaching the UI its name. It is much nicer than SSHing in just to remember which thing was noisy.

# should you do this?

If you already have a reasonably modern, rootable ARM64 phone sitting unused, this is much less ridiculous than it sounds. You get quiet hardware, low power consumption, flash storage, Wi-Fi, a built in display for recovery, and a battery that behaves like a tiny UPS. Stock Android already supports the hardware, while Termux and a rooted chroot are enough to run a surprising amount of normal Linux software.

I would not put irreplaceable data on one without automated off device backups, and I would not treat the chroots as hostile workload isolation. Rooting expands the trust boundary, Android remains an unusual server host, and software rendered desktop Chrome is not going to beat a dedicated workstation with a GPU.

But for a handful of personal services, especially when the alternative is paying indefinitely for a VPS that is either slow or annoyingly expensive, it is a genuinely useful option rather than only a stunt.

The phone is still a weird server. It shares one kernel, Android occasionally needs to be reminded not to "optimize" it, and a future Android update could always create a new surprise.

But it is quiet, battery backed, fast enough, reachable from anywhere, reproducible from Git, and already sitting in my house. I started this trying to save money on a VPS. I ended up with a rooted phone running my personal infrastructure, and somehow that is much more satisfying. :)

---

*Postscript:* This post was [discussed on Hacker News](https://news.ycombinator.com/item?id=49226636). In true HN fashion, a surprising amount of the conversation ended up being about the title. I enjoyed the accidental linguistics thread. :)
