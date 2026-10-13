---
title: "a teenage programmer's hall of fame of questionable cleverness"
description: "some code from my teenage years, back when being clever was half the fun."
date: 2026-10-13
toc: true
---

I recently came across an archive of projects I wrote as a teenager. Some of them date all the way back to 2017, when I was fifteen, and a surprising amount has survived through old GitHub repositories, forks, and backups.

There's a little bit of everything in there: a C++ editor written in Python, a Raspberry Pi-powered RC car, a software renderer, a cryptosystem, an interpreter, and quite a few questionable experiments from my self-proclaimed hacker era. I had a lot of free time, apparently.

Going through the code reminded me of just how obsessed I used to be with finding clever ways to accomplish things. Not necessarily the simplest or most readable way, but something that made me feel like I'd discovered a secret feature of the language. I particularly enjoyed finding ways to express complicated things in as little code as possible, often at the expense of anyone who might have to read it later. That includes me, unfortunately.

Python, being Python, was more than happy to enable this behavior.

So here's a little collection of some of my favorites. Most of them have absolutely no business being written this way, but I still find them rather amusing.

## parsing ini files without a parser

One of my projects was a Raspberry Pi-based RC car called Cartoon. It had an HTTP server, GPIO-controlled motors, MJPEG camera streaming, and three different clients: Android, desktop, and web. It also had a configuration file.

Python already came with `ConfigParser`, which could have handled the whole thing, but apparently that wasn't interesting enough. So I wrote my own:

```python
def parse_config(data):
    data = re.split('\[(.*?)\]\n', data)[1:]
    data = dict(map(list, zip(*[data[_::2] for _ in range(2)])))

    for sect, vals in data.items():
        vals = re.findall('\w+', vals)
        data[sect] = dict(zip(*[vals[i::2] for i in range(2)]))

    for sect, vals in data.items():
        for key, val in vals.items():
            if val.isdigit():
                data[sect][key] = int(val)

    return data
```

I particularly like this line:

```python
dict(map(list, zip(*[data[_::2] for _ in range(2)])))
```

What an absolute beauty.

The idea is pretty simple, actually. The regex splits the input into alternating section names and contents. Extended slicing lets me take every second element, starting at either index zero or one, which I then pair using `zip`, convert to lists, and pass into `dict`.

And then I do essentially the same thing again to parse the individual key-value pairs. I guess once I figured out that `seq[::2]` and `seq[1::2]` could be used to separate alternating sequences, I was determined to make the entire parser revolve around it.

Does it handle the INI format correctly? Of course not. But it understood my configuration file, and I got to use a bunch of neat Python features along the way. Good enough.

## serialization, courtesy of regex and eval

Around the same time, I was experimenting with writing a software 3D renderer in Python. I had a custom file format for describing shapes, containing vertices and faces, with each face referencing vertex indices and carrying a hexadecimal color.

Naturally, I needed a way to load those files.

```python
@classmethod
def load(cls, file_name, pos=(0, 0, 0)):
    return cls.loads(open(file_name, 'r').read(), pos)

@staticmethod
def loads(data, pos=(0, 0, 0)):
    load = lambda f, expr, data: list(map(f, findall(expr, data)))
    return Shape(**{
        'pos'      : pos,
        'points'   : load(eval, '\((.*?)\)\n', data),
        'face_data': load(lambda d: (eval(d[0]), d[1]), '\((.*?)\); #(\w+)', data)
    })

def dump(self):
    return '// points\n{points}\n\n// face_data\n{face_data}'.format(
        points   ='\n'.join(map(str, self.points)),
        face_data='\n'.join('{}; #{}'.format(d, c) for d, c in self.face_data)
    )
```

There's quite a bit to unpack here. Literally.

The `load` lambda takes a transformation function, a regular expression, and some data. It extracts matching values and applies the transformation to each one. For vertices, that transformation is simply `eval`. For faces, it's another lambda that evaluates the vertex indices and pairs them with a color.

Then, for reasons known only to my teenage self, I construct a dictionary containing the exact arguments expected by `Shape.__init__`, only to immediately unpack it with `**`.

A miniature serialization framework, powered by regular expressions, higher-order functions, and the Python interpreter itself. The `dump` method isn't much better, with its nested `join`, `map`, and formatting expressions.

Yes, `eval` is a terrible idea for parsing untrusted input. Thankfully, the only person writing these shape files was me, and I was mostly interested in seeing how much functionality I could squeeze into a few lines.

## the camera movement incident

This next one is perhaps my favorite, mostly because I genuinely had to reverse-engineer it to remember what I was doing.

The same renderer had a camera that could move around the scene using WASD and Q/E. Instead of implementing six movement operations, I came up with this:

```python
move_keys = {
    pygame.K_q: [(1, 1), ( 1,  0)],
    pygame.K_e: [(1, 1), (-1,  0)],
    pygame.K_d: [(0, 2), ( 1,  1)],
    pygame.K_a: [(0, 2), (-1, -1)],
    pygame.K_w: [(2, 0), ( 1, -1)],
    pygame.K_s: [(2, 0), (-1,  1)]
}

class Camera(Camera):
    def move(self, inf):
        ca = cos(self.rot[1]) * self.speed
        sa = sin(self.rot[1]) * self.speed

        if inf[0][0] == 2:
            ca, sa = sa, ca

        axis_d = {0: ca, 1: self.speed, 2: sa}
        for axis, m in zip(*inf):
            self.pos[axis] += (axis_d[axis] * m)
```

What the hell?

After staring at it for a while, I remembered the idea. Each key maps to a pair of tuples. The first tuple describes which coordinate axes to modify, and the second contains their corresponding direction multipliers.

For example, pressing W gives `[(2, 0), (1, -1)]`, which `zip(*inf)` turns into `(2, 1)` and `(0, -1)`. The rest of the function computes movement components from the camera's rotation, then uses those pairs to update the relevant coordinates. That special case involving `inf[0][0] == 2` swaps the sine and cosine components for forward/backward movement.

So, instead of writing explicit movement functions, I had essentially invented a tiny instruction format for camera movement. I'm not even sure this saved much code, but I distinctly remember enjoying tricks like this. There was something satisfying about encoding behavior into a small data structure and writing a generic function to interpret it.

I also found this in the same class:

```python
self.speed += {
    keys[pygame.K_PLUS] :  radians(1),
    keys[pygame.K_MINUS]: -radians(1)
}.get(1, 0)
```

A dictionary whose keys are booleans, used to determine whether to increase or decrease the speed. If both keys are pressed, the entries collide because they're both `True`, and one overwrites the other.

A feature, I'm sure.

At the time, only God and I knew how this worked. Now, only God knows. Well, God and an LLM I recently asked to help me decipher it, I suppose.

## making methods appear out of nowhere

I also had a small Pygame scene-management framework, because apparently using Pygame directly wasn't sufficiently interesting either.

One thing I disliked was repeatedly passing the display surface to drawing functions. Ordinarily, you'd write a few wrappers for the functions you needed, but I figured Python could just manufacture the methods for me.

```python
def init_draw_functions(self):
    draw_template = lambda func: lambda *a, **k: func(self.display, *a, **k)

    for name in filter(lambda f: '__' not in f, dir(pygame.draw)):
        setattr(
            self,
            f'draw_{name}',
            draw_template(getattr(pygame.draw, name))
        )
```

This inspects `pygame.draw`, creates wrappers around its functions that automatically insert `self.display` as the first argument, and attaches them directly to the scene manager instance.

I could then call `self.draw_circle(...)` or `self.draw_line(...)` without explicitly defining either method. A tiny bit of runtime metaprogramming that probably saved me less time than I spent thinking about how clever it was.

I still rather like it, though. There's something neat about making an object grow its own interface at runtime.

The same file also contains:

```python
def main_loop(self): # fix your timestep! lmao
```

Good to know I was already aware of the important problems.

## why use a conditional when you have xor?

There was also a period when I was particularly fond of bitwise operations. My maze generator, for example, had a keyboard shortcut for toggling between a fixed frame rate and running without a frame-rate cap.

```python
if event.key == pygame.K_f:
    self.curr_fps ^= 0 ^ self.fps
```

And another simulation had:

```python
if event.key == pygame.K_f:
    self.fps ^= (60 ^ 0)
```

The trick relies on the properties `x ^ x = 0` and `0 ^ x = x`, so repeatedly XORing a value with a constant toggles it between zero and that constant, assuming it starts in one of those states.

Perfectly functional. Completely unnecessary.

I think this summarizes my relationship with programming at the time rather well. Whenever I discovered something interesting, whether it was a language feature, a mathematical identity, or an algorithm, I'd immediately try to find somewhere to use it. And if there wasn't an obvious application, I'd invent one.

## reinventing the wheel was the point

There's a fairly common piece of programming advice: don't reinvent the wheel. Generally, it's good advice. There's little reason to write your own implementation of something that's already been solved, especially when you're building software that other people depend on.

But I think it's rather terrible advice if you're programming for fun.

Sometimes you don't want an INI parser. You want to write an INI parser. You don't particularly need a software renderer, a programming language interpreter, or a cryptosystem either, but you might be curious about how one works. And what better way to find out than to try implementing it yourself?

I certainly wasn't thinking about productivity when I wrote these projects. I'd come across something interesting, spend an unreasonable amount of time trying to understand it, and eventually end up with a little program that did something vaguely resembling what I'd intended. Sometimes I'd get distracted by a completely unrelated language feature along the way, and that would become the new project.

Looking back, a surprising amount of what I learned came from exercises like these. The INI parser gave me an excuse to play with Python's iterators and slicing. The renderer got me interested in transformations, coordinate systems, and projection. Writing an interpreter made a lot of programming language concepts much less mysterious.

None of the resulting software had to be particularly useful. I was just enjoying myself.

## when the answer is a prompt away

It's interesting to think about all of this now that we have LLMs capable of generating working implementations of practically any little utility you can imagine.

I use them myself, and they're wonderful tools. In fact, part of what prompted this whole trip down memory lane was going through my old code with an LLM, asking it to explain particularly incomprehensible bits, and laughing at some of the things I'd written. There's something quite funny about needing an AI to reverse-engineer your own teenage code.

But I wonder what fifteen-year-old me would have done with one.

Take the INI parser. Today, I could just ask an LLM to write it, and I'd probably get something considerably better in a few seconds. More sensibly, it might tell me to use `configparser` and save myself the trouble altogether.

Which would have been perfectly reasonable advice, except the trouble was sort of the point. I wasn't trying to get an INI parser as quickly as possible. I was playing with Python and enjoying the process of figuring things out.

I sometimes wonder how much of that experimentation I would have missed if I'd had a tool that could immediately produce a working solution. Would I have spent an afternoon messing around with `zip`, `map`, and slicing? Would I have bothered writing my own shape loader, or figuring out all those weird ways to represent camera movement?

Perhaps not. Or perhaps I'd have used it to explore even more things. Having something that can explain unfamiliar concepts, answer questions, and help you get unstuck is an incredible advantage when you're learning. I certainly would have appreciated it back then.

I don't think there's anything inherently valuable about spending three hours debugging a typo, nor do I think using an LLM somehow makes the things you build less yours. But I do think it's worth being conscious of what you're getting out of the process.

When you're programming recreationally, there's no particular reason to optimize every bit of friction out of the experience. You might enjoy figuring out how something works more than having the finished implementation. And if that's the case, immediately asking for a solution can be a rather effective way to deprive yourself of the interesting part.

I suppose that's something I'd tell my younger self if he had access to these tools: use them, absolutely. Just don't forget to mess around on your own every once in a while. Not because you have something to prove, but because it's fun.

## looking back

It's funny seeing how much my programming style has changed while recognizing so many of the same habits. I still like finding unexpected uses for language features, coming up with small abstractions to express complicated behavior, and occasionally turning an ordinary problem into a disproportionately elaborate project.

I'd like to think I've developed a better sense of when to indulge those tendencies, but I'm glad I spent those years writing the stuff I did. I wasn't trying to build a portfolio, optimize my productivity, or even become a better programmer. Programming was simply what I liked doing with my free time, and I happened to learn quite a lot along the way.

I could rewrite most of these projects today in a fraction of the time. An LLM could probably rewrite a good portion of them before I'd finished making coffee. But I wouldn't trade the hours I spent figuring things out, discovering weird language features, and feeling absurdly accomplished whenever something finally worked.

And who knows, maybe if I'd had an LLM in 2017, I'd have learned twice as much. Or maybe I'd just have a perfectly ordinary INI parser, and nothing to write about today. :)
