---
title: "would I have learned as much with an LLM?"
description: "incidental learning in the age of LLMs."
date: 2026-10-20
toc: true
---

I recently came across an archive of projects I wrote as a teenager. Some of them date all the way back to when I was fifteen.

There's a little bit of everything in the archive: a C++ editor written in Python, a Raspberry Pi powered RC car, a software renderer, a cryptosystem, an interpreter, and quite a few questionable experiments from my self-proclaimed hacker era. Apparently I had a lot of free time.

Much of the code is about as good as you'd expect. What stood out was how obsessed I was with finding clever ways to accomplish things, especially if I could squeeze them into very few lines. Readability was a problem for whoever had to look at it later. And many years later, that turned out to be me!

But I remember how absorbed I was in writing it. I'd discover a language feature, find somewhere to use it, and then find several more places where it probably didn't belong. A surprising amount of my understanding of programming came from getting carried away like this.

Looking back at those projects, I wonder how I would have approached them if I'd had an LLM at fifteen. How many of those detours would I have taken?

First, though, you should see some of the code.

## parsing ini files without a parser

One of my projects was a Raspberry Pi based RC car called Cartoon. It had an HTTP server, GPIO-controlled motors, MJPEG camera streaming, and three different clients: Android, desktop, and web. It also had a configuration file.

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

What an absolute beauty(?).

The regex splits the input into alternating section names and contents. Extended slicing lets me take every second element, starting at either index zero or one, which I then pair using `zip`, convert to lists, and pass into `dict`.

And then I do essentially the same thing again to parse the individual key value pairs. Starting with the words extracted by the regex:

```python
>>> vals = ['speed', '3', 'fps', '30']
>>> [vals[i::2] for i in range(2)]
[['speed', 'fps'], ['3', '30']]
>>> list(zip(*[vals[i::2] for i in range(2)]))
[('speed', '3'), ('fps', '30')]
>>> dict(zip(*[vals[i::2] for i in range(2)]))
{'speed': '3', 'fps': '30'}
```

Once I figured out that `seq[::2]` and `seq[1::2]` could separate alternating sequences, I was determined to make the entire parser revolve around it. My enthusiasm for slicing had apparently exceeded my interest in configuration files.

Does it handle the INI format correctly? Of course not. But it understood my configuration file, and I got to use a bunch of neat Python features along the way.

## the camera movement incident

Around the same time, I was writing a software 3D renderer in Python. That project got me interested in transformations, coordinate systems, and projection. It also produced this, which I had to reverse engineer to remember what I was doing.

The camera could move around the scene using WASD and Q/E:

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
    def move(self, table):
        ca = cos(self.rot[1]) * self.speed
        sa = sin(self.rot[1]) * self.speed

        if table[0][0] == 2:
            ca, sa = sa, ca

        axis_d = {0: ca, 1: self.speed, 2: sa}
        for axis, m in zip(*table):
            self.pos[axis] += (axis_d[axis] * m)
```

After staring at it for a while, I remembered the idea. The camera's position is stored as `[x, y, z]`, so axis `0` is x, `1` is y (up/down), and `2` is z. Moving along the ground changes x and z; moving vertically changes y.

Each key's entry says which coordinates to change and whether to add or subtract the movement calculated for them. For W, `[(2, 0), (1, -1)]` means “change z and x, adding to z and subtracting from x.” The `zip(*table)` turns that into `(2, 1)` and `(0, -1)` for the loop.

The amount to add or subtract depends on which way the camera is facing. `self.rot[1]` is its rotation around the vertical axis. For W, the sine/cosine swap makes the loop equivalent to:

```python
self.pos[2] += cos(self.rot[1]) * self.speed  # z
self.pos[0] -= sin(self.rot[1]) * self.speed  # x
```

At zero rotation, cosine is 1 and sine is 0. Starting at `[0, 0, 0]` with a speed of one, pressing W moves the camera to `[0, 0, 1]`. Turn it 90 degrees in the positive direction, and the same key moves it from the origin to `[-1, 0, 0]` instead. W follows the camera's facing direction. S uses the same axes with the signs reversed, so it moves backward.

I had essentially invented a tiny instruction format for camera movement. I'm not even sure this saved much code, but I distinctly remember enjoying tricks like this. There was something satisfying about encoding behavior into a small data structure and writing a generic function to interpret it.

Buried under the tuple indexing is an interesting problem: how do you describe movement relative to where a camera is pointing? I had to work out how the rotation affected the coordinates, then decide how to represent the different directions. The resulting representation is rather difficult to read, but working on the renderer gave me a reason to spend time with those ideas.

I could have written the movement much more clearly and learned the same things. Still, trying to make it clever was part of what held my attention. Nobody was waiting for this renderer. I could spend as long as I liked on a peculiar way of moving its camera.

I also found this in the same class:

```python
self.speed += {
    keys[pygame.K_PLUS]:   radians(1),
    keys[pygame.K_MINUS]: -radians(1)
}.get(1, 0)
```

A dictionary whose keys are booleans, used to determine whether to increase or decrease the speed. If both keys are pressed, the entries collide because they're both `True`, and one overwrites the other.

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

I still rather like it, though. There's something neat about making an object grow its own interface at runtime. Reading it now, I also think about having to find those methods later, or explain to someone where they came from. At fifteen, making them appear was sufficiently exciting.

The same file also contains:

```python
def main_loop(self): # fix your timestep! lmao
```

Good to know I was already aware of the important problems!

Elsewhere, my enthusiasm for bitwise operations produced this shortcut for toggling a simulation's frame rate cap:

```python
self.fps ^= 60 * (event.key == pygame.K_f)
```

The trick relies on the properties `x ^ x = 0` and `0 ^ x = x`, so repeatedly XORing a value with a constant toggles it between zero and that constant, assuming it starts in one of those states.

The comparison supplies `True` or `False`, so the multiplier makes this XOR with either 60 or zero.

Looking back, I can recognize the appeal of these choices and see reasons to reconsider them. I still enjoy small abstractions and unexpected uses of language features. I've also had the experience of returning to something I was very pleased with and having no idea how it works.

That's part of the judgment I was missing then. Discovering that you can do something is exciting enough to make it seem worth doing everywhere. It takes longer to develop a sense of when it helps.

## when the answer is a prompt away

I wasn't working through a curriculum with these projects. I'd come across something interesting, spend an unreasonable amount of time trying to understand it, and end up with a little program that did something vaguely resembling what I'd intended. Sometimes a completely unrelated language feature would become the new project.

Over time, that gave me practice making decisions about code, seeing what happened, and reconsidering them. I think of that as part of developing mastery: being able to reason about an implementation, change it, and recognize where your choices are making life difficult.

This is what makes me curious about how I would have used an LLM.

Take the camera example. I could have asked for WASD movement, received a readable implementation, and carried on with the renderer. I might have read the explanation and felt that I understood it. Having the camera move correctly would have been a satisfying place to stop.

But would I have been able to work out the movement myself? Would I have known what to change if it behaved strangely? Those are harder questions to answer when the code already works. My own version forced me to make decisions about axes, signs, and rotation before I could move around the scene.

Of course, I could have copied camera code from a tutorial in 2017. I could also have used a library and avoided writing much of the renderer. There have always been ways to skip parts of the problem. An LLM makes that option unusually convenient though: I can ask for something shaped around my exact code, then keep asking it to handle the next difficulty.

I use these tools myself, and that convenience is useful. When I want to finish something, I often welcome it. But fifteen-year-old me also wanted a working renderer, even while enjoying all the detours involved in building one. I doubt I would have stopped at every prompt to consider whether I was skipping something I'd enjoy figuring out.

The learning was often incidental, and that's the part I worry I might have missed. I wasn't consciously choosing an educational exercise each time. I wanted something to work. An implementation I could follow when it was explained to me might have felt like enough, right up until I needed to solve a related problem on my own.

Then again, I might have used an LLM to go much further. I could have asked why my camera math worked, tried another representation, or gotten help with a concept that would otherwise have stopped the project entirely. Having something to answer questions while I was learning would have been an enormous advantage.

Some difficulties gave me a reason to stay with an idea long enough to understand it. Having help available means I get more say in which difficulties I spend time on. It also means I have to notice when figuring something out is part of what I wanted from the project.

## the trouble was sort of the point

These projects didn't have to be particularly useful. I was programming because it was what I liked doing with my free time, and I happened to learn quite a lot along the way. I'm glad I had all those afternoons to get carried away, write something ridiculous, and feel absurdly accomplished when it finally worked.

Maybe if I'd had an LLM in 2017, I'd have learned twice as much. Or maybe I'd just have a perfectly ordinary INI parser, and nothing to write about today. :)
