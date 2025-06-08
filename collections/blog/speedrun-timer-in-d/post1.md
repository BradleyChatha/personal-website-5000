---
slug: post
title: How I made a speedrun timer in D
published: 2025-06-08
updated: 2025-06-08
order: 0
---

I semi-recently played through the original Deus Ex, and enjoyed my time with it so much that I felt like getting into speedrunning it, which ended up with me having to create a custom speedrun timer that "injects" itself into the game in order to implement features such as auto-splitting and load time removal.

This article details the rough journey I went through. It's not super well structured, but I was sorely lacking resources such as this when I was implementing the more complicated parts of the timer, so I wanted to share my experience.

This is basically a detailing of "baby's first game hack" as none of the techniques I've used here are advanced, and are more basic building blocks for injecting your own stuff into another process, but resources like this article were severely lacking/hard to find in my experience, so I imagine this will still be useful to someone.

If you read this entire thing then I'm afraid to say you have a fatal case of nerdism (welcome!).

## Summary

## Linux Limitations

Deus Ex speedrunners on Windows will have access to LiveSplit, which is the standard go-to speedrunning tool. LiveSplit has a lot of features, one of which includes the ability to write plugins that implement auto-splitting and load removal for particular games.

To be brief: A "split" can be thought of as just a level in a game. Speedrunners often want to track how fast they perform individual levels/splits, and so will create a list of these splits to track and manage over time.

Most games require the speedrunner to manually trigger the next split once they're done with their current one. This is annoying and inaccurate, so some games will have a plugin that enables auto-splitting - automatic detection of when the current split has finished (e.g. detecting a level change).

Additionally some games are very heavy on how many times the speedrunner must load levels or saves. As the time it takes for these loads to happen is very greatly dependent on the runner's computer (and other factors), it's common for these games to _not_ take into account loading times into the final time achieved.

Some games will have LiveSplit plugins that implement this functionality - such as in Deus Ex's case - however for technical reasons I'm not privy to, these plugins are unable to work on Linux, even if you use something like Wine to run LiveSplit (or maybe I just couldn't figure it out myself, either/or).

This means if you speedrun on Linux you'll have inferior tooling and a complete inability to perform auto-splitting and load removal, preventing you from getting an accurate measurement of how fast your runs and splits actually are.

## The goal

My goal with the timer was to have the following features:

- A timer that is relatively accurate (it's really, really hard to even get close to 100% accuracy with external timing software).

- The ability to detect when I reach a new level in order to power auto-splitting - ideally with as little delay as I can achieve.

- The ability to detect when I'm in a loading screen, so the timer can automatically pause.

- The ability to create and track splits.

I decided to write the timer in the [D programming language](https://dlang.org/) as:

1. It's my main language.

2. It's a systems-level language with a C compatible memory model, so I can access all the lower level syscalls and functions I need as easily as I could in C or C++, with no compromises.

3. It has a sleuth of high-level features - including a garbage collector - so I can give myself a pleasent and easy to use interface in front of the lower level code.

4. (For Reddit and Hacker News if this gets posted there) No, D does not have 2 standard libraries, and that hasn't been the case for a very long time. No, the GC doesn't magically make this sort of program impossible. No, I'm not rewriting it in Rust or Zig. Yes, something something Dick joke something something. Thank you, please actually foster a discussion now.

## The search for a loading flag

Deus Ex was made on a very early version of the Unreal Engine, and so you can actually extract all of the game's scripts directly from its compiled data as they're just sitting there in plain text.

Specifically, by running `strings Engine.u` to extract all the plain text strings from one specific file, we can see the following enum:

```txt title="Engine.u" {"of note":3}
var transient enum ELevelAction
        LEVACT_None,
        LEVACT_Loading,
        LEVACT_Saving,
        LEVACT_Connecting,
        LEVACT_Precaching
} LevelAction;
```

There also exists some code to set a global variable to `LEVACT_Loading` during a loading screen, so in theory I should be able to find a byte somewhere that changes to (what I assumed) to be `1` during loading, and `0` during normal gameplay, right? _right_?

I started off by:

1. Running the game.

2. Using `ps aux` to find the PID for the game.

3. Attaching [scanmem](https://github.com/scanmem/scanmem) to the PID so I can start pin-pointing where this mythical loading flag exists.

4. Trigger a loading screen; quickly swap to scanmem and trigger a scan for the value `1` - causing it to pause the game's process while it performs a scan, and then repeating the process to whittle down the result list.

In other old/simpler games this approach generally works to find a specific memory address for some specific variable, however I made the mistake of believing that Unreal's VM/interpreter for its game script would lay out its memory in a clean, familiar way, and that it wouldn't constantly allocate and move things around in memory all the time.

Ultimately I couldn't find any singular memory address that changed to `1` during loading screens and `0` outside of them. I'd often find multiple addresses that behaved like this, but these addresses would always change during loading screens (or other events) and so were unfeasable to reliably use in the timer (trust me, I made a lot of [hacky attempts](https://github.com/BradleyChatha/deusex-timer/blob/master/source/old_app.d) to make it work).

In the end I gave up on the idea of a quick win after at least 20 hours of my life gone, and instead accepted that I had needed to do things in a more "proper" way.

## Pre-requisite research - syscalls

My next idea felt very ambitious, as this isn't something I'd have ever done before, but in a way that also served as motivation to get it implemented and working.

Due to the very existance of debuggers I knew that there were ways to read and write into another process' memory, and so I thought that the following process must be possible:

1. I should be able to inject my own machine code into the game, so e.g. that I could set my own flag in a well-known location.

2. I should then be able to check said flag at regular intervals, and respond to it in kind.

After a bit of google-fu I found a few syscalls that Linux supports which allow me to achieve these exact goals:

- [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) - This can do a lot, but essentially allows a process to become the "parent" of another process, and allows it to perform a lot of debugger-like activities.

- [process_vm_readv](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) - Allows one process to read from another process' memory, as long as the parent process has `ptrace` permissions.

Notably a `process_vm_writev` syscall also exists, however it adhears to memory page protections - so if I wanted to inject data into a write-protected memory page, it'd fail. Curiously `ptrace` is able to bypass protections, but has a different limitation in that you always have to "poke" 8 bytes at a time, no more, no less, which is definitely annoying to deal with.

While D does provide a lot of bindings for libc functions, it unfortunately (and sadly unsuprisingly) lacked bindings for these two functions.

D is heavily compatible with C however, so it's trivial to define our own bindings:

```d
import core.sys.posix.sys.uio : iovec;

// D fact: Enums don't physically exist in the final output like an `int PTRACE_ATTACH = 16` would,
// they're compile-time-only constants.
enum PTRACE_ATTACH = 16;
enum PTRACE_DETACH = 17;
enum PTRACE_POKEDATA = 5;

extern(C) long ptrace(int op, int pid, void* addr, void* data);
extern(C) ptrdiff_t process_vm_readv(int pid, iovec* local, size_t len, iovec* remote, size_t rlen, ulong flags);
```

## Pre-requisite research - finding the LoadMap function

So now that I had a way to write/read from the game's memory, my next goal was to find an appropriate function to inject some custom logic into.

Windows binaries are in the [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) format, and so after having a little read about the format itself there's one section that stood out to me: the Export Address Table.

To keep it simple, for our purposes this table contains a list of functions that Unreal Engine exposes to the game, including a Relative Virtual Address (RVA) which is basically just an offset within the game's machine code to the first instruction for any given, exported function.

Fortunately we can dump these tables even on Linux, in this case for Engine.dll: `llvm-readobj --coff-exports Engine.dll`

I then searched for the word "Load" and quickly found this particular entry for a `LoadMap` function:

```c++
Export {
  Ordinal: 1278
  Name: ?LoadMap@UGameEngine@@UAEPAVULevel@@ABVFURL@@PAVUPendingLevel@@PBV?$TMap@VFString@@V1@@@AAVFString@@@Z
  RVA: 0x33A5
}
```

I then decompiled Engine.dll: `objdump -d Engine.dll` and noticed that the base address was `0x10300000`. So by adding the RVA (`0x33A5`) to this base address (equalling `0x103033A5`) we end up on this exact instruction:

```asm
103033a5:  e9 46 8e 08 00  jmp 0x1038c1f0
```

**Miracle #1:** Since all calls to LoadMap point to this instruction which then jumps into the actual start address of the function, this is the only instruction I need to patch if I change the start address, rather than having to find and patch all `call` instructions for LoadMap instead.

Following the address that this jmp instruction points to leads us to the start of an actual function (the first two instructions setup a [stack frame](https://en.wikipedia.org/wiki/Call_stack#Structure), which is a dead giveaway):

```asm
1038c1f0:  55                 push   %ebp
1038c1f1:  8b ec              mov    %esp,%ebp
1038c1f3:  6a ff              push   $0xffffffff
1038c1f5:  68 bb ff 41 10     push   $0x1041ffbb
1038c1fa:  64 a1 00 00 00 00  mov    %fs:0x0,%eax
1038c200:  50                 push   %eax
...
```

I don't really know why, but functions in Engine.dll have a ton of `int3` instructions just before them, and a ton of `nop` instructions at the end:

```asm
... even more int3s
1038c1ec:  cc              int3
1038c1ed:  cc              int3
1038c1ee:  cc              int3
1038c1ef:  cc              int3
1038c1f0:  55              push   %ebp
1038c1f1:  8b ec           mov    %esp,%ebp
... rest of LoadMap
1038e72b:  6a 00           push   $0x0
1038e72d:  e8 9e 4d 08 00  call   0x104134d0
1038e732:  90              nop
1038e733:  90              nop
1038e734:  90              nop
1038e735:  90              nop
... even more nops, followed by int3s
```

**Miracle #2**: We have plenty of free space to inject our own code, so we don't have to do any other potential shennanigans with shuffling the entire function about, but only portions of it - I'll get to that part later.

Just to confirm that this is indeed **the** LoadMap function, I performed the following steps:

1. I launched the game.

2. I used `ps aux` and manually searched for which PID the game was running under.

3. I attached a debugger to the game via `lldb -p $PID`.

4. I created a breakpoint at LoadMap's first push instruction `b 0x1038c1f0`.

5. I loaded the game's first level, and saw that the breakpoint triggered!

```asm
Process 2620396 stopped
* thread #1, name = 'DeusEx.exe', stop reason = breakpoint 1.1
    frame #0: 0x1038c1f0
->  0x1038c1f0: pushl  %ebp
    0x1038c1f1: movl   %esp, %ebp
    0x1038c1f3: pushl  $-0x1
    0x1038c1f5: pushl  $0x1041ffbb    ; imm = 0x1041FFBB
```

## Pre-requisite research - finding some unused memory I can modify

With a way to modify the game's code; the location of the LoadMap function, and the general idea that I want to modify LoadMap so that it sets a `loading` flag somewhere, I now need to find where that "somewhere" is.

Linux allows you to inspect the memory maps for any process by looking at the special `/proc/<PID>/maps` file. Here's two example entries:

```text
f7f6c000-f7f6d000 rw-p 00003000 fe:00 469819172 /home/bradley/.local/share/Steam/steamapps/common/Proton - Experimental/files/bin/wine
f7f6d000-f7f6f000 r--p 00000000 00:00 0         [vvar]
```

I won't go through the entire format, but essentially what I'm looking for is an area of memory that is writeable (has the `w` flag) and has a small portion that the game never uses itself (so it doesn't clobber my own values I stuff there).

When a process is running in memory, it'll have maps containing the contents of any shared libraries that it's linked against. Interestingly this holds true for Windows DLLs running under Wine/Proton as well (I have a big knowledge gap here if you couldn't tell).

So if we look for mappings for `Engine.dll` that we can also write to (which may or may not be a good idea for me to use ;D) - `cat /proc/2637581/maps | grep -E " .w.. .+Engine.dll"`, we can see there's at least two writeable mappings:

```
10479000-10486000 rwxp 00179000 103:02 2416829569 /nvme2/Games/steamapps/common/Deus Ex/System/Engine.dll
10599000-105a0000 rwxp 00186000 103:02 2416829569 /nvme2/Games/steamapps/common/Deus Ex/System/Engine.dll
```

Being able to use one of these maps to store our data would be useful, since it'd be easy to code for "find the second Engine.dll mapping and use the last few bytes for our own purposes" rather than a more generalised approach.

So I run the game; attach to it with lldb, and use `mem read 0x105a0000-0xFF -c 0xFF -s1` to peek at the last 255 bytes of the second mapping. It was all 0!

I did a casual ~~slowrun~~ speedrun; ocassionally running the above lldb command, and saw that nothing ever seems to write to this area of memory, making it a perfect area for us to store the little bits and bobs we need for ourselves.

## Pre-requisite research - summary

- I have the means to access the game's memory from another process, which includes modifying its running machine code.

- I have the perfect function to modify in order to track whether we're in a loading screen or not.

- I have a consistent memory location that should always be safe to store a bit of custom data into.

At this point it was clear there was a valid pathway for me to implement the new plan, and so came time to get a small MVP of the injection functionality sorted.

## Framework - RunningProcess

Instead of hacking together a bunch of code like I was doing with my earlier experiments, I decided that it was worth the time to setup a mini framework for myself in order to keep myself sane (and keep the code clean, I _guess_).

The first thing I needed was a way to list all running processes so I can find which one the game is.

By iterating over the directories of `/proc/` we can easily discover all currently running PIDs, as most directory names are a PID. I've already talked about `/proc/<PID>/maps`, but there's also another interesting file called `/proc/<PID>/comm` which contains the name of the binary that the process was created for:

```bash
> cat /proc/2637581/comm
DeusEx.exe
```

In other words we can easily find the PID for the game by just looking out for which one has `DeusEx.exe` as its `comm`.

I started off with writing a `RunningProcess` struct that contains a static function to eagerly fetch all currently running processes:

```d
struct RunningProcess
{
    int pid;

    // Values directly corresponding to the same named files in /proc/<pid>/
    string cmdline;
    string comm;

    static RunningProcess[] listAll()
    {
        // D fact: Scoped, selective imports!
        import std.algorithm : all, filter, map;
        import std.array     : array;
        import std.conv      : to;
        import std.file      : dirEntries, SpanMode, readText;
        import std.path      : baseName;
        import std.string    : chomp;
        import std.uni       : isNumber;

        // D fact: UFCS (Uniform Function Call Syntax) allows all free standing functions
        //         to use member function call syntax. "baz(bar(foo))" can be written as "foo.bar().baz()"
        //
        // Also:   `!Yada` and `!(Yada)` are used to pass in template parameters.
        return dirEntries("/proc", SpanMode.shallow)
            .filter!(de => de.baseName.all!isNumber)
            .map!((de) {
                RunningProcess process;
                process.pid = de.baseName.to!int;

                // D fact: `A ~ B` means "append B to A"
                process.cmdline = readText(de.name ~ "/cmdline").chomp; // NOTE: cmdline isn't too interesting to explain, so I've ignored it.
                process.comm    = readText(de.name ~ "/comm").chomp;

                return process;
            })
            .array;
    }

    string command()
    {
        return this.cmdline.length ? this.cmdline : this.comm;
    }
}
```

## Framework - GameProcess

Now I wanted a wrapper around a RunningProcess that had more specific functionality for handling `ptrace`, as well as reading data (but not writing yet).

I started off with a simple enough class that can handle attaching and detaching from the game process via `ptrace`:

```d
class GameProcess
{
    private
    {
        int _pid;
        bool _attached;

        this(int pid)
        {
            this._pid = pid;
            this.attach();
        }
    }

    ~this()
    {
        if(this._pid != 0 && this._attached)
            this.detach();
    }

    static GameProcess fromPid(int pid)
    {
        return new GameProcess(pid);
    }

    static GameProcess fromProcess(RunningProcess process)
    {
        return new GameProcess(process.pid);
    }

    void attach()
    in(!this._attached, "Already attached")
    {
        const result = ptrace(PTRACE_ATTACH, pid, null, null);
        if(result == -1)
        {
            // I kept procrastinating on DRYing this, and eventually gave up on the idea entirely, so this
            // code is duplicated a _lot_.
            import core.stdc.errno : errno;
            import std.string : fromStringz;
            import core.sys.posix.string : strerror;
            throw new Exception("Failed to attach to process: " ~ strerror(errno).fromStringz.idup);
        }

        this._attached = true;
    }

    void detach()
    in(this._attached, "Not attached")
    {
        const result = ptrace(PTRACE_DETACH, pid, null, null);
        if(result == -1)
        {/*...*/}

        this._attached = false;
    }

    void pause()
    {
        import core.sys.posix.signal : kill, SIGSTOP;
        kill(this._pid, SIGSTOP);
    }

    void resume()
    {
        import core.sys.posix.signal : kill, SIGCONT;
        kill(this._pid, SIGCONT);
    }

    int pid()
    {
        return this._pid;
    }
}

```

I was then able to write a small function to select the Deus Ex process, and wrap it into a `GameProcess`:

```d
int main()
{
    GameProcess deusex;
    Patcher enginePatcher; // Ignore for now - I'll get to this
    findDeusEx(deusex, enginePatcher);
}

void findDeusEx(out GameProcess deusex, out Patcher enginePatcher)
{
    import std.algorithm : filter;
    import std.range     : takeExactly;

    auto process = RunningProcess
                    .listAll()
                    .filter!(p => p.comm == "deusex.exe" || p.comm == "DeusEx.exe")
                    .takeExactly(1)
                    .front;

    deusex = GameProcess.fromProcess(process);

    // Again, I'll get to this a bit later.
    enginePatcher = new Patcher(deusex, (map){
        import std.algorithm : endsWith;
        return map.pathname.endsWith("Engine.dll");
    });
}
```

As I also needed programatic access of the process' memory maps, I decided to stuff that into GameProcess as well. I decided to use a simple regex since it just needed to be a quick and simple solution:

```d
class GameProcess
{
    // D fact: Nested structs/classes will be given a hidden context pointer to the parent type,
    //         unless you mark it as `static`.
    static struct MemoryMap
    {
        ulong start;
        ulong end;
        bool readable;
        bool writable;
        bool executable;
        bool private_;
        ulong offset;
        uint major;
        uint minor;
        uint inode;
        string pathname;
    }

    private
    {
        MemoryMap[] _maps;
    }

    void refreshMaps()
    {
        import std.conv   : to;
        import std.file   : readText;
        import std.string : lineSplitter;
        import std.regex  : regex, matchFirst;

        // D fact: `r` strings don't support escape characters, so they're great for regexes!
        MemoryMap[] mappings;
        const reg = regex(r"([0-9a-f]+)-([0-9a-f]+)\s+([-r][-w][-x][-p])\s+([0-9a-f]+)\s+([0-9a-f]+):([0-9a-f]+)\s([0-9]+)\s+(.*)");

        foreach(line; readText("/proc/" ~ this._pid.to!string ~ "/maps").lineSplitter)
        {
            const captures = line.matchFirst(reg);
            if(!captures)
                continue;

            mappings ~= MemoryMap(
                captures[1].to!ulong(16),
                captures[2].to!ulong(16),
                captures[3][0] == 'r',
                captures[3][1] == 'w',
                captures[3][2] == 'x',
                captures[3][3] == 'p',
                captures[4].to!ulong(16),
                captures[5].to!uint(16),
                captures[6].to!uint(16),
                captures[7].to!uint,
                captures[8]
            );
        }

        this._maps = mappings;
    }

    bool mapStillExists(MemoryMap map)
    {
        import std.algorithm : any;
        return this._maps.any!(m => m.start == map.start && m.end == map.end);
    }

    MemoryMap[] memoryMaps()
    {
        return this._maps;
    }
}
```

Finally, GameProcess also needed to provide an interface for reading memory from the game, which is where the `process_vm_readv` comes in.

One issue I ran into with `process_vm_readv` is that it would often fail to accurately read larger chunks of memory, providing me with completely wrong values. I suspect this is because `process_vm_readv` for some reason doesn't ensure the pages it needs to read from are still swapped in by the time it reads from them (or some other page related madness)?

Either way, this is why the following code snippet provides the `peek` functions for cases where I only need to access a specific portion of the game's memory, instead of entire maps at a time.

In short, `process_vm_readv` works by filling in at least two `iovec` structures - one containing a pointer + length for a buffer on the caller process' side, and one pointing to a memory address + length on the target process' side. Linux will then copy the target process' memory over to the caller process' provided buffer.

```d
class GameProcess
{
    // D fact: A `delegate` is a function pointer with a hidden context pointer attached to it, e.g.
    //         so the delegate can access stack variables.
    void accessMemory(MemoryMap map, void delegate(scope const ubyte[]) callback)
    {
        import core.memory : GC;

        auto buffer = (cast(ubyte*)GC.malloc(map.end - map.start, 0, typeid(ubyte)))[0..map.end - map.start];
        scope(exit) GC.free(buffer.ptr); // scope(exit) is just like `defer` in Go.

        iovec local;
        local.iov_base = buffer.ptr;
        local.iov_len = buffer.length;

        iovec remote;
        remote.iov_base = cast(void*)map.start;
        remote.iov_len = buffer.length;

        const result = process_vm_readv(this._pid, &local, 1, &remote, 1, 0);
        if(result == -1)
        { /* error handling */ }

        callback(buffer);
    }

    T peek(T)(size_t address)
    {
        T ret;

        iovec local;
        local.iov_base = cast(void*)&ret;
        local.iov_len = T.sizeof;

        iovec remote;
        remote.iov_base = cast(void*)address;
        remote.iov_len = T.sizeof;

        const result = process_vm_readv(this._pid, &local, 1, &remote, 1, 0);
        if(result == -1)
        { /* error handling */ }

        return ret;
    }

    ubyte[] peek(size_t address, return ubyte[] buffer)
    {
        iovec local;
        local.iov_base = cast(void*)&buffer[0];
        local.iov_len = buffer.length;

        iovec remote;
        remote.iov_base = cast(void*)address;
        remote.iov_len = buffer.length;

        const result = process_vm_readv(this._pid, &local, 1, &remote, 1, 0);
        if(result == -1)
        { /* error handling */ }

        return buffer[0..result];
    }
}
```

Since D contains a bunch of high-level features like first-class functions, I decided to make `accessMemory` use a callback pattern, so that the caller never has to worry about dealing with the underlying short-lived memory (which I only do to reduce the amount of GC pauses, by freeing early to hopefully reduce pressure).

Here's a few snippets on how these functions are used, these snippets will be covered in depth later on:

```d
// Example of accessMemory
ubyte[8] retPopAndMovInstructions;
deusex.accessMemory(loadMapSig.map, (scope memory){
    // Note: since we're assigning to a static array, the data is copied - `memory` is NOT being incorrectly escaped
    retPopAndMovInstructions = memory[retPopAndMovOffset..retPopAndMovOffset+8];

    const target = [0x90, 0x90, 0x90, 0x90]; // nop nop nop nop
    while(endOfLoadMapInstructions < memory.length - target.length)
    {
        if(memory[endOfLoadMapInstructions..endOfLoadMapInstructions+target.length] == target)
            return;
        endOfLoadMapInstructions++;
    }

    throw new Exception("Could not find end of LoadMap?");
});

// Example of peek

// process_vm_readv sometimes fails with ESRCH and I have no idea why, so ignore any errors for now.
bool isLoading = false;
try isLoading = deusex.peek!bool(flagsAddress);
catch(Exception) return;
```

This should hopefully showcase why I love using D - in this case it effortlessly allowed me to wrap my low-level code in a higher-level syntax, without any real compromise or additional complexity.

## Framework - Patcher

For the final part of the "low-level" related classes, we have the `Patcher` class which as the name implies, is responsible for allowing me to modify the game's memory.

I originally imagined the patcher as being a lot more complex than it ended up being, hence why I decided to have a dedicated class for write operations, but realistically I could've gotten away with putting this stuff into `GameProcess` as well.

Here's the class in mostly its entirety, with some legacy cruft removed:

```d
import std.typecons : Nullable;

class Patcher
{
    // D fact: alias != typedef, it's basically just a way to provide a different name for an existing type,
    //         rather than creating an entirely new type.
    alias MapSelector = bool delegate(const GameProcess.MemoryMap);

    static struct FunctionEstimate
    {
        GameProcess.MemoryMap map;
        size_t offset;
        size_t estimatedSize;
    }

    private
    {
        GameProcess _process;
        MapSelector _mapSelector;
    }

    this(GameProcess process, MapSelector selector)
    {
        this._process = process;
        this._mapSelector = selector;
    }

    Nullable!FunctionEstimate signatureScan(
        int[] bytes,
        size_t delegate(scope const ubyte[] memoryStartingFromSignature) sizeEstimator,
    )
    {
        this._process.refreshMaps();
        foreach(map; this._process.memoryMaps)
        {
            if(!this._mapSelector(map))
                continue;

            Nullable!FunctionEstimate result;
            this._process.accessMemory(map, (scope memory){
                if(bytes.length < bytes.length)
                    return;

                size_t byteIndex;
                Failed: while(byteIndex < memory.length - bytes.length)
                {
                    const offset = byteIndex;
                    foreach(i, check; bytes)
                    {
                        // Note: This if statement allows for things like `-1` to mean "any byte".
                        //       This functionality never got used in the end.
                        if(bytes[i] >= 0 && bytes[i] <= 0xFF)
                        {
                            if(memory[offset + i] != bytes[i])
                            {
                                byteIndex++;
                                goto Failed;
                            }
                        }
                    }

                    result = FunctionEstimate(map, offset, sizeEstimator(memory[offset..$]));
                    return;
                }
            });

            if(!result.isNull)
                return result;
        }

        // D fact: typeof(return) is the function's return type.
        // Also  : All D types expose their default initialiser under the special `.init` property.
        //         In this case, the `.init` of a `Nullable` is one where `.isNull` returns true.
        return typeof(return).init;
    }

    void poke8Bytes(FunctionEstimate func, ptrdiff_t offset, ubyte[8] bytes)
    {
        const result = ptrace(
            PTRACE_POKEDATA,
            this._process.pid,
            cast(void*)(func.map.start + func.offset + offset),
            cast(void*)(*(cast(size_t*)bytes.ptr))
        );
        if(result == -1)
        { /* error handling */ }
    }
}
```

Signature scanning is a common technique that's used for figuring out where specific functions/specific code exists - specifically by looking for a specific set of instructions that are known to uniquely identify the thing you're looking for.

For example, I've confirmed that these instructions from the start of LoadMap are unique to it, so can easily be used as the "signature" to scan for:

```asm
0x55,                           push ebp
0x8B, 0xEC,                     mov ebp, esp
0x6A, 0xFF,                     push 0xFFFFFFFF
0x68, 0xBB, 0xFF, 0x41, 0x10    push 0x1041ffbb
```

In DeusEx's case, none of the signatures I need to look for change after the game is loaded into memory, so I can hard code everything. In other cases things like memory address may be randomised or in some way dynamic, so some signature scanning code you see elsewhere will support the concept of "placeholders" (often denoted as "??") for specific bytes that can't be hardcoded. While the Patcher supports this, it's not really needed, so I'll leave the topic there.

The Patcher's `signatureScan` is pretty straightforward: do a simple linear search across any maps that the user's provided `MapSelector` allows for; then reach into a user provided callback to estimate the size of the function (for the user code's own purposes really). Curiously this code never appears to run into the `process_vm_readv` issue I mentioned earlier.

The only other function that the Patcher provides (again, I expected this to be a lot more complicated than it turned out as being), is the `poke8Bytes` function - this is where `ptrace` comes in handy due to its ability to bypass page protections, with the previously mentioned downside of having to poke 8 bytes exactly, no more and no less than that.

Just like that, we have a semi-structured approach for finding functions and modifying their code.

## Framework - UI

The code also features an OOP-style way of displaying a TUI within the console, but there's basically nothing interesting there to talk about, so I'll be skipping past it.

## MVP - Setting the flag

I ended up making one mega function to perform pretty much all of the steps I've described: finding the LoadMap function; patching it, and finding a place to store our "is loading" flag:

```d
int main()
{
    // ...

    size_t flagsAddress;
    size_t lastLoadedMapAddress; // I'll get to this later.

    try patchFlagSettersIntoLoadMap(deusex, enginePatcher, /*out*/ flagsAddress, /*out*/ lastLoadedMapAddress);
    finally deusex.detach(); // PTRACE_ATTACH forces the program to pause, so this is just to unpause it. We don't need it to modify memory anymore.
}

void patchFlagSettersIntoLoadMap(
    GameProcess deusex,
    Patcher enginePatcher,
    out size_t flagsAddress,
    out size_t lastLoadedMapAddress,
)
{
    // ... Will be covered in a moment
}
```

The first step was figuring out where LoadMap + its jump table entry were - I technically could've hard coded this, but decided it'd be fun to do things "properly" using my newly made toolkit:

```d
void patchFlagSettersIntoLoadMap(/*...*/)
{
    import std.stdio : writefln;

    /++ Find the LoadMap function, as well as its entry in the jump table. ++/
    auto loadMapSig = enginePatcher.signatureScan([
        0x55,                           // push ebp
        0x8B, 0xEC,                     // mov ebp, esp
        0x6A, 0xFF,                     // push 0xFFFFFFFF
        0x68, 0xBB, 0xFF, 0x41, 0x10    // push 0x1041ffbb
    ], (scope memoryAfterSig){
        // Look for the main ret instruction, to get an estimate of the function's size.
        const target = [0xC2, 0x10, 0x00]; // ret 0x10
        foreach(i, _; memoryAfterSig)
        {
            if(i >= memoryAfterSig.length - target.length)
                throw new Exception("Could not find return instruction?");

            if(memoryAfterSig[i..i+target.length] == target)
                return i;
        }

        assert(false);
    }).get;
    writefln(
        "Found LoadMap at 0x%08X - ret is at 0x%08X (incorrect if already patched)",
        loadMapSig.map.start + loadMapSig.offset,
        loadMapSig.map.start + loadMapSig.offset + loadMapSig.estimatedSize,
    ); // e.g.: Found LoadMap at 0x1038C1F0 - ret is at 0x1038E461

    auto loadMapJumpSigResult = enginePatcher.signatureScan([
        0xE9, 0x46, 0x8e, 0x08, 0x00 // jmp [rel LoadMap]
    ], (scope memoryAfterSig){ return 0; });
}
```

Next step was to find the address I could safely store the loading flag (and the "last loaded map" stuff I'll get to later on) into:

```d
void patchFlagSettersIntoLoadMap(/*...*/, out size_t flagsAddress, out size_t lastLoadedMapAddress)
{
    // ...

    import std.algorithm : filter, canFind;
    import std.array     : array;

    // Engine.dll creates at least 2 writeable mappings.
    // It's very unlikely the last bytes of the last mapping are in actual use, so we can use it to store our own values.
    const mapToStoreFlags = deusex.memoryMaps
                            .filter!(m => m.pathname.canFind("Engine.dll") && m.writable)
                            .array[$-1];
    flagsAddress = mapToStoreFlags.end - 1;
    lastLoadedMapAddress = mapToStoreFlags.end - 9;
    writefln("Storing flag byte at 0x%08X", flagsAddress); // e.g: ... at 0x1059FFFF
    writefln("Storing last loaded map pointer at 0x%08X", lastLoadedMapAddress); // e.g: ... at 0x1059FFF7
}
```

Now for the exciting part, I essentially want to turn the start of the LoadMap function from this:

```asm del={2-9}
... more int3s
1038c1e8:  cc              int3
1038c1e9:  cc              int3
1038c1ea:  cc              int3
1038c1eb:  cc              int3
1038c1ec:  cc              int3
1038c1ed:  cc              int3
1038c1ee:  cc              int3
1038c1ef:  cc              int3
1038c1f0:  55              push   %ebp
1038c1f1:  8b ec           mov    %esp,%ebp
... rest of LoadMap
```

Into this (reminder, I **have** to write 8 bytes at a time, hence the random `nop` paddings you'll start seeing):

```asm ins={1-2}
1038c1e8: c6 05 ff ff 59 10 01  mov    $0x1, 0x1059ffff
1038c1ef: 90                    nop
1038c1f0: 55                    push   %ebp
1038c1f1: 8b ec                 mov    %esp, %ebp
```

I also need to modify LoadMap's jump table entry so that it points towards my newly injected code instead:

```d del={1} ins={2}
From: 103033a5: e9 46 8e 08 00  jmp 0x1038c1f0
To:   103033a5: e9 3e 8e 08 00  jmp 0x1038c1e8
```

Which with the `Patcher` class ended up being very easy to pull off:

```d
void patchFlagSettersIntoLoadMap(Patcher enginePatcher, /*...*/)
{
    // ...

    // Write 8 bytes before the first instruction of LoadMap
    enginePatcher.poke8Bytes(loadMapSig, -8, [
        // mov byte [FlagsAddress], 1
        0xC6, 0x05,
        cast(ubyte)(flagsAddress & 0xFF),
        cast(ubyte)((flagsAddress & 0xFF00) >> (8 * 1)),
        cast(ubyte)((flagsAddress & 0xFF0000) >> (8 * 2)),
        cast(ubyte)((flagsAddress & 0xFF000000) >> (8 * 3)),
        0x01,

        0x90, // nop
    ]);

    // `jmp` uses a relative offset, rather than an absolute address, so the easiest option
    // is to read in the instruction; subtract 8 from the offset, and inject the change back in.
    ubyte[8] jumpInstructions;
    deusex.accessMemory(loadMapJumpSig.map, (scope memory){
        jumpInstructions = memory[loadMapJumpSig.offset..loadMapJumpSig.offset+8];
    });
    jumpInstructions[1] -= 8;
    enginePatcher.poke8Bytes(loadMapJumpSig, 0, jumpInstructions);
}
```

At this point I was happy enough to manually check that the flag gets set, so:

1. I load up the game.
2. Ran the timer to inject its changes (and some painful debugging I'm skipping over :D).
3. Attached LLDB to the game as before.
4. Loaded a map.
5. Used LLDB to see if the flag got set.

```bash
(lldb) mem read 0x1059FFFF -c 1
0x1059ffff: 01
```

Success!

## MVP - Unsetting the flag

This is where things got a little tricky - unsetting the flag _should_ be as simple as doing `mov [FlagAddress], 0` just before the main `ret` instruction, right? Yes! However there's some additional complications in order to pull such a thing off.

The first issue is around how the `LoadMap` function is layed out: The main `ret` instruction which handles success cases isn't the final instruction of the function, but instead is followed by what I believe to be an exception handling branch:

```asm {4}
... rest of LoadMap's happy path
1038e45e:	8b e5                	mov    %ebp,%esp
1038e460:	5d                   	pop    %ebp
1038e461:	c2 10 00             	ret    $0x10 ; <-- Main success case ret instruction
... beginning of some other branch
1038e464:	8b 4d b0             	mov    -0x50(%ebp),%ecx
1038e467:	8d 95 7c ff ff ff    	lea    -0x84(%ebp),%edx
```

I'll talk about the exception handling stuff at the very end, but the main pain point here is that there's no free space for me to inject my `mov` instruction.

Essentially, what has to be done here is:

1. Inject my `mov` instruction into where the function-ending `nop`s are.
2. Move the `ret` instruction, and a few surrounding instructions to also be where the `nop`s are, just after my `mov` instruction.
3. Inject a `jmp` instruction where the old instructions we moved used to be - this `jmp` will go to where the `mov`, `ret`, etc. instructions are now placed.

It sounds a bit messy and complex, but bare with me since it's not as bad as it seems once implemented.

The main thing to think about here is the `jmp` instruction I need to inject. I'd need 5 bytes to inject this particular instruction, which means I need to move the `ret` (which is 3 bytes), as well as any other instructions before it that total to at least 5 bytes:

```asm del={1-3}
1038e45e:	8b e5      mov    %ebp,%esp ; 2 bytes - I have to include both bytes to not cut the instruction in half
1038e460:	5d         pop    %ebp      ; 3 bytes
1038e461:	c2 10 00   ret    $0x10     ; 6 bytes

; Since I need a multiple of 8, I'll also read in the first 2 bytes of this instruction, but leave
; them unmodified & not copy them anywhere.
1038e464:	8b 4d b0   mov    -0x50(%ebp),%ecx
```

I can then change the above instructions to look like this:

```asm ins={1-2}
1038e45e: e9 cf 02 00 00  jmp    0x1038e732 ; This address is where the nops start - i.e. where we're injecting our new code.
1038e463: 90              nop

; (Unmodified)
1038e464:	8b 4d b0   mov    -0x50(%ebp),%ecx
```

While then also changing the nops at the end of LoadMap to look like this:

```asm del={2-6} ins={10-16}
; From
1038e732:	90                   	nop
1038e733:	90                   	nop
1038e734:	90                   	nop
1038e735:	90                   	nop
1038e736:	90                   	nop
...

; To
1038e732: c6 05 ff ff 59 10 00  movb   $0x0, 0x1059ffff ; Unset the loading flag
1038e739: 90                    nop
...
1038e751: 90                    nop
1038e752: 8b e5                 movl   %ebp, %esp ; Old instructions we're preserving
1038e754: 5d                    popl   %ebp
1038e755: c2 10 00              retl   $0x10
```

You may have noticed that I've kept a lot of `nops` between the flag unsetter and the old return instructions - this is because we'll be injecting more code there soon, so we'll need some space.

Let's start off with simply reading in the instructions we're going to move, and figuring out where the true end of the function is:

```d
void patchFlagSettersIntoLoadMap(/*...*/)
{
    // ...

    const retOffset = loadMapSig.offset + loadMapSig.estimatedSize; // `esimatedSize` was calculated earlier by looking for the `ret 0x10` instruction.
    const retPopAndMovOffset = retOffset - 3; // start of where we need to copy from
    ubyte[8] retPopAndMovInstructions; // The first 6 are the instructions we're overwriting/moving, the other 2 are from that unrelated instruction we're not doing anything with.

    size_t endOfLoadMapInstructions = retPopAndMovOffset; // Gets modified below.

    deusex.accessMemory(loadMapSig.map, (scope memory){
        // Copy the mov; pop; ret, and 2 bytes of that other instruction.
        retPopAndMovInstructions = memory[retPopAndMovOffset..retPopAndMovOffset+8];

        // Find the actual ending of the function - where all the weird nops are
        const target = [0x90, 0x90, 0x90, 0x90]; // nop nop nop nop
        while(endOfLoadMapInstructions < memory.length - target.length)
        {
            if(memory[endOfLoadMapInstructions..endOfLoadMapInstructions+target.length] == target)
                return;
            endOfLoadMapInstructions++;
        }

        throw new Exception("Could not find end of LoadMap?");
    });
}
```

Then let's handle replacing the old instructions with our new `jmp` instruction:

```d
void patchFlagSettersIntoLoadMap(/*...*/)
{
    // ...

    // Reminder: relative jmps occur after the IP is updated, so we have to
    //           remove the extra bytes that are read as part of the jmp instruction.
    const relativeJumpOffset = (endOfLoadMapInstructions - retOffset) - 2;
    ubyte[8] jumpMiniDetourInstructions = [
        // jmp [rel NewEndOfLoadMap]
        0xE9,
        cast(ubyte)(relativeJumpOffset & 0xFF),
        cast(ubyte)((relativeJumpOffset & 0xFF00) >> (8 * 1)),
        cast(ubyte)((relativeJumpOffset & 0xFF0000) >> (8 * 2)),
        cast(ubyte)((relativeJumpOffset & 0xFF000000) >> (8 * 3)),
        0x90, // nop

        // Preserve existing instructions.
        retPopAndMovInstructions[6],
        retPopAndMovInstructions[7],
    ];
    // (second parameter needs to be relative to `loadMapSig.offset` - not important, just maths getting in the way of my hopes and dreams)
    enginePatcher.poke8Bytes(loadMapSig, retPopAndMovOffset - loadMapSig.offset, jumpMiniDetourInstructions);
}
```

We can now set the instruction our `jmp` points to, to be the flag unsetter instruction, while also moving over the other instructions we wanted to preserve:

```d
void patchFlagSettersIntoLoadMap(/*...*/)
{
    // ...

    const ubyte[8] unsetFlagInstructions = [
        // mov byte [FlagsAddress], 0
        0xC6, 0x05,
        cast(ubyte)(flagsAddress & 0xFF),
        cast(ubyte)((flagsAddress & 0xFF00) >> (8 * 1)),
        cast(ubyte)((flagsAddress & 0xFF0000) >> (8 * 2)),
        cast(ubyte)((flagsAddress & 0xFF000000) >> (8 * 3)),
        0x00,

        0x90, // nop
    ];

    const ubyte[8] preservedInstructions = [
        // mov
        retPopAndMovInstructions[0],
        retPopAndMovInstructions[1],

        // pop
        retPopAndMovInstructions[2],

        // ret
        retPopAndMovInstructions[3],
        retPopAndMovInstructions[4],
        retPopAndMovInstructions[5],

        0x90, 0x90 // nop nop
    ];

    endOfLoadMapInstructions -= loadMapSig.offset; // Make it relative to the start of the function, rather than the start of the memory map.

    enginePatcher.poke8Bytes(loadMapSig, endOfLoadMapInstructions, unsetFlagInstructions);
    enginePatcher.poke8Bytes(loadMapSig, endOfLoadMapInstructions+32, preservedInstructions);
}
```

And after that slightly annoying, kind of confusing dance that was just performed, I loaded up the game; performed the injection, and observed that the flag was `1` during the loading screen, and `0` afterwards.

Huzzah, the pain's not over yet.

## MVP - The rest of the owl

I won't cover this part too much, but this is essentially when I started to get the basic UI + timer logic together. My timer logic isn't overly accurate, and the UI code isn't anything special, hence why I'm not really covering it.

The main part that's interesting is the update controller, which gets ran on every UI tick (yep... UI logic and update logic aren't separate...):

```d
auto deusExController(
    Timer timer,
    Label mapLabel,
    SplitList splitList,
    GameProcess deusex,
    size_t flagsAddress,
    size_t lastLoadedMapAddress,
)
{
    import core.time : Duration;
    import std.algorithm : canFind;

    enum State
    {
        waitingForFirstLoad,
        normal,
        endCutscene,
    }
    State state;
    bool wasLoadingLastTick;
    bool endOnce;
    string lastLoadedMap;

    return delegate (Duration _, BackgroundUpdate __, UiInput ___){
        // process_vm_readv sometimes fails with ESRCH and I have no idea why, so ignore any errors for now.
        bool isLoading = false;
        try isLoading = deusex.peek!bool(flagsAddress);
        catch(Exception) return;

        scope(exit) wasLoadingLastTick = isLoading;
        splitList.updateElapsedTime(timer.elapsed);

        if(wasLoadingLastTick && !isLoading)
        {
            FStringNoCap lastLoadedMapPtr;
            while(true)
            {
                try lastLoadedMapPtr = deusex.peek!FStringNoCap(lastLoadedMapAddress);
                catch(Exception) continue;
                break;
            }

            if(lastLoadedMapPtr.ptr > 0)
            {
                // ...
                lastLoadedMap = toDString(deusex, lastLoadedMapPtr).stripRight.stripRight("\0");
                // ...
            }
        }

        void restart()
        {
            state = State.waitingForFirstLoad;
            mapLabel.text = "Restart was detected";
            timer.reset();
            splitList.reset();
        }

        // D fact: The `with` statement allows you to introduce an implicit lookup scope.
        //         So `State.waitingForFirstLoad` can simply become `waitingForFirstLoad`.
        //
        // Also:   `final switch` will crash if their implicit `default` case is taken,
        //          great for exhaustive enum switching!
        final switch(state) with(State)
        {
            case waitingForFirstLoad: // ...
            case normal: // ...
            case endCutscene: // ...
        }
    };
}
```

It showcases how the `peek` functions are being used, and teases further the "last loaded map" stuff, which, speaking about that...

## Last Loaded Map - research

The autosplitter cannot work solely off of whether we're in a loading screen or not since any given loading screen doesn't necssarily mean that a new map is being loaded. e.g. Reloading the current map is used/abused to perform some major glitches during the speedrun, so the only safe way to know whether we've actually gone onto a different map, is by figuring out which map the game loaded.

To start, while I've been referring to LoadMap as `LoadMap` - its full mangled signature looks like this:

```
?LoadMap@UGameEngine@@UAEPAVULevel@@ABVFURL@@PAVUPendingLevel@@PBV?$TMap@VFString@@V1@@@AAVFString@@@Z
```

Which, when put through a [demangler](https://demangler.com/) comes out as:

```c++
public: virtual class ULevel * __thiscall UGameEngine::LoadMap(
    class FURL const &,
    class UPendingLevel *,
    class TMap<class FString,class FString> const *,
    class FString &
)
```

There's several potential leads here to learn about what map the game is trying to load:

1. The return type is a `ULevel`, which may include the map name as a field.
2. The first parameter is an `FURL`, which might be a path to a map file to load.
3. The second parameter also sounds like it could contain a path or name about what to load.
4. ... And so could the last parameter.

I'm can't remember exactly why, but I decided to first look into checking out the return value to obtain the map name, rather than have a peek at the parameters.

I couldn't really find much comprehensive documentation about the `__thiscall` convention, but from a quick glance at the dissambled code, it looked like it was using the `eax` register to provide the returned `ULevel*` - strangely standard coming from a convention made by Microsoft.

So I hooked up LLDB, added a breakpoint onto LoadMap's `ret` instruction, and began having a poke around in memory:

```bash
# Getting the pointer stored in eax
(lldb) reg read eax
     eax = 0x0af91400

# Having a peek at the memory being pointed to
(lldb) mem read 0x0af91400 -c 0xFF
0x0af91400: fc 8a 42 10 85 b9 00 00 e0 d2 42 05 00 00 00 00  ..B.......B.....
0x0af91410: 00 78 39 06 95 0e 00 00 e0 b6 5a 06 41 00 07 60  .x9.......Z.A..`
0x0af91420: 67 56 00 00 58 8b 58 10 d4 8a 42 10 00 c0 fb 04  gV..X.X...B.....
0x0af91430: 7c 04 00 00 3f 05 00 00 00 14 f9 0a 00 00 00 00  |...?...........
0x0af91440: 00 ee 6f 01 3a c7 60 01 07 00 00 00 07 00 00 00  ..o.:.`.........
0x0af91450: 00 00 00 00 00 00 00 00 00 00 00 00 6e 1e 00 00  ............n...
0x0af91460: ac 9e b2 08 09 00 00 00 09 00 00 00 28 e3 5f 06  ............(._.
0x0af91470: 02 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00  ................
0x0af91480: 00 00 00 00 01 00 00 00 00 00 00 00 00 00 d9 08  ................
0x0af91490: d7 06 00 00 d7 06 00 00 00 f0 06 0b 00 00 00 00  ................
0x0af914a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x0af914b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x0af914c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x0af914d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x0af914e0: 00 00 00 00 38 0e e6 0a 01 00 00 00 01 00 00 00  ....8...........
0x0af914f0: 20 6e b7 02 08 00 00 00 00 00 cb 04 c0 08 5d      n............]
```

The situation here is that I'm looking for the map name, specifically this means I'm looking for something resembling a string/character array.

Most standard array types are implemented with the following layout:

```d
struct Array(T)
{
    T* ptr;
    size_t length;
    size_t capacity; // sometimes
}
```

So in other words I wanted to look for any two pairs of four bytes (since DeusEx is a 32-bit game), where the first four bytes look like a pointer (a bunch of seemingly 'random' bytes) and where the second four bytes looked like a length (a smaller number where most of the bytes should be 0).

I tried a couple of pairs that looked like what I wanted, before I ended up on this particular part, which is 0x60 bytes into where the pointer in `eax` points to:

```bash "ac 9e b2 08" "09 00 00 00"
0x0af91460: ac 9e b2 08 09 00 00 00 09 00 00 00 28 e3 5f 06  ............(._.
```

The two `09 00 00 00` side by side looked suspiciously like a length + capacity pair, and it followed the `ac 9e b2 08` which looked suspiciously like a pointer.

Following the pointer, we get the following result:

```bash
(lldb) mem read 0x08b29eac -c 0x09
0x08b29eac: 30 00 30 00 5f 00 49 00 6e    0.0._.I.n
```

It _kinda_ looks like string data, but is obviously incomplete. The hint here is that the game is actually using a 2-byte character type (there's a 00 between each ascii character, potentially UTF-16?), so instead of reading 9 bytes, we just have to read in 18 instead:

```bash
(lldb) mem read 0x08b29eac -c 0x12
0x08b29eac: 30 00 30 00 5f 00 49 00 6e 00 74 00 72 00 6f 00  0.0._.I.n.t.r.o.
0x08b29ebc: 00 00                                            ..
```

et voila, we know that 0x60 bytes within a `ULevel` points to a map name, and that we can easily access the `ULevel*` that LoadMap returns.

I expected this to be a _lot_ more painful to figure out, especially since I actually did some fruitless string searching in my initial hacky attempts. At least I found out why I couldn't find the string "00_Intro" in memory before... because of the 2-byte character type ;(

The LoadMap function signature has a parameter typed as `FString`, so I named the D version `FStringNoCap` as I had no interest in the capacity field.

```d
struct FStringNoCap
{
    uint ptr;
    uint length;
}
```

## Last Loaded Map - reading it from the timer

This process is largely familiar already:

1. Remember we left some extra nops between our "flag unsetter" and "return" instructions. This is the perfect place to store our next bit of code.
2. We just need to stuff the pointer `*(eax + 0x60)` and the length `*(eax + 0x64)` somewhere we can read it later.
3. We have plenty of unused space around where we store the loading flag, so we can just stuff the values there.

Here's how it was implemented:

```d
void patchFlagSettersIntoLoadMap(/*...*/)
{
    const ubyte[8][3] stashMapNameInstructions = [
        [
            // eax (used as the return register) contains a ULevel. ULevel + 0x60 is a string type,
            // where the first four bytes is a pointer to the raw string data. This string is the level name.

            // mov dword ecx, [eax + 0x60]
            0x8B, 0x48, 0x60,

            // mov [LastLoadedMapPtr], ecx
            0x89, 0x0D,
            cast(ubyte)(lastLoadedMapAddress & 0xFF),
            cast(ubyte)((lastLoadedMapAddress & 0xFF00) >> (8 * 1)),
            cast(ubyte)((lastLoadedMapAddress & 0xFF0000) >> (8 * 2)),
        ],
        [
            // Last byte of the previous instruction
            cast(ubyte)((lastLoadedMapAddress & 0xFF000000) >> (8 * 3)),

            // We also need to stash the length so we know exactly how much memory to read, otherwise
            // we'd have to write a (potentially) slooow loop.
            0x8B, 0x48, 0x64, // mov dword ecx, [eax + 0x64]

            // mov [LastLoadedMapLength], ecx
            0x89, 0x0D,
            cast(ubyte)((lastLoadedMapAddress + 4) & 0xFF),
            cast(ubyte)(((lastLoadedMapAddress + 4) & 0xFF00) >> (8 * 1)),
        ],
        [
            // Last two bytes of the previous instruction
            cast(ubyte)(((lastLoadedMapAddress + 4) & 0xFF0000) >> (8 * 2)),
            cast(ubyte)(((lastLoadedMapAddress + 4) & 0xFF000000) >> (8 * 3)),

            // nops
            0x90,0x90,0x90,0x90,0x90,0x90,
        ]
    ];

    enginePatcher.poke8Bytes(loadMapSig, endOfLoadMapInstructions+8, stashMapNameInstructions[0]);
    enginePatcher.poke8Bytes(loadMapSig, endOfLoadMapInstructions+16, stashMapNameInstructions[1]);
    enginePatcher.poke8Bytes(loadMapSig, endOfLoadMapInstructions+24, stashMapNameInstructions[2]);
}
```

From there, the update controller is able to read in the map name:

```d
auto deusExController(/*...*/, size_t lastLoadedMapAddress)
{
    // ...
    FStringNoCap lastLoadedMapPtr;
    while(true)
    {
        try lastLoadedMapPtr = deusex.peek!FStringNoCap(lastLoadedMapAddress);
        catch(Exception) continue;
        break;
    }

    if(lastLoadedMapPtr.ptr > 0)
    {
        import std.string : stripRight;
        lastLoadedMap = toDString(deusex, lastLoadedMapPtr).stripRight.stripRight("\0");
        mapLabel.text = lastLoadedMap;
    }
    // ...
}
```

And finish off most of the other un-mentioned logic used by the timer to keep track of current map, as well as perform autosplitting.

The `toDString` function basically just converts the 2-byte characters into 1-byte characters, since the game only uses ASCII for the map names anyway.

And that's _basically it_ from the complicated side of things. At this point I sorted out the logic for saving and loading splits; updated the UI to be a bit more usable, and so on. All relatively boring stuff.

## Issue - exception handling isn't patched

During the any% speedrun route used for DeusEx, you'll have to use a glitch called the "Glitchy Save".

I don't know the details behind it, but you essentially create a save during a third person cutscene, and then any attempts to load this save breaks the game script in useful ways.

The problem is that loading a Glitchy Save causes LoadMap to take a different branch, as it has to handle an exception being thrown during loading. This means the logic for unsetting the loading flag (and fetching the map name) will never trigger, as a that entire section of code doesn't get executed.

This means the timer will be permanently paused until a valid map is loaded. I added a hacky way around this by keeping a list of levels that require the glitchy save, and making it so the timer will never pause on these levels, but it's a less than ideal solution.

I haven't really had the energy or motivation to look into this properly, but it shouldn't be too much of a hassle to eventually fix... hopefully.

## Issue - Save screens aren't handled at all

The timer should also be trying to eliminated the time it takes to create a save, but currently I've not even attempted to bother with that - largely due to lack of motivation.

It should be very straightforward though, since I don't even need to add any "fetch map name" logic. It'd just need the "is saving" flag logic.

## Improvement - use a different mechanism for detecting loading transitions

Currently the timer will attempt to check the state of the loading flag + last loaded map name, every UI tick (8ms).

The issue is that the syscalls being performed for reading appear to cause the game to stutter in a slight but noticable way, making it a bit less pleasent to play.

I've been brainstorming a whole bunch on more efficient methods for detecing when "not loading -> loading" and vice versa transition occurs, namely around trying to generate a Linux signal from the game's side that then gets caught by the timer.

I haven't found the energy yet to do some R&D around this solution, but in theory it _could_ work and help me avoid this currently janky method. It would require a decent refactor of both the timer logic and code injection though.

## Conclusion

This article covered a ton of stuff from:

- Linux syscalls.
- Special Linux directories.
- Several cool features of D.
- A deeper dive into a single function of DeusEx than most people would ever care about.
- Basic assembly.

I'm too tired to write a cheesy outro. bye.
