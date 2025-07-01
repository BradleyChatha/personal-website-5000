---
slug: features-of-d-that-i-love
title: 10 features of D that I love
published: 2025-07-01
updated: 2025-07-01
order: 0
---

This is a beginner-friendly post exploring some of my favourite parts of the [D programming language](https://dlang.org/), ranging from smaller quality of life stuff, to more major features.

I _won't_ talk much about D's metaprogramming in this post as that topic basically requires its own dedicated feature list, but I still want to mention that D's metaprogramming is world class - allowing a level of flexibility & modelling power that few statically compiled languages are able to rival.

I'll be providing some minimal code snippets to demonstrate each feature, but this is by no means an in depth technical post, but more of an easy to read "huh, that's neat/absolutely abhorrent!" sort of deal.

## Summary

## Feature - Automatic constructors

If you define a struct (by-value object) without an explicit constructor, the compiler will automatically generate one for you based on the lexical order of the struct's fields.

```d
struct Vector2
{
    int a;
    int b;

    /++ Automatically generates this constructor:

    this(int a = int.init, int b = int.init)
    {
        this.a = a;
        this.b = b;
    }

    ++/
}

void main()
{
    const noParams = Vector2();
    const oneParam = Vector2(20); // Sets .a to `20`
    const twoParams = Vector2(20, 40); // Sets .a to `20` and .b to `40`
}
```

Very handy for Plain Old Data types, especially with the semi-recent support for [named parameters](https://dlang.org/spec/expression.html#argument-parameter-matching).

## Feature - Design by contract

D supports [contract programming](https://en.wikipedia.org/wiki/Design_by_contract) which allows functions to define:

- "in" assertions to confirm that the function's parameters are valid.
- "out" assertions to confirm that the function's return value is in a valid state.

Additionally you can attach "invariants" onto structs and classes. Invariants are functions that run at the start and end of every **public** member function, and can be used to ensure that the type is always in a valid state.

Let's start off with a contrived example of invariants:

```d
// Example of invariants
struct PositiveBound
{
    private
    {
        int _lower;
        int _upper;

        // Arbitrary function syntax
        invariant
        {
            assert(_lower >= 0, "_lower must not be negative");
            assert(_upper >= 0, "_upper must not be negative");
        }

        // Short hand syntax, translates to a single `assert()`.
        invariant(_upper >= _lower, "_upper must not be less than _lower");
    }

    this(int lower, int upper)
    {
        // invariants don't run at the start of constructors.

        this._lower = lower;
        this._upper = upper;

        // invariants are called.
    }

    void upper(int upper)
    {
        // invariants are called.

        this._upper = upper;

        // invariants are called again.
    }

    private void setLower(int lower)
    {
        // Function is non-public, invariants aren't called.
        this._lower = lower;
    }
}
```

Now let's rewrite the above type to use "in" contracts instead, with an extra function to show off "out" contracts:

```d
// Example of in/out contracts
struct PositiveBound
{
    private
    {
        int _lower;
        int _upper;
    }

    this(int lower, int upper)
    in(lower >= 0, "lower must not be negative")
    in(upper >= lower, "upper must not be less than lower")
    {
        // `in` functions are called.
        this._lower = lower;
        this._upper = upper;
    }

    void upper(int upper)
    in(upper >= this._lower, "upper must not be less than lower")
    {
        this._upper = upper;
    }

    private void setLower(int lower)
    in(lower >= 0, "lower must not be negative")
    {
        this._lower = lower;
    }

    int numbersInRange()
    out(result; result >= 0, "result is somehow negative?")
    out(result; this._upper == this._lower || result != 0, "upper and lower are different numbers, but result is somehow 0?")
    {
        return this._upper - this._lower; // `out` functions are called, with (this._upper - this._lower) as their parameter.
    }
}
```

This can allow for an easy self-descriptive validation pattern for consumers/readers of your code, as well as an easy to implement self-checking mechanism for types that have complex internals.

Anecdotally I find this to be an underutilised feature of D, and it's one I like to make use of a lot in my own code.

## Syntax - The dollar operator

A lot of languages do not provide a shorthand syntax for referencing the length of an array, which can sometimes lead to awkward looking code when e.g. slicing arrays (any Go enjoyers here?).

D provides the dollar operator, which is a shorthand syntax for referencing the length of something.

```d
auto foo = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
auto bar = foo[5..$-2]; // Same as: foo[5..foo.length-2]
```

Structs and classes can even [overload](https://dlang.org/spec/operatoroverloading.html#dollar) this operator.

## Feature - CTFE (Compile Time Function Execution)

D compilers provide an interpreter for the language which allows a very large amount of D code to be ran at compile time, as-is, without any special marking or other weirdness to go with it.

Generally, anywhere where the language requires a compile-time constant is a place where CTFE will transparently come into play.

```d
import std.algorithm : filter;
import std.array     : array;
import std.range     : iota;

// As we're setting a global variable, the value must be a compile-time constant.
//
// Due to CTFE, we can just use normal D functions to compute a value for us.
immutable ALL_EVEN_NUMBERS_UNDER_1000 = iota(0, 1000).filter!(n => n % 2 == 0).array;

// pragma(msg) can write to stdout during compile time, thus requiring a compile-time constant.
// We can use this to confirm that everything is only happening during compilation.
pragma(msg, ALL_EVEN_NUMBERS_UNDER_1000); // [0, 2, 4, 8, ...
```

This feature has a lot of different practical applications, and can allow for much cleaner, robust code than hardcoding precomputed values.

Since a lot of use cases relate to metaprogramming I'll leave the topic here, but CTFE is an extremely instant example of D's unusual feature set.

## Feature - Built-in unittests

D has direct support for defining unittests, and even allows you to override the built-in test runner for something more robust (such as with the [unit-threaded](https://code.dlang.org/packages/unit-threaded) library).

D code usually bundles unittests and normal code within the same file, rather than splitting them out into separate files as with most other languages:

```d
int add(int a, int b) => a + b;
unittest
{
    assert(add(60 + 8) == 68, "60 + 8 is somehow not equal to 68");
}

// If you give a unittest an empty documentation comment (`///`), then D's built in documentation
// generator will generate an "example" block using the test code!

int sub(int a, int b) => a - b;
///
unittest
{
    assert(sub(70, 2) == 68);
}
```

This extremely low-friction barrier for writing tests is a godsend for motivating people to write even the most minimal of tests.

Of course if you have more complex needs then the option to have a proper testing framework + structure is still available to you, but the vast majority of D code I've seen simply uses `unittest` blocks, optionally with a library that provides a better test runner.

## Feature - Exhaustive switch statements

D provides a `final switch` statement which has an autogenerated `default:` case that will immediately crash the program if its taken.

This allows you to define a switch that will always alert you if a new value needs to be added, or if an invalid value was somehow passed into it.

Additionally, if you use a `final switch` with an `enum` value, then a compile-time check is triggered to ensure that every value within the `enum` type has been declared, making it impossible to forget to add a new case when the enum is modified.

```d
enum OutputType
{
    file,
    stdout
}

void main()
{
    auto output = OutputType.stdout;

    // Exhaustive switching with a compile time check.
    final switch(output)
    {
        case OutputType.file:
            // ...
            break;

        case OutputType.stdout:
            // ...
            break;
    }

    // Exhausitve switching with no compile time check, may trigger a `SwitchError` at runtime.
    auto str = "not my string";
    final switch(str)
    {
        case "my string":
            // ...
            break;

        // Any other value will crash the program (unless the SwitchError is caught, which you shouldn't do outside of tests).
    }
}
```

## Syntax - Parenthesis omission

D allows you to omit parentheses when calling functions in multiple contexts.

When calling a function with no parameters, you can omit them:

```d
struct Person
{
    private string _name;

    string name() => this._name;
}

void main()
{
    import std.stdio : writeln;

    auto person = Person("Brad");
    writeln(person.name); // Instead of: writeln(person.name())
}
```

(Marginally related) When calling a function with 1 parameter, you may use assignment syntax instead:

```d
struct Person
{
    private string _name;

    void name(string name)
    {
        this._name = name;
    }
}

void main()
{
    Person person;
    person.name = "Brad"; // Instead of: person.name("Brad")
}
```

When passing a single template parameter which consists of only 1 lexical token, you may omit the parenthesis:

```d
import std.conv : to;

void main()
{
    auto number = "20".to!int; // Instead of "20.to!(int)" or "20.to!(int)()"
}
```

This can do wonders for readability.

## Syntax - UFCS (Uniform Function Call Syntax)

UFCS allows call chains to be "inverted" by allowing freestanding functions to be used as if they were a member of their first parameter.

In other words: `baz(bar(foo))` can be rewritten as `foo.bar().baz()`.

The two following snippets are completely equivalent in function, except the second snippet uses UFCS to provide a more clean look.

```d
import std.algorithm : filter, map;
import std.range     : iota;
import std.stdio     : writeln;

// Without UFCS
void main()
{
    writeln(map!(num => num * 2)(
        filter!(num => num % 2 == 0)(
            iota(0, 10_000)
        )
    ));
}
```

```d
import std.algorithm : filter, map;
import std.range     : iota;
import std.stdio     : writeln;

// With UFCS
void main()
{
    iota(0, 10_000)
        .filter!(num => num % 2 == 0)
        .map!(num => num * 2)
        .writeln();
}
```

## Feature - Scoped & Selective Imports

D supports limiting imports to a specific scope, whether that be a singular if-statement, an entire function, an entire struct/class, etc.

D will also allow you to selectively import symbols from other modules, instead of polluting your lookup scope with a ton of unrelated stuff - also helps increase comprehension of the codebase.

```d
// (slightly contrived example)

import std.algorithm : joiner; // Scoped to the entire module.

struct Person
{
    import std.algorithm : filter; // Scoped to everything in this struct.

    string[] names;

    void printNames()
    {
        import std.stdio : write, writeln; // Scoped only to this function.

        if(this.names.length > 1)
        {
            import std.algorithm : each; // Scoped only to this branch.
            this.names.filter!(name => name.length > 0)
                      .joiner(" ")
                      .each!write;
            writeln();
        }
        else
            writeln(this.names[0]);
    }
}

void main()
{
    Person(["Bradley", "Chatha"]).printNames();
    Person(["Shmradley"]).printNames();
}
```

While it may seem like clutter and extra effort, in the long run this allows for:

1. Making it easy for newcomers to understand where certain functions are coming from.
2. Allows for code to become "portable" between files since the code can carry most of its external dependencies inside of itself, making refactoring a bit easier.

## Feature - Built-in documentation generator

Finally, D has a built-in documentation generator with a relative standard, easy to read format.

There's also a handful of documentation tools that are detached from the built-in one since the default generated output is a bit lacklustre (_cough_ I'm plugging my [custom tool](https://github.com/Juptune/marmos) here).

Here's a relatively extreme example from one of my personal projects, to get an idea of the basic format:

```d
/++
 + Parses a URI from a string into a `ScopeUri`, which specifically does not contain any copy of the input
 + data, but instead slices from the original `input` slice.
 +
 + This means the returned `ScopeUri` is only valid for as long as the `input` slice is valid and unmodified.
 +
 + This function is intended to be used when the caller wants to avoid copying the input data, and is willing
 + to accept the limitations and risks of a `ScopeUri`.
 +
 + Please report any non-compliance with RFC 3986 as a bug.
 +
 + Valid Formats:
 +  isAbsolute
 +      -> scheme://user:info@host:port/path?query#fragment, e.g. "http://user:info@localhost:8080/some/path?some=query#some-fragment"
 +
 +  isNetworkReference
 +      -> //user:info@host:port/path?query#fragment, e.g. "//user:info@localhost:8080/some/path?some=query#some-fragment"
 +
 +  !isAbsolute && !isNetworkReference && pathIsAbsolute
 +      -> /path?query#fragment, e.g. "/some/path?some=query#some-fragment"
 +
 +  pathIsRootless
 +   only if `UriParseRules.allowUriSuffix` IS NOT set.
 +      -> path?query#fragment, e.g. "some/path?some=query#some-fragment"
 +
 +  isUriSuffix
 +    only the host component is supported within the authority - port and user info are not supported
 +       due to their colons causing the URI to be seen as an absolute URI, which will likely generate an error.
 +    only if `UriParseRules.allowUriSuffix` IS set.
 +       -> host/path?query#fragment, e.g. "localhost/some/path?some=query#some-fragment"
 +
 + Please see the individual, lower level parsing functions for the exact details of each component.
 +
 + Notes:
 +  The output of all `out` parameters is undefined if the function returns an error.
 +
 +  This parser will attempt to heuristically determine whether the start of the URI
 +  is a scheme or an authority. Please note that errors in a scheme may manifest as an error in the
 +  authority component.
 +
 +  If it's not clear, you can use `uri.hints` to determine the exact structure of the URI.
 +
 + Params:
 +  input = The input string to parse
 +  uri   = The `ScopeUri` to write the parsed URI to
 +  rules = A set of rules that can be used to control the behaviour of the URI parser
 +
 + Throws:
 +  Anything that `uriParseScheme`, `uriParseAuthority`, `uriParsePath`, `uriParseQuery`, or `uriParseFragment` can throw.
 +
 + Returns:
 +  A `Result` indicating whether the parsing was successful or not.
 + ++/
Result uriParseNoCopy(
    const(char)[] input,
    out scope ScopeUri uri,
    UriParseRules rules = UriParseRules.strict
) @nogc @trusted nothrow // Note: It is actually @safe however compiler-generated temporaries trigger @safe deprecation warnings
in(input.length > 0, "Attempting to parse an empty string is likely incorrect logic. Null checks, people!")
{
    // ...
}
```

Here's an example from the standard library, which has minor usage of documentation macros:

```d
/**
Converts a hex literal to a string at compile time.

Takes a string made of hexadecimal digits and returns
the matching string by converting each pair of digits to a character.
The input string can also include white characters, which can be used
to keep the literal string readable in the source code.

The function is intended to replace the hexadecimal literal strings
starting with `'x'`, which could be removed to simplify the core language.

Params:
    hexData = string to be converted.

Returns:
    a `string`, a `wstring` or a `dstring`, according to the type of hexData.

See_Also:
    Use $(REF fromHexString, std, digest) for run time conversions.
    Note, these functions are not drop-in replacements and have different
    input requirements.
    This template inherits its data syntax from builtin
    $(LINK2 $(ROOT_DIR)spec/lex.html#hex_string, hex strings).
    See $(REF fromHexString, std, digest) for its own respective requirements.
 */
template hexString(string hexData)
if (hexData.isHexLiteral)
{
    // ...
}
```

## Conclusion

I tried to focus more on the more simpler day-to-day features, with only a splattering of the bigger more complicated stuff.

Hopefully this provides some insight on the wacky-yet-wonderful feature set that D provides.
