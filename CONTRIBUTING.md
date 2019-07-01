# Contributing

We welcome contributions. If you have questions about what might make a good (or better) contribution you're
encouraged to open an issue.

The rest of this document is divided into three parts:

* General guidance
* `shodohflo`: the _python_ package
* ShoDoHFlo: the application

## General Guidance

### User experience

Even command line programs and packages have a user experience. There should be a "happy path"; it should
be easy to find and stay on.

Python users, generally, want to be able to print out values. `pydoc` should return useful information, this
encompasses not only doc strings but embedded constants and meaningful method names if the methods are going
to be called from outside the module or redefined by subclasses. Consider documenting properties.

### Dependencies

In general these should be avoided when possible. If you introduce dependencies you will probably have to
justify them. Be careful about licensing of dependencies: this code is released under an _Apache 2.0_ license.

Dependencies, when necessary, should break as little as possible. As an example inside the `shodohflo` package,
the essential (and reusable) `shodohflo.fstrm` and `shodohflo.protobuf.protobuf` modules have NO dependencies.
You can clone this repo, `cd` into the toplevel directory, and run `pydoc3` on either of them (assuming your
`PYTHONPATH` allows it). `shodohflo.protobuf.dnstap` has a dependency on _dnspython_; you can't run `pydoc3`
on it without having _dnspython_ installed.

### Python style

Spaces not tabs. ;-) In general following the accepted style guidelines is a good idea, but there is no linter
being run on this codebase. That could happen someday, if code is re-used someplace which runs a linter and
code here causes problems.

"Protecting" users from themselves by not documenting things is not helpful. Point out the happy path, early
and often.

Weird hacks will be forgiven if they support the happy path. (`shodohflo.protobuf.Protobuf.Field()` is
probably a good example of this.)

## `shodohflo`: the _python_ package

It's unlikely that you'll need to ever modify either the core Frame Stream or Protobuf modules. Nonetheless,
the people who use these technologies care about performance, so bear that in mind.

### Examples

Examples are welcomed. They should go in the (toplevel) `examples/` directory. They should be documented.
They should be runnable, even if they don't do much out of the box.

Utilities will be considered, but maybe they should go in a separate repository, with a documentation pointer
here.

### Why are there no tests?

Blame me! I (Fred Morris) didn't write any tests for the Frame Streams implementation. I did write tests
for the Protobuffer primitives, you can find them here: https://github.com/m3047/tahoma_nmsg/tree/master/tests

In the time since there have been no (zero!) bugs reported or encountered. Tests are a good thing, really. I
sincerely believe that (they were helpful when I was originally writing that code). If you want to write
tests look at what I did there, and put them in a `tests/` directory at the toplevel.

However there is test _data_, intended for user interface testing. `app/testing/test_data.py` will load either
IP4 or IP6 data into _Redis_. This data includes not just ordinary flows, but NXDOMAIN, stuff which doesn't
have a "hard" NXDOMAIN by doesn't resolve (ANSWER:0), and CNAME loops.

### Other protobuf definitions

Other protobuf definitions (see `shodohflo.protobuf.dnstap`) will be accepted. Decide whether they belong here
or with the project they're related to; please only submit them to one or the other. Doc pointing to where to
find them is also fine, it can go in `__init__.py` or in a `README.md`.

## ShoDoHFlo: the application

* There is no reason to have only one UI.
* This codebase doesn't want to grow up to be a _TIP_ or _SIEM_.

Different kinds of people will use this application. Who knows, maybe there is some other application
which could be usefully built on top of it.

### Installers and installation

The simple case is someone installing everything on one machine. A complicated install might see the agents
installed on more than one machine (perhaps several, or several instances on a single machine monitoring
different interfaces), and the application on another.

Multiple installers and installation targets are welcomed! Documentation is equally as important as code.

### Agents for other applications

If you want to modify the agent code to support a _TIP_ or _SIEM_ that's great! Does it belong here, or
with the target application? Doc pointing to where to find agents for other applications is always welcomed.

### I want to write another UI

Cool! Does it belong here or in a separate repository? In any case we welcome doc pointing to it.

### I want to extend the UI

That's cool, too! Don't introduce additional dependencies or security/management issues into the core
UI and that's fine. Better would be some sort of optional or configurable install.

### Where's the RESTful interface?

There isn't one. Yet. If you want to write a single page app, let's talk. If you have some other purpose
in mind, again let's talk. I (Fred Morris) am willing to write or contribute to a RESTful interface.

