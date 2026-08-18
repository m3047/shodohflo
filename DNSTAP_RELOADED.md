# `dnstap2json` and `dnstap_agent`... Reloaded!

July 2026

**What's going on?**

Major changes have been made to both `examples/dnstap2json.py` and `agents/dnstap_agent.py`. Hopefully these changes will
improve your workflow in the long run. If you're just taking the output of `dnstap2json.py` or `dnstap_agent.py` at _face value_
(as Sherry Turckle might say) you can keep on, keepin' on.

On the `fwm` branch this is still a work in progress.

## Changes, Changes

### Code changes

#### `FieldMapping` handlers

If you've written your own `FieldMapping` handlers: `p.field('response_message')` now returns a tuple of (`dns.message`, _raw data_),
so references need to change from `p.field('response_message')[1]` to `p.field('response_message')[1][0]`. This only affects
protobuf fields which are type `DnsMessageField`. See `shodohflo/protobuf/dnstap.py` for further information.

#### `bkf` field

There is an additional field in the JSON output: `bkf`. This is the count of backfilled (as opposed to forward) references.
See the following _Semantic changes_ section for further details.

### Semantic changes

### `SVCB` Compatible types

## _Capture_ and _Replay_: New Functionality to Support Your Workflow

## The Workflow

***rock and roll!***
