
# mlockall

## Intro
mlockall - lock all mapped pages into physical memory. 

## Description
mlockall allows the calling process to lock all its pages into physical memory. This means that the pages can not be swapped out, will not cause page faults, and will never be moved by any operation. The effect of this can, in some cases, offer better performance. 

There are two flags which can be used with mlockall: 

* MCL_CURRENT: Lock only currently mapped pages.
* MCL_FUTURE: Lock all pages which are mapped in the future.

## Arguments
* `flags`:`int`[K] - flags for mlockall operation. An ORed combination of values from mlockall(2) can be used.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### mlockall
#### Type
Kprobes
#### Purpose
To monitor processes which make use of mlockall and their interaction with the physical memory. 

## Example Use Case
On a real-time embedded system, processes may have a large total number of pages mapped. Under heavy workload, the pages may be swapped out during times of heavy system load. By using mlockall, the real-time processes may be preserved in physical memory. 

## Issues
The main drawbacks of mlockall is its high resource usage. When used, the amount of RAM available to the system will be limited. As a result, memory pressure can be an issue when mlockall is used on a system with multiple processes.

## Related Events
* mlock(2)
* munlockall(2)
* mlock2(2)

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracee recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.