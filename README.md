# rawsight
A raw packet dissector for x86-64 Linux. Captures and parses live  network traffic at the binary level — no libpcap, no abstractions. Built to understand how protocol stacks actually work from the byte up.


## Architecture

rawsight uses a hybrid C/C++ design for the same reason 
network stacks themselves are layered:

**C (Capture Engine)** — raw socket management, epoll I/O loop, 
and all protocol header parsing are written in pure C. Network 
programming at this level is a C domain — the structs map directly 
to wire formats and there are no abstractions between your code 
and the bytes.

**C++ (Analysis Layer)** — packet filtering, storage, and display 
are handled by a C++ engine. STL containers manage captured packet 
history cleanly and RAII ensures no buffer leaks when the capture 
session ends.
