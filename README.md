# HTTP Server

I created this http server to learn about the basics of how the web servers work. Learnt about sockets from the man pages, which I unfortunately never got much exposure to previously, about header parsing (which is like 90% of what I did), reading the RFC for HTTP/1.0 which is a fundamental document for anyone who wants to implement a web server.

Learnt some misc things like, POSIX functions <b>don't</b> actually return the error code but set the error code in the global errno variable, who knew! Decoding uri's, working with some low level system calls like bind, listen and accept.

Yeah, reading the RFC gets you sorted with what you want to do, really helpful.

Also had some fun with fork().

## References

1. [RFC for HTTP/1.0](https://datatracker.ietf.org/doc/html/rfc1945)
2. [This](https://www.reddit.com/r/C_Programming/comments/kbfa6t/comment/gfh8kid) very helpful reddit comment by u/Drach88
3. [Beej's Guide ](https://beej.us/guide/bgnet/)
4. Source code of [thttpd](https://acme.com/software/thttpd/)
5. [Eric's](https://www.youtube.com/watch?v=gk6NL1pZi1M) youtube playlist on this topic
