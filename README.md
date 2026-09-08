# AnyDns

An anyio extension featuring compatability of multiple different
asynchronous dns resolver libraries. The concept follows the same
concept as anyio itself where trio and asyncio can be used
either way. This library also adds useful additional tools such as 
[msgspec](https://msgspec.dev/) which can allow you to convert your DNS resuls in whatever way you want or even let you host your own applications with litestar.

## Supported Libraries
This library takes __c-ares__ libraries currently but many more
    implementations could be easily added on in the future
    as long as they follow the basic concept of anyio support
    with the ability to run on Windows, Linux and Apple.

## Current Usage
Frontend is still being worked on for now but currently picking the library installed should be enough for now.

```python
import anyio

from anydns.cyares import DNSResolver

# this will also work
from anydns.pycares import DNSResolver

async def main():
    async with DNSResolver(["8.8.4.4","1.1.1.1"], timeout=2) as r:
        info = await r.gethostbyaddr("50.87.249.219")
    # HostResult(name='box2079.bluehost.com', aliases=['box2079.bluehost.com'], addresses=['50.87.249.219'])
    print(info)


if __name__ == "__main__":
    anyio.run(main)
```


### cyares
Cyares is implemented as a backend that uses the `.cyares` module.
It utilizes __c-ares__ and __cython__ and was made out of pure inspiration of __pycares__ (by the same author of this library even)
with the goal of added features, extreme speed and a few other safety mechanisms. 

> [!NOTE]
>
> It should be noted that pycares and cyares have event-threads disabled, this was done to prevent the possibilities involving deadlocks and also because anyio supplies it's own selectors for you so you shouldn't ever have to worry about supplying your own read or write selectors.

```
pip install anydns[cyares]
```


### pycares
Pycares was implemented as a backend that uses the `.pycares` module.
It utilizes __c-ares__ and __cffi__. __pycares__ this is also a very mature library with over a decade of maitenence.

> [!NOTE]
>
> It should be noted that pycares and cyares have event-threads disabled, this was done to prevent the possibilities involving deadlocks and also because anyio supplies it's own selectors for you so you shouldn't ever have to worry about supplying your own read or write selectors.


```
pip install anydns[pycares]
```


## Installing everything
If you need to test every single supported backend under the sun when developing your applications (example: testing each one out and checking for bugs) do this

```
pip install anydns[all]
```


## Adding your library to the current List.
If you have a dns library of your own that you want to include
the following criteria must be met.

- must support all operating systems on a PC but mostly the main 3        
    -  Windows, Linux, Apple
- must be compatable with anyio's system
- must be subclassed from `AbstractDNSResolver`


## Current State 
Tests are on my todolist but a release should be coming out soon.
