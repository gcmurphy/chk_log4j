### chk_log4j - Tool to find jar files which are vulnerable to log4j CVE-2021-44228.


#### Install

1. `git clone https://github.com/gcmurphy/chk_log4j`
2. `cd chk_log4j && cargo install --path .`


#### Usage

The tool only checks a single file so it is best combined with something like [fd](https://github.com/sharkdp/fd).

```
$ fd -a -e jar -x chk_log4j
```

