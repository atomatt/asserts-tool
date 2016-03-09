# asserts-tool


## Overview

```
Usage:
  asserts-tool [OPTIONS] <assertion | check | key>

Help Options:
  -h, --help  Show this help message

Available commands:
  assertion  generate new assertion
  check      check assertion chain
  key        generate new key
```


## Generate a signing key

```
Usage:
  asserts-tool [OPTIONS] key

generate new key that can be used to sign assertions

Help Options:
  -h, --help      Show this help message
```


## Generate an assertion

```
Usage:
  asserts-tool [OPTIONS] assertion [assertion-OPTIONS] [file-name]

generate an assertion, signed by the assertion's authority-id

Help Options:
  -h, --help             Show this help message

[assertion command options]
      -s, --signing-key= signing key
```


## Verify assertion chain

```
Usage:
  asserts-tool [OPTIONS] check [check-OPTIONS] [file-name...]

check assertions chain can be loaded

Help Options:
  -h, --help             Show this help message

[check command options]
      -t, --trusted-key= trusted key
```
