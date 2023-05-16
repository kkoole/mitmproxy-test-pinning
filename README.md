# mitmproxy-test-pinning

Collection of mitmproxy addons for automatically detecting certificate pinning misimplementations.

## Getting started

The addons in this repository were written for mitmproxy version 9.0.1.

First download mitmproxy 9.0.1 from https://mitmproxy.org/downloads/#9.0.1/

Next clone the repository

```git clone https://github.com/kkoole/mitmproxy-test-pinning``` 

## Usage

The addons can be used with mitmproxy as follows

```mitmproxy -s /path/to/repo/client_hello_addon.py```

