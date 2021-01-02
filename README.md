# Uzen: YARA with Puppeteer

[![CircleCI](https://circleci.com/gh/ninoseki/uzen.svg?style=shield)](https://app.circleci.com/pipelines/github/ninoseki/uzen)
[![Coverage Status](https://coveralls.io/repos/github/ninoseki/uzen/badge.svg?branch=master)](https://coveralls.io/github/ninoseki/uzen?branch=master)
[![CodeFactor](https://www.codefactor.io/repository/github/ninoseki/uzen/badge)](https://www.codefactor.io/repository/github/ninoseki/uzen)

Uzen is an application combines YARA and headless Chrome. Uzen provides two main functions:

- Record a website with headless Chrome (by using [pyppeteer](https://github.com/pyppeteer/pyppeteer)).
- Scan recorded websites with [YARA](https://virustotal.github.io/yara/).

It can be used for phishing and web-based c2 detection.

**Note:** This project is in an alpha state.

## Table of Contents

- [Requirements](https://github.com/ninoseki/uzen/wiki/Requirements)
- [Installation](https://github.com/ninoseki/uzen/wiki/Installation)
- [Configuration](https://github.com/ninoseki/uzen/wiki/Configuration)
