# Uzen: YARA with Puppeteer

Uzen is an application provides two main functions.

- Record a website with [Puppeteer](https://github.com/puppeteer/puppeteer).
- Scan recorded websites with [YARA](https://virustotal.github.io/yara/).

It can be used for phishing and web-based c2 detection.

Note: This project is in an alpha state.

## Requirements

- Node.js
- Python3 (and [pipenv](https://github.com/pypa/pipenv))
- SQLite

## Installation

```bash
git clone https://github.com/ninoseki/uzen
cd uzen
pipenv install
npm install
```

## Database initialization

Copy `.env.sample` over to `.env` and edit the parameters to match your environment.

```
DEBUG=False
DATABASE_URL=sqlite:////uzen.db
APP_MODELS=uzen.models,
```

Then run the following to create your application's database tables and perform the initial migration.

```bash
python init_db.py
```

## Deployment

```bash
# Build frontend assets
npm run build
# Start a server
uvicorn uzen:app
```

Your application is running at: http://localhost:8000/ in your browser.

## TODO

- Performance improvement for YARA scan.
- Enable to deal with a large amount of datasets.
- Enable to customize Puppeteer configuration.
- Dockerizing the application.
- Write more tests for both frontend and backend.
- Write docs.