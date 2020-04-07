# build env
FROM node:13-alpine as build

COPY ./frontend /frontend
WORKDIR /frontend
RUN npm install && npm run build && rm -rf node_modules

# prod env
FROM python:3.8-slim-buster

# ref. https://github.com/puppeteer/puppeteer/blob/master/docs/troubleshooting.md#chrome-headless-doesnt-launch-on-unix
RUN apt-get update \
  && apt-get install -y \
  # Install dependencies for puppeteer
  # Ref. https://github.com/puppeteer/puppeteer/blob/master/docs/troubleshooting.md#chrome-headless-doesnt-launch-on-unix
  gconf-service libasound2 libatk1.0-0 \
  libatk-bridge2.0-0 libc6 libcairo2 libcups2 \
  libdbus-1-3 libexpat1 libfontconfig1 libgcc1 \
  libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 \
  libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 \
  libx11-6 libx11-xcb1 libxcb1 libxcomposite1 \
  libxcursor1 libxdamage1 libxext6 libxfixes3 \
  libxi6 libxrandr2 libxrender1 \
  libxss1 libxtst6 ca-certificates \
  fonts-liberation libappindicator1 libnss3 \
  lsb-release xdg-utils wget \
  # Install dependencies for YARA
  # Ref. https://yara.readthedocs.io/en/latest/gettingstarted.html
  automake libtool make gcc pkg-config \
  # Install dependencies for Uzen
  dnsutils procps \
  && apt-get clean  \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml /app
COPY poetry.lock /app
COPY .env.sample /app/.env
COPY uzen /app/uzen
COPY --from=build /frontend /app/frontend

RUN pip3 install poetry && poetry config virtualenvs.create false && poetry install --no-dev

ENV PYPPETEER_HOME /app/pyppeteer

RUN mkdir -p /app/pyppeteer && pyppeteer-install

ENV PORT 8000

EXPOSE $PORT

CMD uvicorn --host 0.0.0.0 --port $PORT uzen:app
