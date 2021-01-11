# build env
FROM node:14-alpine as build

COPY ./frontend /frontend
WORKDIR /frontend
RUN npm install && npm run build && rm -rf node_modules

# prod env
FROM python:3.8-slim-buster

RUN apt-get update \
  && apt-get install -y \
  # Install dependencies for puppeteer
  # Ref. https://github.com/puppeteer/puppeteer/blob/master/docs/troubleshooting.md#chrome-headless-doesnt-launch-on-unix
  fonts-liberation \
  libappindicator3-1 \
  libasound2 \
  libatk-bridge2.0-0 \
  libatk1.0-0 \
  libc6 \
  libcairo2 \
  libcups2 \
  libdbus-1-3 \
  libexpat1 \
  libfontconfig1 \
  libgbm1 \
  libgcc1 \
  libglib2.0-0 \
  libgtk-3-0 \
  libnspr4 \
  libnss3 \
  libpango-1.0-0 \
  libpangocairo-1.0-0 \
  libstdc++6 \
  libx11-6 \
  libx11-xcb1 \
  libxcb1 \
  libxcomposite1 \
  libxcursor1 \
  libxdamage1 \
  libxext6 \
  libxfixes3 \
  libxi6 \
  libxrandr2 \
  libxrender1 \
  libxss1 \
  libxtst6 \
  lsb-release \
  wget \
  xdg-utils \
  # Install dependencies for YARA
  # Ref. https://yara.readthedocs.io/en/latest/gettingstarted.html
  automake \
  libtool \
  make \
  gcc \
  pkg-config \
  # Install dependencies for Uzen
  dnsutils \
  procps \
  && apt-get clean  \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /uzen

COPY pyproject.toml /uzen
COPY poetry.lock /uzen
COPY .env.sample /uzen/.env
COPY app /uzen/app
COPY --from=build /frontend /uzen/frontend

RUN pip3 install poetry && poetry config virtualenvs.create false && poetry install --no-dev

ENV PLAYWRIGHT_BROWSERS_PATH /uzen/playwright

RUN mkdir -p /uzen/playwright && python -m playwright install
RUN rm -rf /uzen/playwright/webkit-* && rm -rf /uzen/playwright/firefox-*

ENV PORT 8000

EXPOSE $PORT

CMD uvicorn --host 0.0.0.0 --port $PORT app:app
