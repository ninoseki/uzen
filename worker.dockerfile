# prod env
FROM python:3.9-slim-buster

RUN apt-get update \
  && apt-get install -y \
  # Install chromium dependencies
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
  fonts-noto-color-emoji \
  # Install language fonts
  locales \
  fonts-arphic-ukai \
  fonts-arphic-uming \
  fonts-ipafont \
  fonts-ipaexfont \
  fonts-unfonts-core \
  fonts-wqy-zenhei \
  fonts-thai-tlwg \
  fonts-kacst \
  fonts-freefont-ttf \
  # Install YARA dependencies
  # Ref. https://yara.readthedocs.io/en/latest/gettingstarted.html
  automake \
  libtool \
  make \
  gcc \
  pkg-config \
  # Install Uzen dependencies
  dnsutils \
  procps \
  whois \
  && apt-get clean  \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /uzen

COPY pyproject.toml /uzen
COPY poetry.lock /uzen
COPY app /uzen/app

RUN pip3 install poetry \
  && poetry config virtualenvs.create false \
  && poetry install --no-dev

ENV PLAYWRIGHT_BROWSERS_PATH /uzen/playwright

RUN mkdir -p /uzen/playwright \
  && python -m playwright install chromium

RUN  mkdir -p frontend/dist/static frontend/dist/images \
  && touch frontend/dist/index.html frontend/dist/images/not-found.png

CMD arq app.arq.worker.ArqWorkerSettings
