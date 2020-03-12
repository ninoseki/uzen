# build env
FROM node:13-alpine as build

COPY ./frontend /frontend
WORKDIR /frontend
RUN npm install && npm run build && rm -rf node_modules

# prod env
FROM python:3.8-slim-buster

RUN apt-get update \
  && apt-get install -y \
  curl gnupg python3-dev build-essential gconf-service \
  libasound2 libatk1.0-0 libc6 libcairo2 libcups2 \
  libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 \
  libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 \
  libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \
  libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
  libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \
  ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release \
  xdg-utils wget \
  && apt-get clean  \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install pipenv

WORKDIR /app

COPY Pipfile /app
COPY Pipfile.lock /app
COPY .env.sample /app/.env
COPY uzen /app/uzen
COPY --from=build /frontend /app/frontend

RUN pipenv install --deploy --system \
  && pyppeteer-install

ENV PORT 8000

EXPOSE $PORT

CMD uvicorn --host 0.0.0.0 --port $PORT uzen:app
