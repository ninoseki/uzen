# build env
FROM node:14-alpine as build

COPY ./frontend /frontend
WORKDIR /frontend
RUN npm install -g npm@8 && npm install && npm run build && rm -rf node_modules

# prod env
FROM python:3.9-slim-buster

RUN apt-get update \
  && apt-get install -y \
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
COPY --from=build /frontend /uzen/frontend

RUN pip3 install poetry \
  && poetry config virtualenvs.create false \
  && poetry install --no-dev

ENV PORT 8000

EXPOSE $PORT

COPY gunicorn.conf.py /uzen

CMD gunicorn -k uvicorn.workers.UvicornWorker app:app

