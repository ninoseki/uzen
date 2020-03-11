FROM python:3.8-slim-buster

ENV NPM_CONFIG_PRODUCTION false

RUN apt-get update && apt-get install -y \
  curl gnupg python3-dev build-essential gconf-service libasound2 libatk1.0-0 libc6 libcairo2 \
  libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 \
  libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 \
  libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation \
  libappindicator1 libnss3 lsb-release xdg-utils wget

RUN curl -sL https://deb.nodesource.com/setup_13.x | bash -
RUN apt-get install -y nodejs

RUN pip3 install pipenv

RUN mkdir -p /usr/opt/uzen
WORKDIR /usr/opt/uzen

COPY Pipfile Pipfile
COPY Pipfile.lock Pipfile.lock

RUN pipenv install --deploy --system
RUN pyppeteer-install

COPY . .

RUN cd frontend && npm install && npm run build

EXPOSE 5000

CMD ["uvicorn", "--host", "0.0.0.0", "--port", "5000", "uzen:app"]