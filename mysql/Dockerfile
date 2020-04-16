FROM mysql:5.7

EXPOSE 3306

ENV MYSQL_ALLOW_EMPTY_PASSWORD yes

COPY ./initdb.d/init.sql /docker-entrypoint-initdb.d/
