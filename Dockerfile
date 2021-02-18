FROM node:12.18.3-alpine

WORKDIR /usr/app
COPY . ./
RUN apk add --update \
    yarn \
    nodejs \
    npm