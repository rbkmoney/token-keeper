#!/bin/bash
cat <<EOF
version: '2.1'
services:

  ${SERVICE_NAME}:
    image: ${BUILD_IMAGE}
    volumes:
      - .:$PWD
      - $HOME/.cache:/home/$UNAME/.cache
    working_dir: $PWD
    command: /sbin/init
    depends_on:
      machinegun:
        condition: service_healthy
    mem_limit: 512M

  machinegun:
    image: dr2.rbkmoney.com/rbkmoney/machinegun:9c3248a68fe530d23a8266057a40a1a339a161b8
    command: /opt/machinegun/bin/machinegun foreground
    volumes:
      - ./var/machinegun/config.yaml:/opt/machinegun/etc/config.yaml
      - ./var/machinegun/cookie:/opt/machinegun/etc/cookie
    healthcheck:
      test: "curl http://localhost:8022/"
      interval: 5s
      timeout: 1s
      retries: 20
EOF
