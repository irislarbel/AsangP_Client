ARG DOCKER_TAG=release-v4.4
FROM espressif/idf:${DOCKER_TAG}

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update -y && \
    apt-get install --no-install-recommends -y udev && \
    rm -rf /var/lib/apt/lists/*

RUN echo "source /opt/esp/idf/export.sh > /dev/null 2>&1" >> /etc/bash.bashrc

ENTRYPOINT [ "/opt/esp/entrypoint.sh" ]

CMD ["/bin/bash", "-c"]