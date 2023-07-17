FROM docker:stable-dind
# Keys were rotated in the edge repos, so we need to do this now
RUN apk add -X https://dl-cdn.alpinelinux.org/alpine/v3.16/main -u alpine-keys --allow-untrusted
# Workaround for  https://github.com/AdoptOpenJDK/openjdk-docker/issues/75
RUN apk add --no-cache fontconfig ttf-dejavu openjdk11 bash tini bind-tools
RUN apk add aufs-util --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing
RUN apk add maven --repository https://dl-cdn.alpinelinux.org/alpine/edge/community
# Workaround for  https://github.com/AdoptOpenJDK/openjdk-docker/issues/75
RUN ln -s /usr/lib/libfontconfig.so.1 /usr/lib/libfontconfig.so && \
    ln -s /lib/libuuid.so.1 /usr/lib/libuuid.so.1 && \
    ln -s /lib/libc.musl-x86_64.so.1 /usr/lib/libc.musl-x86_64.so.1
ENV LD_LIBRARY_PATH /usr/lib

ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk/
#ENV DOCKER_STORAGE_DRIVER=overlay2
ENV DOCKER_HOST=unix:///var/tmp/docker.sock

COPY daemon.json /etc/docker/daemon.json
COPY custom-dockerd-entrypoint.sh /usr/local/bin/custom-dockerd-entrypoint.sh

WORKDIR /project

ENTRYPOINT ["/sbin/tini","-g","--","bash","/usr/local/bin/custom-dockerd-entrypoint.sh"]

CMD ["clean","install"]
