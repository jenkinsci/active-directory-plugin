FROM docker:dind
RUN apk add --no-cache fontconfig ttf-dejavu openjdk11 bash tini bind-tools maven

ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk/
#ENV DOCKER_STORAGE_DRIVER=overlay2
ENV DOCKER_HOST=unix:///var/tmp/docker.sock

COPY daemon.json /etc/docker/daemon.json
COPY custom-dockerd-entrypoint.sh /usr/local/bin/custom-dockerd-entrypoint.sh

WORKDIR /project

ENTRYPOINT ["/sbin/tini","-g","--","bash","/usr/local/bin/custom-dockerd-entrypoint.sh"]

CMD ["clean","install"]