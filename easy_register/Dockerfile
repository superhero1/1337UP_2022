FROM debian:latest

RUN apt-get update -y && apt-get install -y xinetd && apt-get clean -y

# Create challenge user
RUN useradd -u 1000 -d /home/1337UP -s /bin/bash 1337UP
RUN mkdir /home/1337UP

# Pipe xinetd logs to docker logs
RUN ln -sf /proc/1/fd/1 /var/log/1337UP.log

# Copy xinetd and other dependencies
COPY deps/1337UP.xinetd /etc/xinetd.d/1337UP
COPY deps/limits.conf /etc/security/limits.d/90-1337UP.conf
COPY deps/banner_fail /etc/banner_fail
COPY deps/start.sh /start.sh

RUN chmod 551 start.sh

# Set up chroot
RUN mkdir /home/1337UP/usr
RUN cp -R /lib* /home/1337UP && \
    cp -R /usr/lib* /home/1337UP/usr

RUN mkdir /home/1337UP/dev && \
    mknod /home/1337UP/dev/null c 1 3 && \
    mknod /home/1337UP/dev/zero c 1 5 && \
    mknod /home/1337UP/dev/random c 1 8 && \
    mknod /home/1337UP/dev/urandom c 1 9 && \
    chmod 666 /home/1337UP/dev/*

RUN mkdir /home/1337UP/bin && \
    mkdir /home/1337UP/etc && \
    cp /bin/* /home/1337UP/bin && \
    cp /etc/shadow /home/1337UP/etc && \
    cp /etc/passwd /home/1337UP/etc && \
    rm /home/1337UP/bin/rm

# Set up challenge and flag
WORKDIR /home/1337UP
COPY easy_register .
COPY flag .

RUN chmod 444 flag
RUN chmod 111 easy_register

RUN chown -R root:root /home/1337UP

CMD ["/start.sh"]

EXPOSE 7777
