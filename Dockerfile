FROM alpine as main

LABEL maintainer="nmaguiar"
LABEL version="v6.1.0"

ADD https://downloads.sourceforge.net/project/davmail/davmail/6.1.0/davmail-6.1.0-3423.zip /tmp/davmail.zip

RUN apk update\
 && apk --no-cache add openjdk17-jre-headless unzip\
 && apk cache purge\
 && adduser davmail -D\
 && mkdir /usr/local/davmail\
 && unzip -q /tmp/davmail.zip -d /usr/local/davmail\
 && rm /tmp/davmail.zip 

EXPOSE        1080
EXPOSE        1143
EXPOSE        1389
EXPOSE        1110
EXPOSE        1025
WORKDIR       /usr/local/davmail

USER davmail
COPY davmail.properties /etc/davmail/davmail.properties

# -------------------
FROM scratch as final

COPY --from=main / /

USER davmail

WORKDIR /usr/local/davmail
ENTRYPOINT ["/usr/local/davmail/davmail", "/etc/davmail/davmail.properties"]