# Dockerfile for davmail
# Copyright 2023 Nuno Aguiar
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
 #&& wget https://repo1.maven.org/maven2/org/jdom/jdom2/2.0.6.1/jdom2-2.0.6.1.jar -O /usr/local/davmail/lib/jdom2-2.0.6.1.jar\
 #&& rm /usr/local/davmail/lib/jdom-1.0.jar\
 && wget https://repo1.maven.org/maven2/commons-codec/commons-codec/1.16.0/commons-codec-1.16.0.jar -O /usr/local/davmail/lib/commons-codec-1.16.0.jar\
 && rm /usr/local/davmail/lib/commons-codec-1.11.jar\
 && wget https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar -O /usr/local/davmail/lib/commons-collections-3.2.2.jar\
 && rm /usr/local/davmail/lib/commons-collections-3.1.jar\
 && wget https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar -O /usr/local/davmail/lib/commons-logging-1.2.jar\
 && rm /usr/local/davmail/lib/commons-logging-1.0.4.jar\
 && wget https://repo1.maven.org/maven2/net/sourceforge/htmlcleaner/htmlcleaner/2.29/htmlcleaner-2.29.jar -O /usr/local/davmail/lib/htmlcleaner-2.29.jar\
 && rm /usr/local/davmail/lib/htmlcleaner-2.21.jar\
 && wget https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar -O /usr/local/davmail/lib/httpclient-4.5.14.jar\
 && rm /usr/local/davmail/lib/httpclient-4.5.6.jar\
 && wget https://repo1.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar -O /usr/local/davmail/lib/httpcore-4.4.16.jar\
 && rm /usr/local/davmail/lib/httpcore-4.4.16.jar\
 #&& wget https://repo1.maven.org/maven2/org/apache/jackrabbit/jackrabbit-webdav/2.21.19/jackrabbit-webdav-2.21.19.jar -O /usr/local/davmail/lib/jackrabbit-webdav-2.21.19.jar\
 #&& rm /usr/local/davmail/lib/jackrabbit-webdav-2.14.6.jar\
 && wget https://github.com/OpenAF/openaf/raw/master/lib/javax.mail.jar -O /usr/local/davmail/lib/javax.mail-api-1.6.2.jar\
 && rm /usr/local/davmail/lib/javax.mail-1.5.6.jar\
 && wget https://repo1.maven.org/maven2/net/freeutils/jcharset/2.1/jcharset-2.1.jar -O /usr/local/davmail/lib/jcharset-2.1.jar\
 && rm /usr/local/davmail/lib/jcharset-2.0.jar\
 && wget https://repo1.maven.org/maven2/org/codehaus/jettison/jettison/1.5.4/jettison-1.5.4.jar -O /usr/local/davmail/lib/jettison-1.5.4.jar\
 && rm /usr/local/davmail/lib/jettison-1.5.3.jar\
 && wget https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar -O /usr/local/davmail/lib/slf4j-api-1.7.36.jar\
 && rm /usr/local/davmail/lib/slf4j-api-1.7.25.jar\
 && wget https://repo1.maven.org/maven2/org/slf4j/slf4j-reload4j/1.7.36/slf4j-reload4j-1.7.36.jar -O /usr/local/davmail/lib/slf4j-reload4j-1.7.36.jar\
 && rm /usr/local/davmail/lib/slf4j-log4j12-1.7.25.jar\
 #&& wget https://repo1.maven.org/maven2/com/fasterxml/woodstox/woodstox-core/6.5.1/woodstox-core-6.5.1.jar -O /usr/local/davmail/lib/woodstox-core-6.5.1.jar\
 #&& rm /usr/local/davmail/lib/woodstox-core-6.4.0.jar\
 #&& wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-1.2-api/2.20.0/log4j-1.2-api-2.20.0.jar -O /usr/local/davmail/lib/log4j-1.2-api-2.20.0.jar\
 #&& wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.20.0/log4j-core-2.20.0.jar -O /usr/local/davmail/lib/log4j-core-2.20.0.jar\
 #&& wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.20.0/log4j-api-2.20.0.jar -O /usr/local/davmail/lib/log4j-api-2.20.0.jar\
 #&& rm /usr/local/davmail/lib/log4j-1.2.17.jar\
 #&& wget https://repo1.maven.org/maven2/com/squareup/okio/okio/1.17.5/okio-1.17.5.jar -O /usr/local/davmail/lib/okio-1.17.5.jar\
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