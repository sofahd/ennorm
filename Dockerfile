FROM alpine:3.17
# Define build-time variables
ARG TOKEN

# Set the build-time variable as an environment variable
ENV TOKEN=${TOKEN}

# Copy files
COPY ./src /home/ennorm/

# Update apt repository and install dependencies
RUN apk --no-cache -U add \
    python3 \
    py3-pip \
    curl \
    python3-dev && \
    addgroup -g 2000 ennorm && \
    adduser -S -s /bin/ash -u 2000 -D -g 2000 ennorm && \
    pip3 install setuptools \
    wheel \
    flask \
    waitress \
    requests \
    cryptography \
    pytz && \
    cd /home/ennorm && \
    mkdir input output && \
    chown ennorm:ennorm -R /home/ennorm/* && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/sofahutils.git  && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/services.git

WORKDIR /home/ennorm
USER ennorm:ennorm

CMD # TODO: Add command to run the application