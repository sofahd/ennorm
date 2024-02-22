FROM alpine:3.17
# Define build-time variables
ARG TOKEN
ARG LOG_API
ARG IP

# Set the build-time variable as an environment variable
ENV TOKEN=${TOKEN}
ENV LOG_API=${LOG_API}
ENV IP=${IP}

# Copy files
COPY ./src /home/pro/

# Update apt repository and install dependencies
RUN apk --no-cache -U add \
    python3 \
    py3-pip \
    git \
    python3-dev && \
    pip3 install setuptools && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/sofahutils.git  && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/services.git

WORKDIR /home/pro

CMD python3 /home/pro/startup.py