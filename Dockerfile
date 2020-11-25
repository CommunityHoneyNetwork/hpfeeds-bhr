FROM python:3.7

LABEL maintainer="Team Stingar <team-stingar@duke.edu>"
LABEL name="hpfeeds-bhr"
LABEL version="1.9.1"
LABEL release="1"
LABEL summary="HPFeeds BHR handler"
LABEL description="HPFeeds BHR handler is a tool for submitting black hole routes from honeypot events."
LABEL authoritative-source-url="https://github.com/CommunityHoneyNetwork/hpfeeds-bhr"
LABEL changelog-url="https://github.com/CommunityHoneyNetwork/hpfeeds-bhr/commits/master"

COPY requirements.txt /opt/requirements.txt
ENV DEBIAN_FRONTEND "noninteractive"

# hadolint ignore=DL3008,DL3005
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y gcc git python3-dev python3-pip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip setuptools wheel \
  && python3 -m pip install -r /opt/requirements.txt \
  && python3 -m pip install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

ADD . /opt/
RUN chmod 755 /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
