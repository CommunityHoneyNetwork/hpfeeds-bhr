FROM python:3.7

LABEL maintainer Team STINGAR <team-stingar@duke.edu>
LABEL name "hpfeeds-bhr"
LABEL version "1.9"
LABEL release "1"
LABEL summary "HPFeeds BHR handler"
LABEL description "HPFeeds BHR handler is a tool for submitting black hole routes from honeypot events."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-bhr"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-bhr/commits/master"

COPY requirements.txt /opt/requirements.txt
ENV DEBIAN_FRONTEND "noninteractive"

RUN apt-get update && ap-get upgrade -y && apt-get install -y gcc git python3-dev python3-pip
RUN pip3 install -r /opt/requirements.txt
RUN pip3 install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

ADD . /opt/
RUN chmod 755 /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
