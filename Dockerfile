FROM ubuntu:18.04

LABEL maintainer Alexander Merck <alexander.t.merck@gmail.com>
LABEL maintainer Jesse Bowling <jessebowling@gmail.com>
LABEL name "hpfeeds-bhr"
LABEL version "0.1"
LABEL release "1"
LABEL summary "HPFeeds BHR handler"
LABEL description "HPFeeds BHR handler is a tool for submitting black hole routes from honeypot events."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-bhr"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-bhr/commits/master"

ENV playbook "hpfeeds-bhr.yml"

RUN apt-get update \
       && apt-get install -y ansible

RUN echo "localhost ansible_connection=local" >> /etc/ansible/hosts
ADD . /opt/
RUN ansible-playbook /opt/${playbook}

ENTRYPOINT ["/usr/bin/runsvdir", "-P", "/etc/service"]
