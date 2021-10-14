# pull official base image
FROM ubuntu:20.04

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y python3-pip
RUN apt-get install libpq-dev -y
RUN apt-get install netcat -y
RUN apt install redis-server -y
RUN apt install nmap -y
# install dependencies
RUN pip3 install --upgrade pip
COPY ./requirements/production.txt .
COPY ./requirements/base.txt .
RUN pip3 install -r production.txt

COPY entrypoint.sh /tmp/entrypoint.sh
RUN sed -i 's/\r$//g' /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
# copy project
COPY . .
ENTRYPOINT ["/tmp/entrypoint.sh"]
