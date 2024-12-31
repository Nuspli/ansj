# sudo docker build -t ansj .
# sudo docker run --privileged -d -p 31337:31337 --rm -it ansj

FROM ubuntu

RUN apt-get update && apt-get install -y \
    libcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf/challenges
COPY challenges/ .

WORKDIR /home/ctf
COPY nsj .
COPY config .

EXPOSE 31337
CMD ./nsj -p 31337 -lp 1024
