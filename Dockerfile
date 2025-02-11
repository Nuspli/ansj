# Here is an example of how you might integrate the nsj with Docker.

FROM ubuntu

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf/challenges
COPY challenges/ .

WORKDIR /home/ctf
COPY nsj .
COPY config .

EXPOSE 31337

RUN chmod +x nsj
CMD ["./nsj", "-p", "31337", "-l", "log", "-lp", "1024"]

# sudo docker build -t ansj .
# sudo docker run --privileged -d -p 31337:31337 --rm -it ansj

# bash: sudo docker exec -it <container> bash
# logs: sudo docker exec -it <container> cat /home/ctf/log

# update challenges / config:
# sudo docker cp challenges/ <container>:/home/ctf/challenges
# sudo docker cp config <container>:/home/ctf/config

# restart: sudo docker restart <container>