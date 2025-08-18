# Here is an example of how you might integrate the nsj with Docker.

FROM ubuntu

# Install dependencies for the python example challenge
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir cowsay

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf/challenges
COPY challenges/ .

WORKDIR /home/ctf
COPY nsj .
COPY config .

EXPOSE 31337

RUN chmod +x nsj

CMD ["./nsj", "-p", "31337", "-l", "log", "-lp", "16", "-lm", "10485760", "-lu", "10", "-lc", "10"]

# example command:
#   serve on port 31337
#   log to file "log"
#   limit processes to 16
#   limit memory to 10 MiB
#   max. 10% cpu usage per connection
#   max. 10 concurrent connections per IP
# (defaults)
#   256KiB tmpfs file system
#   serve multiple challenges through key system
#   tell users how much time they have left
#   use socket as stdin/out/err


# build:                    sudo docker build -t ansj .
# run:                      sudo docker run --privileged --cgroupns=host -d -p 31337:31337 --rm -it ansj

# connect:                  nc localhost 31337

# bash inside container:    sudo docker exec -it <container> bash
# read the logs:            sudo docker exec -it <container> cat /home/ctf/log

# update challenge files:   sudo docker cp challenges/. <container>:/home/ctf/challenges
# update config:            sudo docker cp config <container>:/home/ctf/config

# restart:                  sudo docker restart <container>
