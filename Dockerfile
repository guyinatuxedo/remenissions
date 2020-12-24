FROM ubuntu:18.04

# Configure timezone so apt behaves
RUN echo "UTC" > /etc/timezone
RUN rm -f /etc/localtime
RUN apt-get update -y \
    && apt-get install -y tzdata

RUN dpkg-reconfigure -f noninteractive tzdata

# Install Ghidra into /tools
RUN apt-get install -y sudo tmux curl unzip openjdk-11-jdk openjdk-11-jre-headless gdb \
    && apt-get clean -y

RUN mkdir -p /tools/ghidra
WORKDIR /tools/ghidra
RUN curl "https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip" -o ghidra.zip
RUN unzip ghidra.zip
RUN rm ghidra.zip

# Run the setup.sh script
RUN mkdir /remenissions
WORKDIR /remenissions
COPY . .
RUN chmod +x setup.sh
RUN ./setup.sh

# Link remenissions to path
RUN ln -s /remenissions/remenissions /usr/local/bin/remenissions

# Link python to python3
RUN ln -s $(which python3) /usr/local/bin/python

# Make shared folder
RUN mkdir -p /shared
WORKDIR /shared
CMD ["tmux"]
