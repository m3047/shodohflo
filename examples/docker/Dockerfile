FROM redis:latest

RUN apt-get update && apt-get upgrade -y && \
  apt-get install -y \
    iproute2 \
    python3 \
    python3-pip \
    python3-dnspython \
    python3-redis \
    libssl-dev \
    libfstrm-dev \
    libprotobuf-dev \
    protobuf-c-compiler \
    libprotobuf-c-dev
    
RUN pip3 install dpkt flask

COPY agents /usr/local/share/shodohflo/agents
COPY app /usr/local/share/shodohflo/app
COPY examples /usr/local/share/shodohflo/examples
COPY shodohflo /usr/local/share/shodohflo/shodohflo

RUN cd /usr/local/share/shodohflo/examples/docker && \
  tar -xzf `find ./ -name 'bind*tgz'` && \
  mv `find ./ -maxdepth 1 -name 'bind*' -and -type d` /usr/src/bind && \
  cd /usr/src/bind && \
  ./configure --with-libtool --enable-dnstap && make && make install && ldconfig
  
RUN mkdir /etc/namedb && \
  cd /usr/local/share/shodohflo/examples/docker && \
  mv named.conf rndc.conf /etc && \
  cp ../../agents/configuration_sample.py ../../agents/configuration.py && \
  mv localhost* test.fwd /etc/namedb && \
  mv app-configuration.py ../../app/configuration.py

EXPOSE 3047/tcp
CMD ["/bin/bash"]
