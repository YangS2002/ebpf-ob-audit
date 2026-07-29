FROM debian:12

WORKDIR /root/
COPY . /root/

RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 libgrpc++1.51 libprotobuf32 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 50051

ENTRYPOINT ["/bin/bash"]