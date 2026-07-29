FROM debian:12

WORKDIR /root/
COPY . /root/

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      libelf1 libelf-dev zlib1g-dev \
      make git clang llvm pkg-config build-essential \
      protobuf-compiler protobuf-compiler-grpc libprotobuf-dev libgrpc++-dev && \
    apt-get install -y --no-install-recommends ca-certificates	&& \
    apt-get install -y libgtest-dev pkg-config cmake && \
	  update-ca-certificates	&& \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash"]
