FROM golang:buster AS builder

WORKDIR /app
COPY runner.go /app/runner.go
RUN go build runner.go

FROM debian:buster-slim

RUN useradd -m user
WORKDIR /home/user

RUN chown -R root:root /home/user

COPY ynetd /usr/bin/

COPY ./flag /home/user/flag
COPY ./src/d8 /home/user/d8
COPY ./src/snapshot_blob.bin /home/user/snapshot_blob.bin

COPY --from=builder /app/runner /home/user/runner
RUN chmod +x /home/user/runner

USER user
CMD ["ynetd", "-lt", "60", "-p", "1337", "-sh", "n", "/home/user/runner"]
