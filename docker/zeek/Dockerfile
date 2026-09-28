# Pinned: zeek/zeek:latest moved to Zeek 9, which removed the
# extract-certs-pem policy this sensor loaded, and every sensor built after
# that failed at startup. Bump deliberately, and run docker/zeek/test-sensor.sh.
FROM zeek/zeek:9.0.0@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME ["/zeek-logs", "/pcap-input"]
ENTRYPOINT ["/entrypoint.sh"]
