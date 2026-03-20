FROM zeek/zeek:latest
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME ["/zeek-logs", "/pcap-input"]
ENTRYPOINT ["/entrypoint.sh"]
