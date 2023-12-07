import asyncio
import socket
from dnslib import DNSRecord, RCODE
from dns_cache import DNSCache


class DNSServer:
    def __init__(self):
        self.__root_ns_server = '198.41.0.4'
        self.__cache = DNSCache()

    def __enter__(self):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__sock.bind(('127.0.0.1', 53))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__sock.close()

    def start_work(self):
        event_loop = asyncio.get_event_loop()
        event_loop.run_until_complete(self.__listen())

    async def __listen(self):
        try:
            while True:
                data, addr = self.__sock.recvfrom(1024)
                await self.__parse_query(data, addr)

        except KeyboardInterrupt:
            self.__cache.save_cache()

    async def __parse_query(self, query_data: bytes, addr):
        query = DNSRecord.parse(query_data)
        if extracted_from_cache := self.__cache.get_records_from_cache(query):
            record_with_ip = self.__cache.make_response_from_cache(query, extracted_from_cache)
        else:
            record_with_ip = await self.__get_response_record_with_ip(query, self.__root_ns_server, set(), 1)
        if record_with_ip:
            self.__sock.sendto(record_with_ip.pack(), addr)

    async def __get_response_record_with_ip(self, query, ip_server, visited, version_ip_server):
        with socket.socket(
                socket.AF_INET if version_ip_server == 1 else socket.AF_INET6,
                socket.SOCK_DGRAM
        ) as __sock:
            __sock.settimeout(5)
            try:
                __sock.connect((ip_server, 53))
                __sock.send(query.pack())
                response = __sock.recv(1024)
                response_record = DNSRecord.parse(response)
                if extracted_from_cache := self.__cache.get_records_from_cache(query):
                    return self.__cache.make_response_from_cache(query, extracted_from_cache)
                if response_record.header.rcode == RCODE.NOERROR:
                    self.__cache.save_response_to_cache(response_record)
            except OSError or socket.timeout:
                return

        if response_record.rr:
            return response_record
        else:
            if response_record.ar:
                return await self.__bypass_next_servers(response_record.ar, visited, query)
            elif response_record.auth:
                return await self.__bypass_next_servers(response_record.auth, visited, query)

    async def __bypass_next_servers(self, records, visited, query):
        for record in records:
            (
                ns_server,
                rtype,
                rclass,
                ttl
            ) = (
                str(record.rdata),
                record.rtype,
                record.rclass,
                record.ttl
            )

            if ns_server in visited:
                continue
            else:
                visited.add(ns_server)
                if record := await self.__get_response_record_with_ip(
                        query,
                        ns_server,
                        visited,
                        rtype if rtype != 2 else 1
                ):
                    return record


if __name__ == '__main__':
    with DNSServer() as server:
        server.start_work()
