import socket
from dnslib import DNSRecord
import click


@click.command()
@click.argument('dig', default='dig')
@click.argument('domain-name', default=None)
@click.argument('type-record', default='A')
@click.argument('ns-server', default='@127.0.0.1')
def main(dig, domain_name, type_record, ns_server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((f'{ns_server[1:]}', 53))
    data = DNSRecord.question(domain_name, type_record)
    sock.send(data.pack())
    data = sock.recv(1024)
    print(DNSRecord.parse(data))


if __name__ == '__main__':
    main()
