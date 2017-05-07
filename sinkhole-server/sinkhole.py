# -*- coding: utf-8 -*-

# sinkhole server project.
# By Nguyen Hong Quang, 2017.
# @quangnh89

# License: GPL v3. See LICENSE for more information.

import sys
import getopt
import re
import MySQLdb
import datetime
from twisted.internet import protocol
from twisted.python import log
from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver
from twisted.names import dns
from twisted.names import server

VERSION = "1.0"

# Put your custom configuration here
config = {
    'database': {
        'host': '127.0.0.1',
        'user': 'root',
        'pw': '',
        'db_name': 'sinkholedb'
    },
    'syslog': {
        'interface': '127.0.0.1',
        'listen_port': 10514
    },
    'sinkhole': {
        'external_ip': '192.168.171.10',
        'listen_port': 9999,
        'dns_ttl': 600,
        'dns_port': 53
    }
}

# convert from protocol to number
proto_dict = {
    'TCP': 1,
    'UDP': 2
}

# get current time
def time_now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')


class DatabaseConnector():
    db = None

    def __init__(self, host, user, pw, db_name):
        # Open database connection
        self.db = MySQLdb.connect(host, user, pw, db_name)

    def __del__(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def _commit(self):
        try:
            # Commit your changes in the database
            self.db.commit()
        except Exception as e:
            # Rollback in case there is any error
            self.db.rollback()
            raise e

    # drop all tables and re-create them.
    def init_database(self):
        cursor = self.db.cursor()
        # Drop 'connection_log' if it already exist using execute() method.
        cursor.execute("DROP TABLE IF EXISTS connection_log")
        # Create table
        sql = """CREATE TABLE connection_log ( \
            src_addr_v4 INT UNSIGNED NOT NULL, \
            sport INT UNSIGNED NOT NULL, \
            dport INT UNSIGNED NOT NULL, \
            protocol INT NOT NULL, \
            established_time DATETIME NOT NULL )"""
        cursor.execute(sql)

        # Drop 'sinkhole_data' if it already exist using execute() method.
        cursor.execute("DROP TABLE IF EXISTS sinkhole_data")
        # Create table
        sql = """CREATE TABLE sinkhole_data ( \
            src_addr_v4 INT UNSIGNED NOT NULL, \
            sport INT UNSIGNED NOT NULL, \
            protocol INT NOT NULL, \
            received_time DATETIME NOT NULL, \
            received_data BLOB NOT NULL )"""
        cursor.execute(sql)

        # Drop 'dns_log' if it already exist using execute() method.
        cursor.execute("DROP TABLE IF EXISTS dns_log")
        # Create table
        sql = """CREATE TABLE dns_log ( \
            src_addr_v4 INT UNSIGNED NOT NULL, \
            received_time DATETIME NOT NULL, \
            query_domain TEXT NOT NULL, \
            query_type INT NOT NULL)"""
        cursor.execute(sql)

        # Commit all changes in the database
        self._commit()

    # add new connection information
    # @src_addr_v4 : peer address
    # @sport : peer port
    # @dport : original destination port
    # @protocol: transmission protocol: 1 (TCP) or 2 (UDP)
    def insert_connection(self, src_addr_v4, sport, dport, protocol):
        cursor = self.db.cursor()
        sql = """INSERT INTO \
                 connection_log(src_addr_v4, sport, dport, protocol, established_time) \
                 VALUES (INET_ATON(%s), %s, %s, %s, %s )"""
        cursor.execute(sql, (src_addr_v4, sport, dport, protocol, time_now()))
        self._commit()

    # add new data chunk
    # @src_addr_v4 : peer address
    # @sport : peer port
    # @protocol: transmission protocol: 1 (TCP) or 2 (UDP)
    # @data: data chunk
    def insert_data(self, src_addr_v4, sport, proto, data):
        cursor = self.db.cursor()
        sql = """INSERT INTO \
                 sinkhole_data(src_addr_v4, sport, protocol, received_time, received_data) \
                 VALUES (INET_ATON(%s), %s, %s, %s, %s )"""
        cursor.execute(sql, (src_addr_v4, sport, proto, time_now(), data))
        self._commit()

    # add new DNS query information
    # @src_addr_v4 : peer address
    # @query_domain : domain name which is looked up
    # @query_type : query type
    def insert_dns_query(self, src_addr_v4, query_domain, query_type):
        cursor = self.db.cursor()
        sql = """INSERT INTO \
                 dns_log(src_addr_v4, received_time, query_domain, query_type) \
                 VALUES (INET_ATON(%s), %s, %s, %s )"""

        cursor.execute(sql, (src_addr_v4, time_now(), query_domain, query_type))
        self._commit()


# DNS Server
class DNSServerFactory(server.DNSServerFactory):
    default_addr = config['sinkhole']['external_ip']
    TTL = config['sinkhole']['dns_ttl']
    db = None

    def handleQuery(self, message, protocol, address):
        query = message.queries[0]

        ans = []
        auth = []
        add = []
        send_reply = False

        if int(query.type) == dns.A: #
            send_reply = True
            a = dns.Record_A(address=self.default_addr, ttl=self.TTL)
            rr1 = dns.RRHeader(bytes(query.name), dns.A, ttl=self.TTL, payload=a)
            ans = [rr1]

        if send_reply:
            if self.db is not None:
                self.db.insert_dns_query(address[0], query.name.name, int(query.type))
            message.rCode = dns.OK  # response code
            message.auth = 1  # authority flag
            message.answers = ans
            message.authority = auth
            message.additional = add
            self.sendReply(protocol, message, address)

# Syslog server
class SyslogdProtocol(LineReceiver):
    delimiter = '\n'
    db = None

    def lineReceived(self, line):
        try:
            # parse syslog to get connection information
            src_addr_v4 = re.search("SRC=[0-9]{1,3}\.[[0-9]{1,3}\.[[0-9]{1,3}\.[[0-9]{1,3}",
                                    line, re.M | re.I).group()[4:]
            sport = re.search("SPT=[0-9]{1,3}", line, re.M | re.I).group()[4:]
            sport = int(sport, 10)
            dport = re.search("DPT=[0-9]{1,3}", line, re.M | re.I).group()[4:]
            dport = int(dport, 10)
            proto = re.search("PROTO=[A-Z]+\s", line, re.M | re.I).group().strip().split('=')[1]
            proto = proto_dict[proto]
            if self.db is not None:
                self.db.insert_connection(src_addr_v4, sport, dport, proto)
        except Exception as e:
            print e


# accept every connection and log all data to database
class SinkholeServer(protocol.Protocol):
    db = None
    protocol = proto_dict['TCP']

    def dataReceived(self, chunk):
        self.db.insert_data(self.transport.getPeer().host, self.transport.getPeer().port, self.protocol, chunk)


# entry point
def main():
    init_db = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i", ["init"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        sys.exit(2)

    for o, a in opts:
        if o in ("-i", "--init"):
            init_db = True
        else:
            assert False, "unhandled option"

    try:
        db_connector = DatabaseConnector(
            config['database']['host'],
            config['database']['user'],
            config['database']['pw'],
            config['database']['db_name'])
    except Exception as e:
        print e
        return

    log.startLogging(sys.stdout)

    if init_db:
        print "initialize database"
        db_connector.init_database()

    # DNS server
    verbosity = 0
    factory = DNSServerFactory(verbose=verbosity)
    factory.default_addr = config['sinkhole']['external_ip']
    factory.TTL = config['sinkhole']['dns_ttl']
    factory.db = db_connector
    dns_protocol = dns.DNSDatagramProtocol(factory)
    factory.noisy = dns_protocol.noisy = verbosity
    reactor.listenUDP(config['sinkhole']['dns_port'], dns_protocol)
    # reactor.listenTCP(config['sinkhole']['dns_port'], factory)

    # syslog server
    factory = protocol.ServerFactory()
    factory.protocol = SyslogdProtocol
    factory.protocol.db = db_connector
    reactor.listenTCP(config['syslog']['listen_port'], factory, interface=config['syslog']['interface'])

    # sinkhole server
    factory = protocol.ServerFactory()
    factory.protocol = SinkholeServer
    factory.protocol.db = db_connector
    reactor.listenTCP(config['sinkhole']['listen_port'], factory, interface=config['sinkhole']['external_ip'])

    # Start all factories and run
    reactor.run()


if __name__ == "__main__":
    main()