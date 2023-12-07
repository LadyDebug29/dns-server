import os
import pickle
import time
from collections import defaultdict

from dnslib import DNSRecord


class DNSCache:
    def __init__(self):
        self.__cache = self.initialize_cache()

    @staticmethod
    def initialize_cache():
        try:
            with open('__cache.pickle', 'rb') as handle:
                data = pickle.load(handle)
                for key, (records, expiration_time) in list(data.items()):
                    if time.time() >= expiration_time:
                        del data[key]
            os.remove('__cache.pickle')
            return data

        except FileNotFoundError:
            return dict()

    def save_cache(self):
        with open('__cache.pickle', 'wb') as handle:
            pickle.dump(self.__cache, handle)

    def add_record_to_cache(self, key, records, ttl):
        expiration_time = time.time() + ttl
        self.__cache[key] = (records, expiration_time)

    def get_records_from_cache(self, query):
        key = (query.q.qtype, query.q.qname)
        records_data = self.__cache.get(key)

        if records_data:
            records, expiration_time = records_data
            if time.time() < expiration_time:
                return records
            del self.__cache[key]

        return None

    def save_response_to_cache(self, response_record: DNSRecord):
        records = defaultdict(list)
        for rr_section in (response_record.rr, response_record.auth, response_record.ar):
            for rr in rr_section:
                records[(rr.rtype, rr.rname)].append(rr)
                self.add_record_to_cache((rr.rtype, rr.rname), records[(rr.rtype, rr.rname)], rr.ttl)

    @staticmethod
    def make_response_from_cache(query, data):
        response = DNSRecord(header=query.header)
        response.add_question(query.q)
        response.rr += data

        return response
