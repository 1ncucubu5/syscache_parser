# coding: utf-8

import sys
import json
# VT API module can be installed via pip install virustotal-api
from virus_total_apis import PublicApi as VirusTotalPublicApi
import argparse


class simpleHash:
    # simple file object, automatically calculates hash of itself
    def __init__(self, file_hash):
        self.hash = file_hash

    def get_hash(self):
        return(self.hash)


class observedEntity:
    # Contains one hash and all file names that share this hash
    # It also holds the raw VirusTotal result and provides distilled threat intel information
    def __init__(self, file, alerting_level):
        self.hash = file.get_hash()
        self.isMalicious = False
        self.vt_result = ''
        self.positives = 0
        self.total_scanners = 1  # to avoid division by zero error
        self.ALERTING_LEVEL = alerting_level

    def get_file_hash(self):
        # returns the array of file names that share the hash and therefore the VirusTotal results.
        return(self.hash)

    def get_hash(self):
        # returns the hash of the observed entity, also used for checking against VirusTotal
        return(self.hash)

    def add_virustotal_result(self, result):
        self.vt_result = result

        # Convert json to dictionary:
        json_data = json.loads(json.dumps(result))
        try:
            if json_data['response_code'] == 200:
                # we got a valid response
                self.total_scanners = json_data['results']['total']
                self.positives = json_data['results']['positives']
                self.scan_date = json_data['results']['scan_date']
        except KeyError:
            print("Received unexpected response from VirusTotal:")
            sys.exit(
                f"\nReceived invalid response from VirusTotal. Did you enter a valid VT API Key in the config file?")

    def get_virustotal_result(self):
        return(self.vt_result)

    def is_malicious(self):
        # the definition of "malicious" is not fixed.
        # What we say here is that if a certain number of engines discover the file to be malicious,
        # then we deem it potentially malicious.
        # We use a ratio here, for example 0.1=10%:
        return(self.count_alerting_scanners() / self.count_total_scanners() >= self.ALERTING_LEVEL)

    def count_total_scanners(self):
        # number of AV scanners that were used to check this file
        return(self.total_scanners)

    def count_alerting_scanners(self):
        # number of AV scanners that reported the file as malicious
        return(self.positives)


class entityHandler:
    # manages observed entities, i.e. adds new entities if they were not observed before
    # or otherwise updates information on previously observed entities

    def __init__(self):
        self.hash_dict = {}

    def add_hash(self, hash, alerting_level):
        # check if other files with same hash were already processed (duplicates)
        new_hash = simpleHash(hash)
        self.hash_dict.update(
            {new_hash.get_hash(): observedEntity(new_hash, alerting_level)})

    def get_entities(self):
        # returns an iterable of all observed entities so that they can be checked
        return(self.hash_dict.items())

    def count_entities(self):
        # number of entities (i.e. files with unique hash) in scope
        return(len(self.hash_dict))

    def retrieve_virustotal_results(self):
        # Starts the polling of VirusTotal results for all observed entities
        # VT rate limit is 4 requests per minute. If we have <= 4 unique hashes,
        # we can query them without waiting:
        if entity_handler.count_entities() <= 4:
            waiting_time = 1
        else:
            waiting_time = 15

        i = 0
        for hash, observed_entity in self.get_entities():
            i += 1
            print(f'Processing {i} out of {self.count_entities()}...')
            observed_entity.add_virustotal_result(
                vt.get_file_report(hash, waiting_time))
            # The free VirusTotal API is rate-limited to 4 requests per minute.


VT_KEY = "1a73a008ab8f2912388fa1c6b0ab24e23e495cec48a675432d36d9cce82dc995"
ALERTING_LEVEL = 0.001

# if a path was provided as command line parameter, it will override the config.yaml path:
# create parser
parser = argparse.ArgumentParser()

# we allow to pass path and alert level as command line parameters.
# If they are present, they will override the values in config.yaml
parser.add_argument("-p", "--path", required=True,
                    help="Path to file with hashes")
parser.add_argument("-a", "--alertlv", default=ALERTING_LEVEL, type=float,
                    help="Percentage of reporting scanners to define a file as malicious, e.g. 0.1")

# parse the arguments
args = parser.parse_args()
FILE_PATH = args.path
ALERTING_LEVEL = args.alertlv

print(f"""
Working with the following parameters:
Files with hashes: {FILE_PATH}
Alerting level: {ALERTING_LEVEL}
""")

# Initializing our VirusTotal API with a key
vt = VirusTotalPublicApi(VT_KEY)

# The entity handler will take care of managing all files and their VT results
entity_handler = entityHandler()

file = open(FILE_PATH, 'r')
hashes = file.readlines()

print(f"Parsing hashes...")
for hash in hashes:
    entity_handler.add_hash(hash, ALERTING_LEVEL)

print(f"Done\n")

# VirusTotal polling
entity_handler.retrieve_virustotal_results()

# return relevant results
findings_counter = 0
for hash, observed_entity in entity_handler.get_entities():
    if observed_entity.is_malicious():
        findings_counter += 1
        print(f'====== {hash[0:10]} ======')
        print('Potentially malicious hash for the following files:')

        print(f'\n{observed_entity.count_alerting_scanners()} out of {observed_entity.count_total_scanners()} scanners identified this file as malicious.')
        print('--------------------------------------------------------\n\n\n')
        #print(f'VT Result is: {observed_entity.get_virustotal_result()}')

print(
    f'Finished processing {entity_handler.count_entities()} files. {findings_counter} findings were reported.')
