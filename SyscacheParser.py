# coding: utf-8

import sys
import json
# VT API module can be installed via pip install virustotal-api
from virus_total_apis import PublicApi as VirusTotalPublicApi
import argparse
from Registry import Registry
from progress.bar import Bar


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

        bar = Bar('Processing', max=entity_handler.count_entities())
        for hash, observed_entity in self.get_entities():
            bar.next()
            observed_entity.add_virustotal_result(
                vt.get_file_report(hash, waiting_time))
        bar.finish()
        print()
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

reg = Registry.Registry(FILE_PATH)

hashes = []

# Testing
def add_malicious_hashes():
    hashes = [
        "175e4690e15ff51ec9ad5ae0855504de5246d1895a7c5e3d651e978fff2e2afa",
        "179aee56dc67b625b65fd8033a5bdf23",
        "35760f8e46fa85ce06745ed2678f6420",
        "2c241c517c1b6e8c87b48d0800327330",
        "079eb243e1c8195a520eb1113b56c0a9",
        "36c1fa96c77a82931c49203afeb121b8",
        "01b1a3aee70a3d764ba7fca11b2ab820",
        "2c242f1c6808394d62dc6563020079e4",
        "36deaf2f096c2002837e3412451b7c70",
        "17898c3ef524e654b42bd39f305d0e90",
        "44dc5fda5409b2a020073a5af623c540",
        "36ba8b8a740ac6688826f2ee8bf4e780",
        "178b759ac68f8865ef93a9e0cc165d22",
        "450072c204886c2d13aa6256466a500b",
        "018814a16c1923d58f5a6895b99f87e0",
        "2c25974faeddcac237c4e76a33cb778a",
        "36ba60713e16caf95a1ddcc98cb91c00",
        "175542a8ddadc86ced0a23f67ab7f4b6",
        "44ad9de6f9055f6661cb108c712e3ce0",
        "067ba9bdcd7a8af2c2a03b4090162050",
        "2c327159ceb4fa42d9fb8ea343abbfb0",
        "36b6f081b798f878f915d6662858bfd0",
        "177c59925471ac4257e891d86b71bf80",
        "041ce8602c88517eff47eed504f7c3a0",
        "454fb394fbacf79a7474a8450eaa0120",
        "2c32ea1c70839b66f3430c5590a85753",
        "4532f9c6aba24527acefd24b131147f0",
        "178b9abd10b4ef991f61f2b4bdaabe77",
        "0502405e446f91f5e6d93517a70b7ef0",
        "36df91d7962a6e2b0bef4417d3603440"]


# add_malicious_hashes()


def rec(key, depth=0):
    for subkey in key.subkeys():
        rec(subkey, depth + 0)
        for value in [v for v in key.values()
                      if v.value_type() == Registry.RegBin]:
            shorten = value.value().decode('utf-16').rstrip('\x00')
            hashes.append(shorten[4:len(shorten)] + '\n')


rec(reg.root())

print(f"""
Working with the following parameters:
File with hashes: {FILE_PATH}
""")
# Alerting level: {ALERTING_LEVEL}

# Initializing our VirusTotal API with a key
vt = VirusTotalPublicApi(VT_KEY)

# The entity handler will take care of managing all files and their VT results
entity_handler = entityHandler()


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
