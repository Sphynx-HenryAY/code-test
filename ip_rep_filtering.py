"""
python version requirement:
- 3.6+ for f-string support

module requirement:
- requests
- dotenv
"""


import csv
from time import time_ns
from json import dump as json_dump
from pprint import pprint
from functools import lru_cache

import requests
from dotenv import dotenv_values


APIKEY_ABDB = dotenv_values(".env").get('APIKEY_ABDB')

if APIKEY_ABDB is None:
	raise Exception('Please set APIKEY_ABDB in .env')


def rep_check_abdb(ip, days = 30):
	data_key_map = {
		'ip': 'ipAddress',
		'abuseConfidenceScore': 'abuseConfidenceScore',
		'countryCode': 'countryCode'
	}

	resp = requests.request(
		method = 'GET',
		url = 'https://api.abuseipdb.com/api/v2/check',
		headers = {
			'Accept': 'application/json',
			'Key': APIKEY_ABDB
		},
		params = {
			'ipAddress': ip,
			'maxAgeInDays': str(days)
		}
	)
	data = resp.json().get('data', {})

	return {
		k: data.get(v)
		for k, v in data_key_map.items()
	}

@lru_cache()
def load_iocs():
	with open('ioc.csv') as f_ioc:
		return {
			ioc['ip']: ioc
			for ioc in csv.DictReader(f_ioc)
		}

def data_order_abdb(rep):
	# sort by score then countryCode in ascending order
	# add minus sign if want decending: (-rep['abuseConfidenceScore'], -rep['countryCode'])
	return (rep['abuseConfidenceScore'], rep['countryCode'])

def validation_default(rep):
	return True if rep['abuseConfidenceScore'] <= 25 else False

def validation_ioc(rep):
	rule = load_iocs().get(rep['ip'], {}).get('rule')

	if rule is None:
		return None

	if rule == 'allow':
		return True

	if rule == 'deny':
		return False

def rep_filtering(list_rep):

	# the later in list, the higher priority
	validation_rules = [
		validation_default,
		validation_ioc
	]

	valid_ip = []

	for rep in list_rep:
		for validating in validation_rules:
			_valid = validating(rep)
			if _valid is not None:
				valid = _valid

		if valid:
			rep.update(load_iocs().get(rep['ip'], {}))
			valid_ip.append(rep)

	return valid_ip


if __name__ == '__main__':
	# step 1
	with open('abuse_db.txt', 'r') as f_ip:
		ip_file_content = f_ip.read()
		list_ip = ip_file_content.split()

	# step 2
	list_rep = [rep_check_abdb(ip) for ip in list_ip]

	# step 3
	sorted_list_rep = list(sorted(list_rep, key=data_order_abdb))

	# step 4
	with open(f'ip_rep_abdb_{time_ns()}_{abs(hash(ip_file_content))}.log', 'w') as f_log:
		json_dump(sorted_list_rep, f_log)

	# step 5
	valid_ip = rep_filtering(sorted_list_rep)

	# step 6
	pprint(valid_ip, indent = 2)