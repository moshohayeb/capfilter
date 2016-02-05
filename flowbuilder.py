#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json

EVENTS_FILE_NAME = './events.txt'
TMP_FILE_NAME = '/tmp/__events__.json'

def build_flow_file(filename = EVENTS_FILE_NAME):
	flows = {}

	print('building(%s -> %s)' % (filename, TMP_FILE_NAME))
	try:
		fp = open(filename, 'r')
	except Exception, e:
		print('error(%s)' % e)
		return False

	for line in fp:
		line = line.rstrip('\n')
		try:
			entry = json.loads(line)
		except Exception, e:
			# print('error(%s:%s)' % (line, str(e)))
			continue

		if entry.get('action') != None: continue # Filter open/close

		id = entry['flow_id']
		if id == -1: continue
		if id not in flows: flows[id] = []
		flows[id].append(entry)

	json.dump(flows, open(TMP_FILE_NAME, 'w+'))
	print('done')
	return flows

if __name__ == '__main__':
	build_flow_file()
