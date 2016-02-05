#!/usr/bin/env node
'use strict'

let _ = require('lodash')
var fs = require('fs-extra')
let util = require('util')
let exec = require('child_process').exec;
let sprintf = require("sprintf-js").sprintf
let async = require('async')
let desc = require('./description')

let EVENT_FILE = './events.txt'
let CACHED_EVENT_FILE = '/tmp/__events__.json'
let	EXCLUSIVE = { LU: 'LU', CALL: 'CALL', SMS: 'SMS' }
let DBGDIR = './dbg'

const MAX_SAMPLE_SIZE = 512

let isEventOfType = function (events, eventName) {
	return _.some(events, value => _.startsWith(value.event, eventName))
}

let dd = {}

let flowToCap = function (job, done) {
	exec(job.command, (err, stdout, stderr) => {
		if (err) {
			console.log('failure writing %s (%s)', job.path, err)
			done(err)
			return
		}
		done()
	});
}

let flowToString = function (flow) {
	let eventNames = _.map(flow, 'event')
	let concat = `[ ${_.join(eventNames, ', ')} ]`
	return concat
}

/* flow is assumed sorted */
let flowDissect = function (flow, index) {
	let flowid = _.get(_.head(flow), 'flow_id')
	let frame = _.get(_.head(flow), 'frame')
	let events, json, path, frames, command, base, prevf
	let dirname, total
	let count, flowString
	let description
	let keys

	if (frame === -1) return

	cur ++;
	if (cur > MAX_SAMPLE_SIZE) return

	flowString = flowToString(flow)
	count = _.size(flowsString) - _.size(_.difference(flowsString, [flowString]))
	total = _.size(flows)

	dirname = util.format("%s/%d-%d-%s", DBGDIR, count, _.size(flow), flowid)
	fs.emptyDirSync(dirname)

	// write the raw events to txt file
	path = util.format('%s/events.txt', dirname)
	events = fs.createWriteStream(path)

	path = util.format('%s/raw.json', dirname)
	json = fs.createWriteStream(path)
	json.write(JSON.stringify(flow, null, 4))
	json.end()


	base = 0
	frame = 1

	keys = _.map(flow, f => f.event)
	_.some(desc, (d, key) => {
		if (_.isEqual(d, keys)) {
			description = key;
			return true
		}
		return false
	})

	dd[index] = keys

	events.write('---------------------------------------------------------------\n')
	events.write(sprintf('Description: %s\n', description))
	events.write(sprintf('Commonality: %d/%d (%.2f%%)\n', count, total, (count/total) * 100))
	events.write(sprintf('Capfile:     %s/dump.pcap\n', dirname))
	events.write(sprintf('Raw JSON:    %s/raw.json\n', dirname))
	events.write('---------------------------------------------------------------\n')
	events.write(sprintf('%-5s %-5s %-35s %-8s\n', '#', 'Frame', 'Event', 'Time'))
	events.write('---------------------------------------------------------------\n')
	_.forEach(flow, (ev, i) => {
		if (base === 0) {
			base = +ev.time
			prevf = +ev.frame
		}

		if (+ev.frame !== prevf) {
			frame++;
			prevf = +ev.frame
		}

		let diff = +ev.time - base;
		let line = sprintf('%-5d %-5d %-35s %+-10.6f sec\n', i, frame, ev.event, (diff / 1000000))
		events.write(line)
	})
	events.write('---------------------------------------------------------------\n')
	events.end()

	// extract the event from the pcap
	frames = _.map(flow, 'frame')
	path = util.format('%s/dump.pcap', dirname)
	command = util.format('./capfilter %s %s', path, _.join(frames, ' '))
	queue.push({ path, frames, command })
}

fs.removeSync(DBGDIR)
fs.mkdirpSync(DBGDIR)

let cur = 0
let queue = async.queue(flowToCap, 4)
let jsonEvents = JSON.parse(fs.readFileSync(CACHED_EVENT_FILE))

let flows = [ ]
_.each(jsonEvents, (events, id) => {
	let sevents = _.sortBy(events, 'time')
	flows.push(sevents)
})

// console.log(flows)
let flowsString = _.map(flows, flowToString)
let uf = _.uniqBy(flows, flowToString)
_.each(uf, flowDissect)

console.log('Total Flows: %d', _.size(jsonEvents))
console.log('Uniq: %d', _.size(uf))
