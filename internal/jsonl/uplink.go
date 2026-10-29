package jsonl

// UplinkThreat is the threat of a row of the uplink watchdog
// (internal/uplink): the uplink connection is active again after a down
// period. pf uplink watch writes one such row for each down period. pf
// alert tails the file and posts the row.
const UplinkThreat = "uplink"
