package jsonl

// BlocksThreat is the threat of a notice row that counts the blocked
// requests to listed destinations on one segment. pf observe writes one
// such row for each segment at each flush (internal/observe blocks.go).
// pf alert adds the rows into its block digest. It does not post each row.
const BlocksThreat = "blocks"

// The classes of a block: the type of list that blocked the request.
const (
	// BlockSecurity is a feed that all segments get: a sources.json feed
	// with no segment, for example a malware or phishing list.
	BlockSecurity = "security"
	// BlockOperator is an entry of the operator in blacklist.domains or
	// blacklist.ips.
	BlockOperator = "operator"
	// BlockHouse is a list of the house only: a house feed (ads, trackers,
	// VPN and proxy bypass), house.domains or the house defaults.
	BlockHouse = "house"
	// BlockOther is a block with no list to name: a DNS-over-HTTPS name, a
	// name that paranoid mode does not allow, or listed queries that the
	// resolver did not log because of its log budget.
	BlockOther = "other"
)

// Blocks is the notice row of BlocksThreat. Counts is per class. Top has
// the most frequent destinations, but no BlockHouse destination: those
// are only a count.
type Blocks struct {
	T      string         `json:"t"`
	Threat string         `json:"threat"`
	Rule   string         `json:"rule"`
	Where  string         `json:"where"`
	Counts map[string]int `json:"counts"`
	Top    []BlockHit     `json:"top,omitempty"`
}

// BlockHit is one destination of a Blocks row: the class, the feed id
// ("local" for an operator entry, empty for BlockOther), the client, the
// name or address, and the number of blocks.
type BlockHit struct {
	Class string `json:"class"`
	Feed  string `json:"feed,omitempty"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	N     int    `json:"n"`
}
