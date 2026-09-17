package opencensus

import (
	"slices"

	"go.opencensus.io/tag"
)

func appendIfMissing(slice []tag.Key, i tag.Key) []tag.Key {
	if slices.Contains(slice, i) {
		return slice
	}
	return append(slice, i)
}
