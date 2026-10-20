package main

import (
	"fmt"
	"time"

	"signari.dev/engine/internal/keys"
)

// keyRotationPeriod reads SIGNARI_KEY_ROTATION_PERIOD: empty is off, and a
// period must leave a published key time to be fetched before the next is
// published, so anything under twice the publication wait is refused rather
// than rotating continuously.
func keyRotationPeriod(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 2*keys.MinPublishBeforeActive {
		return 0, fmt.Errorf("SIGNARI_KEY_ROTATION_PERIOD=%q: want a duration of at least %s, "+
			"such as 2160h for ninety days", v, 2*keys.MinPublishBeforeActive)
	}
	return d, nil
}
