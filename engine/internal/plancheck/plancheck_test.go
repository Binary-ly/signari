package plancheck

import (
	"reflect"
	"testing"
)

// The plans the guards read, as PostgreSQL writes them, so that a change in what
// counts as reading a table whole is a change somebody made.
func TestReadWholeTellsASeekFromAWalk(t *testing.T) {
	for name, tc := range map[string]struct {
		plan string
		want []string
	}{
		"a sequential scan": {`Seq Scan on sessions  (cost=1.00 rows=1 width=4)
  Filter: (revoked_at < now())`, []string{"sessions"}},
		"a seek": {`Index Scan using sessions_pkey on sessions  (cost=0.28 rows=1 width=4)
  Index Cond: (sid = 'x'::text)
  Filter: (revoked_at IS NULL)`, nil},
		"an index walked and filtered": {`Index Scan using sessions_pkey on sessions  (cost=0.28 rows=1 width=4)
  Filter: (revoked_at < now())`, []string{"sessions"}},
		"an index walked backwards for one row": {`Limit  (cost=0.28 rows=1 width=4)
  ->  Index Scan Backward using audit_events_pkey on audit_events  (cost=0.28 rows=1 width=4)`, nil},
		"a bitmap": {`Bitmap Heap Scan on families  (cost=1.00 rows=1 width=4)
  Recheck Cond: (revoked_at < now())
  ->  Bitmap Index Scan on families_ended_idx  (cost=0.00 rows=1 width=0)
        Index Cond: (revoked_at < now())`, nil},
		"the filter of the next scan is not this one's": {`Nested Loop  (cost=0.28 rows=1 width=4)
  ->  Index Scan using a_pkey on a  (cost=0.28 rows=1 width=4)
        Index Cond: (id = 1)
  ->  Index Scan using b_a on b  (cost=0.28 rows=1 width=4)
        Filter: (x = 1)`, []string{"b"}},
	} {
		if got := ReadWhole(tc.plan); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: read %v, want %v", name, got, tc.want)
		}
	}
}
