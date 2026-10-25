package attack

import "testing"

func TestTableIntegrity(t *testing.T) {
	for id, tech := range table {
		if id != tech.ID {
			t.Errorf("key %q holds entry with ID %q", id, tech.ID)
		}
		if !idPattern.MatchString(id) {
			t.Errorf("malformed ID %q", id)
		}
		if tech.Name == "" || len(tech.Tactics) == 0 {
			t.Errorf("%s: missing name or tactics", id)
		}
		if p := Parent(id); p != id {
			if _, ok := table[p]; !ok {
				t.Errorf("%s: parent %s missing; fallback-to-parent would be unresolvable", id, p)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		ids     []string
		wantErr bool
	}{
		{nil, false},
		{[]string{"T1014", "T1053.003"}, false},
		{[]string{"T1053.999"}, true},
		{[]string{"t1014"}, true},
		{[]string{"T10141"}, true},
		{[]string{"T9999"}, true},
	}
	for _, c := range cases {
		if err := Validate(c.ids); (err != nil) != c.wantErr {
			t.Errorf("Validate(%v) err=%v, wantErr=%v", c.ids, err, c.wantErr)
		}
	}
}

func TestURL(t *testing.T) {
	tech, _ := Lookup("T1053.003")
	if got, want := tech.URL(), "https://attack.mitre.org/techniques/T1053/003/"; got != want {
		t.Errorf("URL() = %q, want %q", got, want)
	}
}
