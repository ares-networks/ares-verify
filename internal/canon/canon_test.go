package canon

import "testing"

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"sorted keys", `{"b":1,"a":2}`, `{"a":2,"b":1}`, false},
		{"whitespace", "{ \"a\" : [ 1 , true , null ] }", `{"a":[1,true,null]}`, false},
		{"nul escaped", `{"k":"\u0000x\u0000"}`, `{"k":"\u0000x\u0000"}`, false},
		{"control lower hex", `"\u001f"`, `"\u001f"`, false},
		{"short escapes", `"\b\f\n\r\t\"\\"`, `"\b\f\n\r\t\"\\"`, false},
		{"slash not escaped", `"a\/b"`, `"a/b"`, false},
		{"html literal", `"<&>"`, `"<&>"`, false},
		{"non-ascii literal", `"é€😀"`, "\"é€\U0001F600\"", false},
		{"utf16 key order", "{\"\U0001F600\":1,\"￿\":2}", "{\"\U0001F600\":1,\"￿\":2}", false},
		{"negative zero", `-0`, `0`, false},
		{"fraction rejected", `1.5`, ``, true},
		{"exponent rejected", `1e3`, ``, true},
		{"too big", `9007199254740993`, ``, true},
		{"trailing", `{} {}`, ``, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(c.in))
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %s", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}
