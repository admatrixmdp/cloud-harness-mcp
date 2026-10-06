package skillarchive

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"strings"
	"testing"
)

func deflateRaw(raw []byte) []byte {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(raw); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func makeZip(entries []struct {
	name   string
	data   string
	method uint16
}) []byte {
	var locals, centrals []byte
	offset := 0
	for _, entry := range entries {
		name := []byte(entry.name)
		raw := []byte(entry.data)
		method := entry.method
		if method == 0 && entry.method != methodStored {
			method = methodDeflate
		}
		body := raw
		if method == methodDeflate {
			body = deflateRaw(raw)
		}
		local := make([]byte, 30)
		binary.LittleEndian.PutUint32(local[0:], localSignature)
		binary.LittleEndian.PutUint16(local[4:], 20)
		binary.LittleEndian.PutUint16(local[8:], method)
		binary.LittleEndian.PutUint32(local[18:], uint32(len(body)))
		binary.LittleEndian.PutUint32(local[22:], uint32(len(raw)))
		binary.LittleEndian.PutUint16(local[26:], uint16(len(name)))
		locals = append(locals, local...)
		locals = append(locals, name...)
		locals = append(locals, body...)

		central := make([]byte, 46)
		binary.LittleEndian.PutUint32(central[0:], centralSignature)
		binary.LittleEndian.PutUint16(central[4:], 20)
		binary.LittleEndian.PutUint16(central[6:], 20)
		binary.LittleEndian.PutUint16(central[10:], method)
		binary.LittleEndian.PutUint32(central[20:], uint32(len(body)))
		binary.LittleEndian.PutUint32(central[24:], uint32(len(raw)))
		binary.LittleEndian.PutUint16(central[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(central[42:], uint32(offset))
		centrals = append(centrals, central...)
		centrals = append(centrals, name...)
		offset += 30 + len(name) + len(body)
	}
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:], eocdSignature)
	binary.LittleEndian.PutUint16(eocd[8:], uint16(len(entries)))
	binary.LittleEndian.PutUint16(eocd[10:], uint16(len(entries)))
	binary.LittleEndian.PutUint32(eocd[12:], uint32(len(centrals)))
	binary.LittleEndian.PutUint32(eocd[16:], uint32(offset))
	out := make([]byte, 0, len(locals)+len(centrals)+len(eocd))
	out = append(out, locals...)
	out = append(out, centrals...)
	out = append(out, eocd...)
	return out
}

func document(name, body string) string {
	return "---\nname: " + name + "\n---\n" + body + "\n"
}

func skill(slug, body string) struct {
	name   string
	data   string
	method uint16
} {
	return struct {
		name   string
		data   string
		method uint16
	}{name: slug + "/SKILL.md", data: document(slug, body), method: methodDeflate}
}

func TestReadDerivesSlugFromDirectory(t *testing.T) {
	entries, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{skill("alpha", "body"), skill("nested/beta", "body")}))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Slug != "alpha" || entries[1].Slug != "beta" {
		t.Fatalf("%#v", entries)
	}
	if entries[0].DisplayName != "alpha" || !strings.Contains(entries[0].Instructions, "body") {
		t.Fatalf("%#v", entries[0])
	}
}

func TestReadStoredAndDeflated(t *testing.T) {
	stored := skill("stored", "body")
	stored.method = methodStored
	entries, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{stored, skill("packed", "body")}))
	if err != nil || len(entries) != 2 || entries[0].Slug != "stored" || entries[1].Slug != "packed" {
		t.Fatalf("%v %#v", err, entries)
	}
}

func TestReadIgnoresNonSkillFiles(t *testing.T) {
	entries, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{skill("alpha", "body"), {name: "alpha/README.md", data: "notes", method: methodDeflate}}))
	if err != nil || len(entries) != 1 || entries[0].Slug != "alpha" {
		t.Fatalf("%v %#v", err, entries)
	}
}

func TestReadRejectsTraversalAndCaps(t *testing.T) {
	if _, err := Read(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := Read([]byte("not a zip at all, just text")); err == nil {
		t.Fatal("not zip")
	}
	if _, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{{name: "../escape/SKILL.md", data: document("escape", "body"), method: methodDeflate}})); err == nil {
		t.Fatal("escape")
	}
	if _, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{{name: "/etc/SKILL.md", data: document("etc", "body"), method: methodDeflate}})); err == nil {
		t.Fatal("absolute")
	}
	if _, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{{name: "a\\..\\escape/SKILL.md", data: document("escape", "body"), method: methodDeflate}})); err == nil {
		t.Fatal("backslash")
	}
	if _, err := Read(bytes.Repeat([]byte{'A'}, 9*1024*1024)); err == nil {
		t.Fatal("oversized")
	}
}

func TestReadDoesNotInflateAssets(t *testing.T) {
	huge := strings.Repeat("a", MaxEntryBytes*3)
	entries, err := Read(makeZip([]struct {
		name   string
		data   string
		method uint16
	}{skill("alpha", "body"), {name: "alpha/assets/library.min.js", data: huge, method: methodDeflate}}))
	if err != nil || len(entries) != 1 || entries[0].Slug != "alpha" {
		t.Fatalf("%v %#v", err, entries)
	}
}

func TestTrustedVersion(t *testing.T) {
	if got := TrustedVersion("---\nname: tdd\nmetadata:\n  version: 1.2.3\n---\nbody\n"); got != "1.2.3" {
		t.Fatalf("%q", got)
	}
	if got := TrustedVersion("---\nname: tdd\nmetadata:\n  version: ../../etc/passwd\n---\nbody\n"); got != "" {
		t.Fatalf("%q", got)
	}
}
