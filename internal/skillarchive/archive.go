package skillarchive

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
)

const (
	MaxBytes          = 8 * 1024 * 1024
	MaxEntries        = 200
	MaxFiles          = 20_000
	MaxEntryBytes     = 2 * 1024 * 1024
	MaxTotalBytes     = 32 * 1024 * 1024
	MaxInstructions   = 65_536
	MaxBase64         = 11_184_816
	eocdSignature     = 0x06054b50
	centralSignature  = 0x02014b50
	localSignature    = 0x04034b50
	methodStored      = 0
	methodDeflate     = 8
	eocdMin           = 22
	centralHeaderSize = 46
	localHeaderSize   = 30
)

var slugPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)
var semverPattern = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var frontmatterRe = regexp.MustCompile(`(?s)^---\r?\n(.*?)\r?\n---`)
var nameLineRe = regexp.MustCompile(`(?m)^\s*name\s*:\s*(.+?)\s*$`)
var metadataKeyRe = regexp.MustCompile(`^metadata\s*:\s*$`)
var versionLineRe = regexp.MustCompile(`^version\s*:\s*(.+?)\s*$`)

// Entry is one SKILL.md from a validated archive. Instructions never leave the runner.
type Entry struct {
	Path         string
	Slug         string
	DisplayName  string
	Instructions string
}

type centralEntry struct {
	name           string
	method         uint16
	compressedSize uint32
	localOffset    uint32
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", skillsreg.ErrInvalid, message)
}

func u16(b []byte, off int) uint16 {
	return binary.LittleEndian.Uint16(b[off:])
}

func u32(b []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(b[off:])
}

func findEOCD(bytes []byte) (int, error) {
	if len(bytes) < eocdMin {
		return 0, invalid("the archive is too short to be a zip")
	}
	earliest := len(bytes) - eocdMin - 65_535
	if earliest < 0 {
		earliest = 0
	}
	for offset := len(bytes) - eocdMin; offset >= earliest; offset-- {
		if u32(bytes, offset) == eocdSignature {
			return offset, nil
		}
	}
	return 0, invalid("the archive has no zip central directory")
}

func assertSafeEntryPath(name string) error {
	if name == "" {
		return invalid("the archive contains an entry with an empty name")
	}
	if strings.Contains(name, "\x00") {
		return invalid("the archive contains an entry with a null byte in its name")
	}
	if strings.Contains(name, "\\") {
		return invalid("the archive entry " + name + " uses a backslash separator")
	}
	if strings.HasPrefix(name, "/") {
		return invalid("the archive entry " + name + " is an absolute path")
	}
	if len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) {
		return invalid("the archive entry " + name + " looks like a drive path")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return invalid("the archive entry " + name + " escapes the extraction root")
		}
	}
	return nil
}

func readCentralDirectory(raw []byte) ([]centralEntry, error) {
	eocd, err := findEOCD(raw)
	if err != nil {
		return nil, err
	}
	entryCount := int(u16(raw, eocd+10))
	centralSize := int(u32(raw, eocd+12))
	centralOffset := int(u32(raw, eocd+16))
	if entryCount == 0 {
		return nil, invalid("the archive contains no entries")
	}
	if entryCount > MaxFiles {
		return nil, invalid(fmt.Sprintf("the archive contains %d files, above the limit of %d", entryCount, MaxFiles))
	}
	if centralOffset < 0 || centralSize < 0 || centralOffset+centralSize > len(raw) {
		return nil, invalid("the archive central directory is truncated")
	}
	entries := make([]centralEntry, 0, entryCount)
	cursor := centralOffset
	for i := 0; i < entryCount; i++ {
		if cursor+centralHeaderSize > len(raw) {
			return nil, invalid("the archive central directory is truncated")
		}
		if u32(raw, cursor) != centralSignature {
			return nil, invalid("the archive central directory is malformed")
		}
		method := u16(raw, cursor+10)
		compressedSize := u32(raw, cursor+20)
		nameLength := int(u16(raw, cursor+28))
		extraLength := int(u16(raw, cursor+30))
		commentLength := int(u16(raw, cursor+32))
		localOffset := u32(raw, cursor+42)
		if cursor+centralHeaderSize+nameLength > len(raw) {
			return nil, invalid("the archive central directory is truncated")
		}
		name := string(raw[cursor+centralHeaderSize : cursor+centralHeaderSize+nameLength])
		if err := assertSafeEntryPath(name); err != nil {
			return nil, err
		}
		entries = append(entries, centralEntry{name: name, method: method, compressedSize: compressedSize, localOffset: localOffset})
		cursor += centralHeaderSize + nameLength + extraLength + commentLength
	}
	return entries, nil
}

func readEntryData(raw []byte, entry centralEntry) ([]byte, error) {
	localOffset := int(entry.localOffset)
	if localOffset < 0 || localOffset+localHeaderSize > len(raw) {
		return nil, invalid("the archive entry " + entry.name + " is truncated")
	}
	if u32(raw, localOffset) != localSignature {
		return nil, invalid("the archive entry " + entry.name + " is malformed")
	}
	nameLength := int(u16(raw, localOffset+26))
	extraLength := int(u16(raw, localOffset+28))
	start := localOffset + localHeaderSize + nameLength + extraLength
	end := start + int(entry.compressedSize)
	if start < 0 || end < start || end > len(raw) {
		return nil, invalid("the archive entry " + entry.name + " is truncated")
	}
	data := raw[start:end]
	switch entry.method {
	case methodStored:
		if len(data) > MaxEntryBytes {
			return nil, invalid("the archive entry " + entry.name + " is larger than the per-entry limit")
		}
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case methodDeflate:
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		limited := &io.LimitedReader{R: r, N: int64(MaxEntryBytes) + 1}
		out, err := io.ReadAll(limited)
		if err != nil {
			return nil, invalid("the archive entry " + entry.name + " could not be decompressed")
		}
		if len(out) > MaxEntryBytes {
			return nil, invalid("the archive entry " + entry.name + " is larger than the per-entry limit")
		}
		return out, nil
	default:
		return nil, invalid(fmt.Sprintf("the archive entry %s uses unsupported compression method %d", entry.name, entry.method))
	}
}

func slugFromPath(name string) string {
	segments := make([]string, 0)
	for _, segment := range strings.Split(name, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	if len(segments) >= 2 {
		return segments[len(segments)-2]
	}
	return ""
}

func extractFrontmatter(document string) string {
	match := frontmatterRe.FindStringSubmatch(document)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func declaredName(instructions string) string {
	match := nameLineRe.FindStringSubmatch(extractFrontmatter(instructions))
	if len(match) < 2 {
		return ""
	}
	raw := strings.Trim(strings.TrimSpace(match[1]), `"'`)
	return strings.TrimSpace(raw)
}

// TrustedVersion returns metadata.version only when it is valid semver.
func TrustedVersion(document string) string {
	frontmatter := extractFrontmatter(document)
	if frontmatter == "" {
		return ""
	}
	metadataIndent := -1
	for _, line := range strings.Split(frontmatter, "\n") {
		line = strings.TrimRight(line, "\r")
		content := strings.TrimSpace(line)
		if content == "" || strings.HasPrefix(content, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if metadataIndent < 0 {
			if metadataKeyRe.MatchString(content) {
				metadataIndent = indent
			}
			continue
		}
		if indent <= metadataIndent {
			return ""
		}
		if match := versionLineRe.FindStringSubmatch(content); len(match) == 2 {
			raw := strings.Trim(strings.TrimSpace(match[1]), `"'`)
			if raw == "" || utf8.RuneCountInString(raw) > 64 || !semverPattern.MatchString(raw) {
				return ""
			}
			return raw
		}
	}
	return ""
}

func lastSegment(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return name
	}
	return parts[len(parts)-1]
}

// Read validates the whole archive before returning entries. A malformed zip
// never yields a partial library.
func Read(archive []byte) ([]Entry, error) {
	if len(archive) == 0 {
		return nil, invalid("the archive is empty")
	}
	if len(archive) > MaxBytes {
		return nil, invalid(fmt.Sprintf("the archive is larger than the limit of %d bytes", MaxBytes))
	}
	central, err := readCentralDirectory(archive)
	if err != nil {
		return nil, err
	}
	documents := make([]centralEntry, 0)
	for _, entry := range central {
		if lastSegment(entry.name) == "SKILL.md" {
			documents = append(documents, entry)
		}
	}
	if len(documents) == 0 {
		return nil, invalid("the archive contains no SKILL.md, so it holds no skills")
	}
	if len(documents) > MaxEntries {
		return nil, invalid(fmt.Sprintf("the archive contains %d skills, above the limit of %d", len(documents), MaxEntries))
	}
	contents := make(map[string][]byte, len(documents))
	total := 0
	for _, entry := range documents {
		data, err := readEntryData(archive, entry)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > MaxTotalBytes {
			return nil, invalid(fmt.Sprintf("the archive expands beyond the total limit of %d bytes", MaxTotalBytes))
		}
		contents[entry.name] = data
	}
	entries := make([]Entry, 0, len(documents))
	seen := map[string]struct{}{}
	for _, document := range documents {
		instructions := string(contents[document.name])
		if strings.TrimSpace(instructions) == "" {
			return nil, invalid("the archive entry " + document.name + " is empty")
		}
		if len(instructions) > MaxInstructions {
			return nil, invalid("the archive entry " + document.name + " is longer than the instructions limit")
		}
		if strings.Contains(instructions, "\x00") {
			return nil, invalid("the archive entry " + document.name + " contains a null byte")
		}
		slug := slugFromPath(document.name)
		if !slugPattern.MatchString(slug) {
			return nil, invalid("the archive entry " + document.name + " does not name a usable skill directory")
		}
		if _, dup := seen[slug]; dup {
			return nil, invalid("the archive declares the skill " + slug + " more than once")
		}
		seen[slug] = struct{}{}
		display := declaredName(instructions)
		if display == "" {
			display = slug
		}
		entries = append(entries, Entry{Path: document.name, Slug: slug, DisplayName: display, Instructions: instructions})
	}
	return entries, nil
}

// ZipEntry is a test fixture for MakeZip.
type ZipEntry struct {
	Name   string
	Data   string
	Method uint16
}

// Stored is ZIP method 0.
const Stored uint16 = methodStored

// Deflated is ZIP method 8.
const Deflated uint16 = methodDeflate

// MakeZip builds a minimal zip for tests without a third-party archive library.
func MakeZip(entries []ZipEntry) []byte {
	var locals, centrals []byte
	offset := 0
	for _, entry := range entries {
		name := []byte(entry.Name)
		raw := []byte(entry.Data)
		method := entry.Method
		if method != methodStored {
			method = methodDeflate
		}
		body := raw
		if method == methodDeflate {
			var buf bytes.Buffer
			w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
			_, _ = w.Write(raw)
			_ = w.Close()
			body = buf.Bytes()
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

// SkillDocument is a SKILL.md with a name frontmatter field.
func SkillDocument(name, body string) string {
	return "---\nname: " + name + "\n---\n" + body + "\n"
}
