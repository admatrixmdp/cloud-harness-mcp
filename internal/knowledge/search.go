package knowledge

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	embeddingDims       = 128
	embeddingModel      = "local-v1"
	rrfK                = 60
	maxSearchCandidates = 200
	maxFTSCandidates    = 100
)

// SearchHit is one knowledge_search result row (Zod KnowledgeSearchResultItem).
type SearchHit struct {
	Item             Item
	RelevancePercent int
	MatchMode        string
	FTSRank          int
	SemanticRank     int
	Snippet          string
}

// PublicJSON is the Zod-compatible search hit.
func (h SearchHit) PublicJSON() map[string]any {
	out := map[string]any{
		"item":             h.Item.PublicJSON(),
		"relevancePercent": h.RelevancePercent,
		"matchMode":        h.MatchMode,
	}
	if h.FTSRank > 0 {
		out["ftsRank"] = h.FTSRank
	}
	if h.SemanticRank > 0 {
		out["semanticRank"] = h.SemanticRank
	}
	if h.Snippet != "" {
		out["snippet"] = h.Snippet
	}
	return out
}

func upsertFTS(tx *sql.Tx, id, title string, tags []string, content string) error {
	if _, err := tx.Exec(`DELETE FROM knowledge_fts WHERE item_id = ?`, id); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO knowledge_fts (item_id, title, tags, content) VALUES (?, ?, ?, ?)`,
		id, title, strings.Join(tags, " "), content)
	return err
}

func (s *Store) dropIndex(id string) {
	_, _ = s.db.Exec(`DELETE FROM knowledge_fts WHERE item_id = ?`, id)
	_, _ = s.db.Exec(`DELETE FROM knowledge_embeddings WHERE item_id = ?`, id)
}

func (s *Store) indexEmbeddings(principalID, itemID, title, content string) {
	chunks := chunkMarkdown(content, title, 200)
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM knowledge_embeddings WHERE principal_id = ? AND item_id = ? AND model_fingerprint = ?`,
		principalID, itemID, embeddingModel); err != nil {
		return
	}
	for ordinal, chunk := range chunks {
		sum := sha256.Sum256([]byte(chunk))
		vec := localEmbedding(chunk, embeddingDims)
		if _, err := tx.Exec(`INSERT INTO knowledge_embeddings
			(principal_id, item_id, chunk_ordinal, chunk_sha256, vector_blob, dimensions, model_fingerprint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			principalID, itemID, ordinal, hex.EncodeToString(sum[:]), floatBlob(vec), embeddingDims, embeddingModel, now); err != nil {
			return
		}
	}
	_ = tx.Commit()
}

func sanitizeFTSQuery(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	parts := strings.Fields(b.String())
	if len(parts) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(parts))
	for _, tok := range parts {
		quoted = append(quoted, `"`+tok+`"*`)
	}
	return strings.Join(quoted, " OR ")
}

func localEmbedding(text string, dims int) []float32 {
	vec := make([]float32, dims)
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return vec
	}
	scale := float32(1 / math.Sqrt(float64(len(tokens))))
	for _, tok := range tokens {
		sum := sha256.Sum256([]byte(tok))
		bucket := int(binary.BigEndian.Uint16(sum[0:2])) % dims
		sign := float32(1)
		if sum[2]%2 != 0 {
			sign = -1
		}
		vec[bucket] += sign * scale
	}
	var norm float64
	for _, v := range vec {
		norm += float64(v) * float64(v)
	}
	norm = math.Sqrt(norm)
	if norm > 0 {
		for i := range vec {
			vec[i] = float32(float64(vec[i]) / norm)
		}
	}
	return vec
}

func tokenize(text string) []string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.Fields(b.String())
}

func chunkMarkdown(text, title string, targetTokens int) []string {
	paras := strings.Split(text, "\n")
	var blocks []string
	var cur strings.Builder
	for _, line := range paras {
		if strings.TrimSpace(line) == "" {
			if cur.Len() > 0 {
				blocks = append(blocks, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(line)
	}
	if cur.Len() > 0 {
		blocks = append(blocks, strings.TrimSpace(cur.String()))
	}
	if len(blocks) == 0 {
		if title != "" {
			return []string{title}
		}
		return []string{""}
	}
	prefix := ""
	if title != "" {
		prefix = "# " + title + "\n"
	}
	var chunks []string
	current := prefix
	currentTokens := len(strings.Fields(current))
	for _, p := range blocks {
		pTokens := len(strings.Fields(p))
		if currentTokens+pTokens > targetTokens && strings.TrimSpace(current) != "" {
			chunks = append(chunks, strings.TrimSpace(current))
			current = prefix + p + "\n"
			currentTokens = len(strings.Fields(current))
			continue
		}
		current += p + "\n"
		currentTokens += pTokens
	}
	if strings.TrimSpace(current) != "" {
		chunks = append(chunks, strings.TrimSpace(current))
	}
	if len(chunks) == 0 {
		return []string{text}
	}
	return chunks
}

func floatBlob(vec []float32) []byte {
	out := make([]byte, 4*len(vec))
	for i, v := range vec {
		binary.LittleEndian.PutUint32(out[i*4:], math.Float32bits(v))
	}
	return out
}

func blobFloats(b []byte) []float32 {
	n := len(b) / 4
	out := make([]float32, n)
	for i := 0; i < n; i++ {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return out
}

func cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na <= 0 || nb <= 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

type ftsHit struct {
	rank    int
	score   float64
	snippet string
}

type scoredHit struct {
	item      Item
	relevance int
	mode      string
	ftsRank   int
	semRank   int
	snippet   string
	occurred  int64
}

func (s *Store) SearchHits(p ListParams) ([]SearchHit, string, error) {
	if strings.TrimSpace(p.Query) == "" {
		return nil, "", fail(protocol.ErrorInvalidInput, "query is required")
	}
	if p.Limit <= 0 {
		p.Limit = 20
	}
	if p.Limit > 50 {
		return nil, "", fail(protocol.ErrorInvalidInput, "limit must be between 1 and 50")
	}
	offset := 0
	if p.Cursor != "" {
		n, err := strconv.Atoi(p.Cursor)
		if err != nil || n < 0 {
			return nil, "", fail(protocol.ErrorInvalidInput, "invalid knowledge cursor")
		}
		offset = n
	}

	ftsQuery := sanitizeFTSQuery(p.Query)
	ftsHits := map[string]ftsHit{}
	if ftsQuery != "" {
		rows, err := s.db.Query(`
			SELECT item_id, bm25(knowledge_fts, 3.0, 2.0, 1.0) as score,
			       snippet(knowledge_fts, 3, '<mark>', '</mark>', '...', 16) as snippet
			FROM knowledge_fts WHERE knowledge_fts MATCH ?
			ORDER BY bm25(knowledge_fts, 3.0, 2.0, 1.0) ASC LIMIT ?`, ftsQuery, maxFTSCandidates)
		if err == nil {
			idx := 0
			for rows.Next() {
				var id, snippet string
				var score float64
				if err := rows.Scan(&id, &score, &snippet); err != nil {
					continue
				}
				idx++
				ftsHits[id] = ftsHit{rank: idx, score: score, snippet: snippet}
			}
			_ = rows.Close()
		}
	}

	candidates, err := s.queryCandidates(p, maxSearchCandidates)
	if err != nil {
		return nil, "", err
	}
	if len(candidates) == 0 {
		return []SearchHit{}, "", nil
	}

	queryVec := localEmbedding(p.Query, embeddingDims)
	semScore := map[string]float64{}
	ids := make([]string, 0, len(candidates))
	for _, item := range candidates {
		ids = append(ids, item.ID)
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(ids)+1)
	args = append(args, p.PrincipalID)
	for _, id := range ids {
		args = append(args, id)
	}
	embRows, err := s.db.Query(`SELECT item_id, vector_blob, dimensions FROM knowledge_embeddings WHERE principal_id = ? AND item_id IN (`+placeholders+`)`, args...)
	if err == nil {
		for embRows.Next() {
			var id string
			var blob []byte
			var dims int
			if err := embRows.Scan(&id, &blob, &dims); err != nil {
				continue
			}
			sim := cosine(queryVec, blobFloats(blob))
			if sim > semScore[id] {
				semScore[id] = sim
			}
		}
		_ = embRows.Close()
	}
	type ranked struct {
		id  string
		sim float64
	}
	var rankedSem []ranked
	for id, sim := range semScore {
		if sim > 0.05 {
			rankedSem = append(rankedSem, ranked{id: id, sim: sim})
		}
	}
	sort.Slice(rankedSem, func(i, j int) bool { return rankedSem[i].sim > rankedSem[j].sim })
	semRank := map[string]int{}
	for i, r := range rankedSem {
		semRank[r.id] = i + 1
	}
	hasSemantic := len(semRank) > 0

	var scored []scoredHit
	for _, item := range candidates {
		fts, hasFTS := ftsHits[item.ID]
		sem, hasSem := semRank[item.ID]
		if !hasFTS && !hasSem && ftsQuery != "" {
			continue
		}
		var rrf float64
		mode := "hybrid"
		switch {
		case hasFTS && hasSem:
			rrf = (0.5 / float64(rrfK+fts.rank)) + (0.5 / float64(rrfK+sem))
			mode = "hybrid"
		case hasFTS:
			rrf = 0.5 / float64(rrfK+fts.rank)
			if hasSemantic {
				mode = "lexical"
			} else {
				mode = "lexical_fallback"
			}
		case hasSem:
			rrf = 0.5 / float64(rrfK+sem)
			mode = "semantic"
		default:
			rrf = 0.01
			mode = "lexical_fallback"
		}
		rel := int(math.Round(rrf * 61 * 100))
		if rel < 0 {
			rel = 0
		}
		if rel > 100 {
			rel = 100
		}
		occurred := item.OccurredAt
		if occurred == 0 {
			occurred = item.UpdatedAt
		}
		hit := scoredHit{item: item, relevance: rel, mode: mode, occurred: occurred}
		if hasFTS {
			hit.ftsRank = fts.rank
			hit.snippet = fts.snippet
		}
		if hasSem {
			hit.semRank = sem
		}
		scored = append(scored, hit)
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].relevance != scored[j].relevance {
			return scored[i].relevance > scored[j].relevance
		}
		if scored[i].occurred != scored[j].occurred {
			return scored[i].occurred > scored[j].occurred
		}
		return scored[i].item.ID > scored[j].item.ID
	})
	if offset > len(scored) {
		offset = len(scored)
	}
	end := offset + p.Limit
	if end > len(scored) {
		end = len(scored)
	}
	page := scored[offset:end]
	out := make([]SearchHit, 0, len(page))
	for _, h := range page {
		out = append(out, SearchHit{
			Item: h.item, RelevancePercent: h.relevance, MatchMode: h.mode,
			FTSRank: h.ftsRank, SemanticRank: h.semRank, Snippet: h.snippet,
		})
	}
	next := ""
	if end < len(scored) {
		next = strconv.Itoa(end)
	}
	return out, next, nil
}

func (s *Store) queryCandidates(p ListParams, limit int) ([]Item, error) {
	now := time.Now().UnixMilli()
	q := `SELECT id, principal_id, kind, scope, project_id, workspace_id, title, content, content_sha256, journal_type, occurred_at, generation, created_at, updated_at, expires_at, provenance_json FROM knowledge_items WHERE principal_id = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
	args := []any{p.PrincipalID, now}
	if p.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, p.Kind)
	}
	if len(p.Kinds) > 0 {
		placeholders := strings.Repeat("?,", len(p.Kinds))
		q += ` AND kind IN (` + placeholders[:len(placeholders)-1] + `)`
		for _, k := range p.Kinds {
			args = append(args, k)
		}
	}
	if p.Scope != "" {
		q += ` AND scope = ?`
		args = append(args, p.Scope)
		if p.Scope == "project" && p.ProjectID != "" {
			q += ` AND project_id = ?`
			args = append(args, p.ProjectID)
		} else if p.Scope == "workspace" && p.WorkspaceID != "" {
			q += ` AND workspace_id = ?`
			args = append(args, p.WorkspaceID)
		}
	} else if p.ProjectID != "" {
		q += ` AND project_id = ?`
		args = append(args, p.ProjectID)
	} else if p.WorkspaceID != "" {
		q += ` AND workspace_id = ?`
		args = append(args, p.WorkspaceID)
	}
	if p.JournalType != "" {
		q += ` AND journal_type = ?`
		args = append(args, p.JournalType)
	}
	tags, err := normalizeTags(p.Tags)
	if err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = placeholders[:len(placeholders)-1]
		if p.TagMatch == "any" {
			q += ` AND id IN (SELECT item_id FROM knowledge_tags WHERE tag IN (` + placeholders + `))`
			for _, tag := range tags {
				args = append(args, tag)
			}
		} else {
			q += ` AND id IN (SELECT item_id FROM knowledge_tags WHERE tag IN (` + placeholders + `) GROUP BY item_id HAVING COUNT(DISTINCT tag) = ?)`
			for _, tag := range tags {
				args = append(args, tag)
			}
			args = append(args, len(tags))
		}
	}
	q += ` ORDER BY COALESCE(occurred_at, updated_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fail(protocol.ErrorInternal, err.Error())
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, fail(protocol.ErrorInternal, err.Error())
		}
		tags, err := s.tagsFor(item.ID)
		if err != nil {
			return nil, err
		}
		item.Tags = tags
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fail(protocol.ErrorInternal, err.Error())
	}
	return out, nil
}
