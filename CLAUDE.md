<!-- enzyme:start -->
## Enzyme CLI

Use the Enzyme CLI for retrieving context from this vault. Run all commands from the vault root.

### Working memory

Enzyme petri provides your working memory — entities and catalysts (thematic phrases) from the vault.
If petri context was injected automatically (via hook), you already have it. If not, run it yourself
after the user's first message:

- **Specific prompt** ("what pages have I built", "remind me about the auth discussion"):
  `enzyme petri --query "user's question"` — returns entities and catalysts ranked by relevance.
- **Broad prompt** ("hey", "explore my ideas", "what have I been thinking about"):
  `enzyme petri` — returns the full landscape: top entities by recency with all their catalysts.

Use the catalyst phrases as vocabulary for composing `enzyme catalyze` queries — they connect
to pre-computed content that the user's raw words won't find.

### Semantic search

`enzyme catalyze "query"` — search by concept/theme. Compose queries using catalyst vocabulary
from petri rather than the user's raw words.

Example flow:
1. Petri returns entity `design` with catalyst "iterative page design with distinct visual identities"
2. User asked "what pages have I built"
3. Compose: `enzyme catalyze "page creation iterative design visual identities"`

### Other commands

- `enzyme refresh` — re-index changed content (runs on hooks/crons, rarely needed manually)
- `enzyme apply ./target-dir` — index external content using vault catalysts, then `enzyme catalyze "query" --target ./target-dir`
- `grep` — exact tag, wikilink, or text matches (names, `#tags`, `[[links]]`)

**Tag search:** Tags appear as `- tag` in frontmatter and `#tag` inline. Search without `#` to catch both.

**Presentation registers:** Pass `--register` to catalyze to control framing:
- `explore` (default) — wonder, probe, notice patterns
- `continuity` — restore what the user knew, show trajectory, enable forward motion
- `reference` — surface what drew attention, connect imports to the user's own thinking

Results include `presentation_guidance` — follow these when framing the surfaced content.
<!-- enzyme:end -->