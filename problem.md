You are a senior Python backend engineer.

Analyze and fix ONLY the following issues in this repository.

IMPORTANT:
- Read the related files first before editing.
- Explain root cause before changing code.
- Preserve current architecture and coding style.
- Do not introduce breaking API changes.
- After fixing, explain exactly what changed.
- Generate minimal, production-safe patches.

Issues to fix:

Pipeline breaks when no valid DNS queries exist


Problem:
embed_score.py line 417 returns "no_valid_queries" but does not write embed_scores.json.

As a result:
- entropy branch and DGA branch still produce outputs
- aggregator later reads stale/missing embedding results
- pipeline becomes inconsistent

Required fix:
1. Ensure embed_scores.json is ALWAYS generated.
2. When no valid queries exist:
   - write a valid empty JSON structure
   - include metadata/status explaining no valid queries
3. Aggregator must safely handle empty embedding results.
4. Prevent stale previous-run files from being reused.
5. Add defensive validation and logging.

Expected behavior:
- pipeline never crashes
- downstream stages always receive deterministic files
- rerunning pipeline cannot accidentally reuse old scores

Report shows benign domains in "Top Suspicious Domains"


Problem:
generate_report.py line 82 creates:
    suspected = ...

But line 87 incorrectly uses:
    sorted_scores[:top_n]

instead of:
    suspected[:top_n]

This causes benign domains to appear in suspicious section.

Required fix:
1. Correct the logic so only suspicious domains appear.
2. Preserve existing sorting behavior.
3. Add validation to ensure:
   - suspicious list never contains benign verdicts
4. Add small inline comments explaining the bug.

Expected behavior:
- "Top Suspicious Domains" contains only suspicious entries
- report output remains backward compatible
 Aggregator can merge scores from different domains


Problem:
aggregate_scores.py line 156 joins only on query_id.

This is unsafe because:
- different branches may produce different ordering
- stale files may exist
- query_id alone is insufficient identity

This can silently combine scores from different domains.

Required fix:
1. Make aggregation deterministic and safe.
2. Use composite validation:
   - query_id
   - domain
   - source
3. Detect mismatches explicitly.
4. Fail safely with clear warnings/errors instead of silently merging.
5. Add normalization if needed (case handling, whitespace, etc.)
6. Ensure aggregation remains backward compatible where possible.

Expected behavior:
- scores cannot be merged across different domains
- mismatched rows are detected immediately
- aggregation is deterministic across reruns

================================================================

Workflow requirements:
1. First inspect the current implementation carefully.
2. Identify all affected files.
3. Explain the root cause for each issue.
4. Propose fixes before editing.
5. Then implement changes.
6. Show unified diffs for every modified file.
7. Finally summarize:
   - what was fixed
   - why it was happening
   - possible remaining edge cases

Also:
- check whether there are hidden side effects
- check for stale-cache/file reuse bugs
- check for silent failure paths
- check for data consistency issues across the ML pipeline