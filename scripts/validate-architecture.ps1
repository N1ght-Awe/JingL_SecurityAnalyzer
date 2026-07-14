param([string]$Root = (Split-Path $PSScriptRoot -Parent))

$ErrorActionPreference = 'Stop'
$main = Join-Path $Root 'skill.md'
$refs = Join-Path $Root 'shared-references'
$requiredRefs = @(
  'source-routing.md', 'scan-index.md', 'candidate-ranking.md',
  'call-chain-tracing.md', 'proof-schema.md', 'security-tool-probing.md',
  'cross-repo-tracing.md', 'sanitizers.md', 'proof-patterns.md',
  'subskill-contract.md', 'agent-output-schema.md', 'repo-boundary-manifest.md',
  'report-schema.md', 'regression-matrix.md', 'coverage-metrics.md'
)

foreach ($name in $requiredRefs) {
  if (-not (Test-Path (Join-Path $refs $name))) { throw "Missing shared reference: $name" }
}

$text = Get-Content -Raw -Encoding UTF8 $main
foreach ($name in $requiredRefs) {
  if ($text -notmatch [regex]::Escape($name)) { throw "Main entry does not reference: $name" }
}

$skills = Get-ChildItem -Directory (Join-Path $Root 'skill')
if ($skills.Count -ne 18) { throw "Expected 18 subskills; found $($skills.Count)" }
foreach ($skill in $skills) {
  $file = Join-Path $skill.FullName 'skill.md'
  if (-not (Test-Path $file)) { throw "Subskill missing skill.md: $($skill.Name)" }
  $body = Get-Content -Raw -Encoding UTF8 $file
  if (([regex]::Matches($body, '(?m)^## [1-9]\.')).Count -lt 9) { throw "Subskill has fewer than nine core sections: $($skill.Name)" }
}

$index = Get-Content -Raw -Encoding UTF8 (Join-Path $refs 'scan-index.md')
foreach ($skill in $skills) {
  if ($index -notmatch [regex]::Escape("skill/$($skill.Name)")) { throw "Scan index has no route for subskill: $($skill.Name)" }
}

$patterns = Get-Content -Raw -Encoding UTF8 (Join-Path $refs 'proof-patterns.md')
if ($patterns -notmatch 'supply-chain\.upload-download-execute-without-verification') { throw 'Missing supply-chain proof pattern' }
if ($text -match '## 17') { throw 'Main entry still has a stale 17-type heading' }

Write-Output "PASS: 18 subskills, $($requiredRefs.Count) shared references, index routing, supply-chain proof pattern, and main entry are consistent."
