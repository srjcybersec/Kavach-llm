#Requires -Version 5.1
<#
  Creates a new Git repo with many small commits and irregular timestamps.

  Window (local): 2026-04-03 11:00 → 2026-04-04 02:00
  Dates use GIT_AUTHOR_DATE / GIT_COMMITTER_DATE (Git stores UTC).

  Re-run: Remove-Item -Recurse -Force .git  then run this script from repo root is not needed;
  script cd's to kavach-llm parent of scripts/.
#>
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

if (Test-Path (Join-Path $RepoRoot ".git")) {
  Write-Host "ERROR: .git already exists. Delete first: Remove-Item -Recurse -Force .git" -ForegroundColor Red
  exit 1
}

$start = Get-Date -Year 2026 -Month 4 -Day 3 -Hour 11 -Minute 0 -Second 0
$end   = Get-Date -Year 2026 -Month 4 -Day 4 -Hour 2  -Minute 0 -Second 0
if ($end -le $start) { throw "Invalid time window." }

function Set-CommitDates([datetime]$WhenLocal) {
  $iso = $WhenLocal.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $env:GIT_AUTHOR_DATE = $iso
  $env:GIT_COMMITTER_DATE = $iso
}
function Clear-CommitDates {
  Remove-Item Env:GIT_AUTHOR_DATE, Env:GIT_COMMITTER_DATE -ErrorAction SilentlyContinue
}
function Commit-At([datetime]$dt, [string]$message) {
  Set-CommitDates $dt
  git commit -m $message
  Clear-CommitDates
}

function Get-WalkCommitTimes {
  param(
    [datetime]$WinStart,
    [datetime]$WinEnd,
    [int]$Count,
    [System.Random]$Rng
  )
  if ($Count -lt 1) { return @() }
  if ($Count -eq 1) {
    return ,@($WinStart.AddMinutes($Rng.Next(2, 12)).AddSeconds($Rng.Next(-30, 40)))
  }

  $span = $WinEnd - $WinStart
  # ~3 min minimum average gap so we can fit many commits in ~15h
  $minTotalSlack = [TimeSpan]::FromMinutes(3 * [Math]::Max(1, $Count - 1))
  if ($span -lt $minTotalSlack) { throw "Window too tight for commit count $($Count): need at least $($minTotalSlack.TotalMinutes) min." }

  $times = New-Object System.Collections.Generic.List[datetime]
  $t = $WinStart.AddMinutes($Rng.Next(0, 9)).AddSeconds($Rng.Next(-25, 35))
  [void]$times.Add($t)

  for ($i = 1; $i -lt $Count; $i++) {
    $remaining = $Count - $i
    $room = $WinEnd - $t

    if ($room.TotalMinutes -lt 4) {
      $gapTicks = [long]($room.Ticks / [double]([Math]::Max(1, $remaining)))
      $step = [TimeSpan]::FromTicks([Math]::Max([TimeSpan]::FromSeconds(8).Ticks, $gapTicks))
      $t = $t.Add($step).AddSeconds($Rng.Next(-5, 6))
      if ($t -ge $WinEnd) { $t = $WinEnd.AddSeconds(-$Rng.Next(3, 22) - $remaining) }
      if ($t -le $times[-1]) { $t = $times[-1].AddSeconds(8 + $Rng.Next(0, 15)) }
      [void]$times.Add($t)
      continue
    }

    $idealStep = $room.Ticks / [double]$remaining
    $noise = 0.32 + $Rng.NextDouble() * 1.12
    $stepTicks = [long]($idealStep * $noise)
    $step = [TimeSpan]::FromTicks([Math]::Max([TimeSpan]::FromMinutes(2).Ticks, [Math]::Min($stepTicks, ($room.Ticks * 0.82))))

    if ($Rng.NextDouble() -lt 0.16) {
      $step = $step.Add([TimeSpan]::FromMinutes($Rng.Next(18, 75)))
    } elseif ($Rng.NextDouble() -lt 0.30) {
      $step = $step.Add([TimeSpan]::FromMinutes($Rng.Next(8, 28)))
    }

    $t = $t.Add($step).AddSeconds($Rng.Next(-40, 45))
    if ($t -ge $WinEnd) {
      $t = $WinEnd.AddSeconds(-$Rng.Next(30, 240) - ($Count - $i) * 2)
    }
    if ($t -le $times[-1]) {
      $t = $times[-1].AddMinutes($Rng.Next(3, 18)).AddSeconds($Rng.Next(-15, 30))
    }
    [void]$times.Add($t)
  }

  while ($times.Count -lt $Count) {
    $prev = $times[-1]
    $need = $Count - $times.Count
    $slack = $WinEnd - $prev
    if ($slack.TotalSeconds -lt 2) {
      $times[$times.Count - 1] = $WinEnd.AddSeconds(-$need * 2 - $Rng.Next(2, 10))
      $prev = $times[-1]
      $slack = $WinEnd - $prev
    }
    $chunk = $slack.Ticks / [double]($need + 1)
    $t = $prev.AddTicks([long]([Math]::Max([TimeSpan]::FromSeconds(6).Ticks, $chunk * ($Rng.NextDouble() * 0.52 + 0.20)))).AddSeconds($Rng.Next(-15, 18))
    if ($t -le $prev) { $t = $prev.AddSeconds(6 + $Rng.Next(0, 20)) }
    if ($t -ge $WinEnd) { $t = $WinEnd.AddSeconds(-$Rng.Next(5, 45) - $need) }
    [void]$times.Add($t)
  }

  $pen = $times[$times.Count - 2]
  $times[$times.Count - 1] = $pen.AddMinutes($Rng.Next(4, 35)).AddSeconds($Rng.Next(-30, 40))
  if ($times[-1] -gt $WinEnd) { $times[-1] = $WinEnd.AddSeconds(-$Rng.Next(12, 120)) }
  if ($times[-1] -le $pen) {
    $times[-1] = $pen.AddSeconds(30 + $Rng.Next(0, 400))
    if ($times[-1] -gt $WinEnd) { $times[-1] = $WinEnd.AddSeconds(-$Rng.Next(6, 45)) }
  }

  for ($i = 1; $i -lt $times.Count; $i++) {
    if ($times[$i] -le $times[$i - 1]) {
      $times[$i] = $times[$i - 1].AddSeconds(14 + $Rng.Next(0, 100))
    }
  }
  if ($times[-1] -gt $WinEnd) {
    $overBy = $times[-1] - $WinEnd
    for ($j = 0; $j -lt $times.Count; $j++) { $times[$j] = $times[$j].Subtract($overBy) }
    for ($i = 1; $i -lt $times.Count; $i++) {
      if ($times[$i] -le $times[$i - 1]) { $times[$i] = $times[$i - 1].AddSeconds(10) }
    }
  }

  if ($times.Count -ne $Count) { throw "Get-WalkCommitTimes: expected $Count stamps, got $($times.Count)." }
  return ,$times.ToArray()
}

git init -b main

$commits = @(
  @{ M = "chore: add npm workspaces root manifest"; A = @("package.json") },
  @{ M = "chore: add package lockfile"; A = @("package-lock.json") },
  @{ M = "chore: add ESLint config"; A = @(".eslintrc") },
  @{ M = "chore: add Prettier config"; A = @(".prettierrc") },
  @{ M = "chore: add TypeScript project references"; A = @("tsconfig.json", "tsconfig.base.json") },
  @{ M = "chore: add gitignore"; A = @(".gitignore") },
  @{ M = "chore: add root Tailwind config"; A = @("tailwind.config.js") },
  @{ M = "chore: add Docker Compose stack"; A = @("docker-compose.yml") },
  @{ M = "docs: add screenshots placeholder"; A = @("docs") },
  @{ M = "docs: add README"; A = @("README.md") },
  @{ M = "docs: add environment variable template"; A = @(".env.example") },
  @{ M = "feat(backend): add service package manifest"; A = @("apps/backend/package.json") },
  @{ M = "feat(backend): add backend TypeScript config"; A = @("apps/backend/tsconfig.json") },
  @{ M = "feat(backend): add backend Dockerfile"; A = @("apps/backend/Dockerfile") },
  @{ M = "feat(backend): add Prisma schema and migrations"; A = @("apps/backend/prisma") },
  @{ M = "feat(backend): add runtime config"; A = @("apps/backend/src/config.ts") },
  @{ M = "feat(backend): add env loader"; A = @("apps/backend/src/envLoader.ts") },
  @{ M = "feat(backend): add Prisma client bootstrap"; A = @("apps/backend/src/prismaClient.ts") },
  @{ M = "feat(backend): add Express type augmentations"; A = @("apps/backend/src/types") },
  @{ M = "feat(backend): add JWT helpers"; A = @("apps/backend/src/lib/jwt.ts") },
  @{ M = "feat(backend): add security middleware"; A = @("apps/backend/src/middleware/security.ts") },
  @{ M = "feat(backend): add session auth middleware"; A = @("apps/backend/src/middleware/auth.ts") },
  @{ M = "feat(backend): add auth routes"; A = @("apps/backend/src/routes/auth.ts") },
  @{ M = "feat(backend): add health route"; A = @("apps/backend/src/routes/health.ts") },
  @{ M = "feat(backend): add pattern utilities"; A = @("apps/backend/src/lib/patterns.ts") },
  @{ M = "feat(backend): add embedding utilities"; A = @("apps/backend/src/lib/embeddings.ts") },
  @{ M = "feat(backend): add adaptive weights"; A = @("apps/backend/src/lib/adaptiveWeights.ts") },
  @{ M = "feat(backend): add input scanner middleware"; A = @("apps/backend/src/middleware/inputScanner.ts") },
  @{ M = "feat(backend): add threat classifier"; A = @("apps/backend/src/middleware/threatClassifier.ts") },
  @{ M = "feat(backend): add context tracker"; A = @("apps/backend/src/middleware/contextTracker.ts") },
  @{ M = "feat(backend): add arbitration service"; A = @("apps/backend/src/services/arbitrationService.ts") },
  @{ M = "feat(backend): add persona drift service"; A = @("apps/backend/src/services/personaDriftService.ts") },
  @{ M = "feat(backend): add Redis integration"; A = @("apps/backend/src/services/redisService.ts") },
  @{ M = "feat(backend): add output filter middleware"; A = @("apps/backend/src/middleware/outputFilter.ts") },
  @{ M = "feat(backend): add audit logger"; A = @("apps/backend/src/middleware/auditLogger.ts") },
  @{ M = "feat(backend): add policy engine"; A = @("apps/backend/src/middleware/policyEngine.ts") },
  @{ M = "feat(backend): add risk scorer"; A = @("apps/backend/src/lib/scorer.ts") },
  @{ M = "feat(backend): add Gemini LLM service"; A = @("apps/backend/src/services/llmService.ts") },
  @{ M = "feat(backend): add proxy route"; A = @("apps/backend/src/routes/proxy.ts") },
  @{ M = "feat(backend): add threat socket feed"; A = @("apps/backend/src/socket") },
  @{ M = "feat(backend): add policy rules API"; A = @("apps/backend/src/routes/policies.ts") },
  @{ M = "feat(backend): add analytics routes"; A = @("apps/backend/src/routes/analytics.ts") },
  @{ M = "feat(backend): add audit log API"; A = @("apps/backend/src/routes/audit.ts") },
  @{ M = "feat(backend): add API keys routes"; A = @("apps/backend/src/routes/keys.ts") },
  @{ M = "feat(backend): add feedback routes"; A = @("apps/backend/src/routes/feedback.ts") },
  @{ M = "feat(backend): add Express server wiring"; A = @("apps/backend/src/server.ts") },
  @{ M = "feat(backend): add application entrypoint"; A = @("apps/backend/src/index.ts") },
  @{ M = "test(backend): add input scanner unit tests"; A = @("apps/backend/src/middleware/__tests__") },
  @{ M = "test(backend): add proxy route e2e tests"; A = @("apps/backend/src/routes/__tests__") },
  @{ M = "feat(frontend): add Vite package manifest"; A = @("apps/frontend/package.json") },
  @{ M = "feat(frontend): add frontend TypeScript config"; A = @("apps/frontend/tsconfig.json") },
  @{ M = "feat(frontend): add Vite config"; A = @("apps/frontend/vite.config.ts") },
  @{ M = "feat(frontend): add PostCSS and Tailwind for Vite"; A = @("apps/frontend/postcss.config.js", "apps/frontend/tailwind.config.js") },
  @{ M = "feat(frontend): add HTML shell and container assets"; A = @("apps/frontend/index.html", "apps/frontend/Dockerfile", "apps/frontend/nginx.conf") },
  @{ M = "feat(frontend): add React entrypoint"; A = @("apps/frontend/src/main.tsx") },
  @{ M = "feat(frontend): add router and App shell"; A = @("apps/frontend/src/App.tsx", "apps/frontend/src/vite-env.d.ts") },
  @{ M = "feat(frontend): add client store"; A = @("apps/frontend/src/store") },
  @{ M = "feat(frontend): add shared lib utilities"; A = @("apps/frontend/src/lib") },
  @{ M = "feat(frontend): add API health hook"; A = @("apps/frontend/src/hooks/useApiHealth.ts") },
  @{ M = "feat(frontend): add socket hook"; A = @("apps/frontend/src/hooks/useSocket.ts") },
  @{ M = "feat(frontend): add threat types"; A = @("apps/frontend/src/types") },
  @{ M = "style(frontend): add global theme CSS"; A = @("apps/frontend/src/index.css") },
  @{ M = "feat(frontend): add badge primitive"; A = @("apps/frontend/src/components/ui/badge.tsx") },
  @{ M = "feat(frontend): add button primitive"; A = @("apps/frontend/src/components/ui/button.tsx") },
  @{ M = "feat(frontend): add card primitive"; A = @("apps/frontend/src/components/ui/card.tsx") },
  @{ M = "feat(frontend): add input primitive"; A = @("apps/frontend/src/components/ui/input.tsx") },
  @{ M = "feat(frontend): add textarea primitive"; A = @("apps/frontend/src/components/ui/textarea.tsx") },
  @{ M = "feat(frontend): add Shell layout"; A = @("apps/frontend/src/components/layout/Shell.tsx") },
  @{ M = "feat(frontend): add Sidebar layout"; A = @("apps/frontend/src/components/layout/Sidebar.tsx") },
  @{ M = "feat(frontend): add Topbar layout"; A = @("apps/frontend/src/components/layout/Topbar.tsx") },
  @{ M = "feat(frontend): add system status bar"; A = @("apps/frontend/src/components/layout/SystemStatusBar.tsx") },
  @{ M = "feat(frontend): add auth API client"; A = @("apps/frontend/src/services/authApi.ts") },
  @{ M = "feat(frontend): add proxy API client"; A = @("apps/frontend/src/services/proxyApi.ts") },
  @{ M = "feat(frontend): add Playground page"; A = @("apps/frontend/src/pages/Playground.tsx") },
  @{ M = "feat(frontend): add analytics API client"; A = @("apps/frontend/src/services/analyticsApi.ts") },
  @{ M = "feat(frontend): add report download client"; A = @("apps/frontend/src/services/reportApi.ts") },
  @{ M = "feat(frontend): add live threat feed panel"; A = @("apps/frontend/src/components/dashboard") },
  @{ M = "feat(frontend): add analytics dashboard page"; A = @("apps/frontend/src/pages/Dashboard.tsx") },
  @{ M = "feat(frontend): add policies API client"; A = @("apps/frontend/src/services/policiesApi.ts") },
  @{ M = "feat(frontend): add policies editor page"; A = @("apps/frontend/src/pages/Policies.tsx") },
  @{ M = "feat(frontend): add audit API client"; A = @("apps/frontend/src/services/auditApi.ts") },
  @{ M = "feat(frontend): add audit explorer page"; A = @("apps/frontend/src/pages/Audit.tsx") },
  @{ M = "feat(frontend): add API keys client"; A = @("apps/frontend/src/services/keysApi.ts") },
  @{ M = "feat(frontend): add settings page"; A = @("apps/frontend/src/pages/Settings.tsx") }
)

$n = $commits.Count
$rng = [System.Random]::new([BitConverter]::ToInt32([System.Guid]::NewGuid().ToByteArray(), 0))
$extraFinal = 1
$allTimes = Get-WalkCommitTimes -WinStart $start -WinEnd $end -Count ($n + $extraFinal) -Rng $rng
$times = $allTimes[0..($n - 1)]
$timeFinal = $allTimes[$n]

for ($i = 0; $i -lt $n; $i++) {
  foreach ($p in $commits[$i].A) {
    $full = Join-Path $RepoRoot $p
    if (-not (Test-Path $full)) {
      Write-Warning "Skip missing path: $p"
      continue
    }
    git add -- $p
  }
  if (-not (git diff --cached --quiet)) {
    Commit-At $times[$i] $commits[$i].M
  } else {
    Write-Warning "Nothing staged for: $($commits[$i].M)"
  }
}

git add -A
if (-not (git diff --cached --quiet)) {
  Commit-At $timeFinal "chore: add git history seeding script"
}

Write-Host ""
Write-Host "Commits: $(git rev-list --count HEAD). Author dates (local):" -ForegroundColor Green
$root = git rev-list --max-parents=0 HEAD
git --no-pager log -1 $root --format="first %ad  %s" --date=iso-local
git --no-pager log -1 HEAD --format="last  %ad  %s" --date=iso-local
