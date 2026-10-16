#Requires -Version 5.1

<#
.SYNOPSIS
Repairs what a failed CI run broke when the repair is mechanical, and explains the rest.

.DESCRIPTION
Run by .github/workflows/ci-autofix.yml for every failed security-ci or performance run, and
runnable by hand with -DryRun to see what it would do.

  formatting                     cargo fmt
  lints with a machine fix       cargo clippy --fix
  advisory with a fixed release  cargo update to the patched, semver-compatible version
  runner or network trouble      the failed jobs are rerun, once

Repairs are committed to autofix/<branch>, verified by a security-ci run dispatched on that branch,
and proposed as a pull request; nothing merges on its own. Anything left over (a failing test, an
advisory with no compatible fix, a slower scan) is written up with the failing steps and the error
lines pulled out of the log: as a comment on the pull request the run belonged to, or otherwise as
an issue, which the workflow closes once the branch is green again.

The work is split in three so the failed commit's code never runs next to a token that can write:

  Collect  reads the run and its log (needs a token that can read Actions)
  Repair   runs cargo on the failed commit, which executes its build scripts and proc macros, so it
           gets no token at all; it leaves repair.patch and the findings in -StateDirectory
  Apply    applies repair.patch (Rust sources and Cargo.lock only), pushes, and reports; it runs no
           code from the failed commit

Without -Mode all three run in turn, which is how it is run by hand.

No AI and no secrets: the workflow's own token is all it uses.
#>

[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Repair', 'Apply')]
    [string]$Mode,
    [long]$RunId,
    # A checkout of the failed commit, where repairs are made (Repair) or applied (Apply).
    [string]$WorkTree,
    # The pull request the run belonged to, if any.
    [string]$PullRequest,
    # Where the phases hand over state.json and repair.patch.
    [string]$StateDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "blackshard-repair-$RunId"),
    # Report what would happen without pushing, opening, commenting or rerunning anything.
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Lines that mean the runner or the network failed rather than the code.
$transientPattern = 'Could not resolve host|ETIMEDOUT|ECONNRESET|connection (reset|refused|timed out)|' +
    '50[234] (Bad Gateway|Service Unavailable|Gateway Time-?out)|429 Too Many Requests|rate limit|' +
    'The operation was canceled|runner has received a shutdown signal|lost communication with the server|' +
    'No space left on device|spurious network error'
# Lines worth showing a person: compiler and test errors, advisories, and the step's own error.
$keyLinePattern = '^error(\[E\d+\])?:|^\s+-->|panicked at|^test .* FAILED|^failures:|' +
    '^(ID|Crate|Title|Solution):|##\[error\]|^throw |Exception:|regression|disagree'
# What a mechanical repair may touch. Anything else in the patch means it did not come from
# cargo fmt, clippy --fix or cargo update, and is refused.
$repairablePath = '(^|/)Cargo\.lock$|\.rs$'

# Absolute, since Repair and Apply change into the work tree before writing or reading the patch.
$StateDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($StateDirectory)
$statePath = Join-Path $StateDirectory 'state.json'
$patchPath = Join-Path $StateDirectory 'repair.patch'

# Standard output only; a tool's complaints on stderr (a deleted branch's 404, cargo's progress)
# are not failures here.
function Read-Native([string]$Command, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 2>$null
}

function Invoke-Native([string]$Command, [string[]]$Arguments) {
    # Windows PowerShell 5.1 turns a native tool's stderr into terminating errors under 'Stop';
    # cargo reports progress there. The exit code is what decides success.
    $ErrorActionPreference = 'Continue'
    # Native output to the host, so it never becomes part of a function's return value.
    & $Command @Arguments 2>&1 | ForEach-Object { "$_" } | Out-Host
    $LASTEXITCODE
}

function Save-State($State) {
    New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Read-State {
    Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-Collect {
    if (-not $RunId) { throw '-RunId is required to collect a run.' }
    $run = gh run view $RunId --json headBranch,headSha,attempt,workflowName,url,jobs | ConvertFrom-Json
    $branch = $run.headBranch
    $state = [ordered]@{
        runId        = $RunId
        branch       = $branch
        fixBranch    = 'autofix/' + ($branch -replace '[^A-Za-z0-9/_.-]', '-')
        headSha      = $run.headSha
        workflowName = $run.workflowName
        url          = $run.url
        action       = 'repair'
        failedSteps  = @()
        otherSteps   = @()
        wantsFormat  = $false
        wantsLints   = $false
        wantsAudit   = $false
        compileError = $false
        keyLines     = @()
        repaired     = @()
        unrepaired   = @()
    }

    # A newer commit on the branch has its own run, and an open repair is already waiting for review.
    $head = Read-Native gh @('api', "repos/{owner}/{repo}/branches/$branch", '--jq', '.commit.sha')
    if ($LASTEXITCODE -ne 0) {
        # Most often a pull request branch deleted once it merged. This used to be read as the
        # branch having moved, and gh's exit code then failed the whole job.
        Write-Host "$branch no longer exists; there is nothing to repair."
        if (-not $DryRun) { $state.action = 'skip' }
    }
    elseif ($head -ne $run.headSha) {
        Write-Host "$branch has moved past $($run.headSha); its newer run decides."
        if (-not $DryRun) { $state.action = 'skip' }
    }

    $failedSteps = @(foreach ($job in $run.jobs | Where-Object conclusion -eq 'failure') {
            foreach ($step in $job.steps | Where-Object conclusion -eq 'failure') { "$($job.name): $($step.name)" }
        })
    if (-not $failedSteps) {
        # A job can fail without a failed step, when it times out or the runner is lost.
        $failedSteps = @($run.jobs | Where-Object conclusion -eq 'failure' | ForEach-Object { "$($_.name): (no step finished)" })
    }
    $log = @(Read-Native gh @('run', 'view', "$RunId", '--log-failed') | ForEach-Object {
            # "job<TAB>step<TAB>timestamp text", coloured; keep the text.
            ($_ -replace '^[^\t]*\t[^\t]*\t\W*\d{4}-\d\d-\d\dT[\d:.]+Z ?', '') -replace '(\x1b|\^\[)\[[0-9;]*m', ''
        })

    $state.failedSteps = $failedSteps
    $state.wantsFormat = [bool]($failedSteps -match 'cargo fmt')
    $state.wantsLints = [bool]($failedSteps -match 'cargo clippy')
    $state.wantsAudit = [bool]($failedSteps -match 'cargo audit')
    $state.otherSteps = @($failedSteps | Where-Object { $_ -notmatch 'cargo fmt|cargo clippy|cargo audit' })
    $state.compileError = [bool]($log -match '^error\[E\d+\]')
    $state.keyLines = @($log | Where-Object { $_ -match $keyLinePattern } | Select-Object -Unique -First 40)
    Write-Host "Failed steps:`n  $($failedSteps -join "`n  ")"

    # Runner or network trouble: one rerun, and nothing else, since the code may be fine.
    $transient = [bool]($log -match $transientPattern)
    $repairable = $state.wantsFormat -or $state.wantsLints -or $state.wantsAudit
    if ($state.action -eq 'repair' -and $transient -and $run.attempt -eq 1 -and -not $repairable) {
        Write-Host 'The log points at the runner or the network; the failed jobs will be rerun once.'
        $state.action = 'rerun'
    }
    Save-State $state
}

function Invoke-Repair {
    if (-not $WorkTree) { throw '-WorkTree is required to repair a run.' }
    $state = Read-State
    if ($state.action -ne 'repair') { return }

    $repaired = New-Object System.Collections.Generic.List[string]
    $unrepaired = New-Object System.Collections.Generic.List[string]
    Push-Location -LiteralPath $WorkTree
    try {
        if ($state.wantsFormat) {
            [void](Invoke-Native cargo @('fmt', '--all'))
            if ((Invoke-Native cargo @('fmt', '--all', '--', '--check')) -eq 0) { $repaired.Add('formatting (`cargo fmt`)') }
            else { $unrepaired.Add('formatting that `cargo fmt` could not settle') }
        }
        if ($state.wantsLints) {
            [void](Invoke-Native cargo @('clippy', '--fix', '--workspace', '--all-targets', '--allow-dirty', '--allow-staged'))
            [void](Invoke-Native cargo @('fmt', '--all'))
            if ((Invoke-Native cargo @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')) -eq 0) {
                $repaired.Add('lints with a machine-applicable fix (`cargo clippy --fix`)')
            }
            elseif ($state.compileError) { $unrepaired.Add('the code does not compile (errors below); `clippy --fix` cannot repair that') }
            else { $unrepaired.Add('clippy lints with no machine-applicable fix') }
        }
        if ($state.wantsAudit) {
            $audit = (Read-Native cargo @('audit', '--json') | Out-String) | ConvertFrom-Json
            $updated = @()
            foreach ($finding in $audit.vulnerabilities.list) {
                if (@($finding.versions.patched).Count -gt 0) {
                    $package = "$($finding.package.name)@$($finding.package.version)"
                    # Stays within the semver range the manifests allow; a fix that needs a major
                    # upgrade of whatever depends on the crate is left for a person.
                    if ((Invoke-Native cargo @('update', '-p', $package)) -eq 0) { $updated += $package }
                }
            }
            $remaining = (Read-Native cargo @('audit', '--json') | Out-String) | ConvertFrom-Json
            if ($updated -and $remaining.vulnerabilities.count -lt $audit.vulnerabilities.count) {
                $repaired.Add("vulnerable dependencies updated to fixed releases: $($updated -join ', ')")
            }
            elseif ($updated) {
                # Moved within the same vulnerable range; not worth a lockfile change of its own.
                git checkout -- Cargo.lock
            }
            foreach ($finding in $remaining.vulnerabilities.list) {
                $patched = @($finding.versions.patched) -join ', '
                if (-not $patched) { $patched = 'none yet' }
                $unrepaired.Add("$($finding.advisory.id) in $($finding.package.name) $($finding.package.version) " +
                    "has no fixed release this lockfile can take (patched: $patched). Upgrade whatever pins it, " +
                    'or record in `.cargo/audit.toml` why blackshard is not exposed.')
            }
        }

        # git writes the patch itself; a PowerShell redirect would re-encode it.
        Remove-Item -LiteralPath $patchPath -ErrorAction SilentlyContinue
        if ($repaired.Count -gt 0 -and (git status --porcelain)) {
            git diff --binary "--output=$patchPath"
        }
    }
    finally {
        Pop-Location
    }

    $state.repaired = @($repaired)
    $state.unrepaired = @($unrepaired)
    Save-State $state
}

# The patch was made where build scripts from the failed commit ran, so it is checked rather than
# trusted: only the files a mechanical repair produces may change.
function Assert-RepairablePatch {
    $paths = @(git apply --numstat $patchPath | ForEach-Object { ($_ -split "`t", 3)[2] })
    if ($LASTEXITCODE -ne 0) { throw 'repair.patch does not apply to the failed commit.' }
    $refused = @($paths | Where-Object { $_ -notmatch $repairablePath -or $_ -match ' => ' })
    if ($refused) { throw "repair.patch touches files a mechanical repair never changes: $($refused -join ', ')" }
}

function Invoke-Apply {
    $state = Read-State
    switch ($state.action) {
        'skip' { return }
        'rerun' {
            if (-not $DryRun) { gh run rerun $state.runId --failed }
            return
        }
    }

    $pullRequestUrl = $null
    if (@($state.repaired).Count -gt 0 -and (Test-Path -LiteralPath $patchPath)) {
        if (-not $WorkTree) { throw '-WorkTree is required to apply a repair.' }
        $summary = @($state.repaired) -join '; '
        Write-Host "Repaired: $summary"
        Push-Location -LiteralPath $WorkTree
        try {
            # Run by hand, Repair already left its changes in this work tree.
            if (-not (git status --porcelain)) {
                Assert-RepairablePatch
                git apply $patchPath
                if ($LASTEXITCODE -ne 0) { throw 'repair.patch could not be applied.' }
            }
            if (-not $DryRun) {
                git switch -c $state.fixBranch
                git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' `
                    commit -am "ci: repair $($state.workflowName) on $($state.branch)" -m "Automatic repair of $($state.url): $summary."
                git push --force origin $state.fixBranch
                $body = "Automatic repair of [$($state.workflowName) run $($state.runId)]($($state.url)) on ``$($state.branch)``.`n`n" +
                    ((@($state.repaired) | ForEach-Object { "- $_" }) -join "`n") +
                    "`n`nA security-ci run was started on this branch to check it. Review and merge as usual."
                # A repair already under review is brought up to date rather than proposed twice.
                $pullRequestUrl = gh pr list --head $state.fixBranch --state open --json url --jq '.[0].url'
                if (-not $pullRequestUrl) {
                    $pullRequestUrl = gh pr create --base $state.branch --head $state.fixBranch --label ci-autofix `
                        --title "ci: repair $($state.workflowName) on $($state.branch)" --body $body
                }
                # A pull request opened with the workflow's token starts no CI by itself.
                gh workflow run security-ci --ref $state.fixBranch
            }
        }
        finally {
            Pop-Location
        }
    }

    $leftOver = @($state.otherSteps) + @($state.unrepaired)
    if ($leftOver.Count -eq 0) { return }

    $report = @(
        "**$($state.workflowName) failed** on ``$($state.branch)`` at $($state.headSha.Substring(0, 7)): [run $($state.runId)]($($state.url))"
        ''
        'Failed steps:'
        (@($state.failedSteps) | ForEach-Object { "- $_" })
    )
    if ($pullRequestUrl) { $report += @('', "Repaired automatically in $pullRequestUrl.") }
    $report += @('', 'Needs a person:')
    $report += $leftOver | ForEach-Object { "- $_" }
    $keyLines = @($state.keyLines)
    if ($keyLines) {
        $report += @('', '<details open><summary>Error lines from the log</summary>', '', '```') + $keyLines + @('```', '</details>')
    }
    $report = $report -join "`n"

    if ($DryRun) {
        Write-Host "`n----- report -----`n$report"
        return
    }
    if ($PullRequest) {
        gh pr comment $PullRequest --body $report --edit-last --create-if-none
    }
    else {
        $title = "CI failing on $($state.branch): $($state.workflowName)"
        $existing = gh issue list --label ci-autofix --state open --search "in:title `"$title`"" --json number,title |
            ConvertFrom-Json | Where-Object title -eq $title | Select-Object -First 1
        # Edited rather than commented on, so a failure that persists night after night stays one quiet issue.
        if ($existing) { gh issue edit $existing.number --body $report }
        else { gh issue create --label ci-autofix --title $title --body $report }
    }
}

if (-not $Mode -or $Mode -eq 'Collect') { Invoke-Collect }
if (-not $Mode -or $Mode -eq 'Repair') { Invoke-Repair }
if (-not $Mode -or $Mode -eq 'Apply') { Invoke-Apply }
# Every real failure above throws. Without this, the exit code of whichever native tool ran last
# (a cargo check that found the problem being repaired, a gh lookup that came back empty) would
# become the step's result.
exit 0
