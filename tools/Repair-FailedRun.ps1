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

No AI and no secrets: the workflow's own token is all it uses.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [long]$RunId,
    # A checkout of the failed commit, where repairs are made.
    [Parameter(Mandatory = $true)]
    [string]$WorkTree,
    # The pull request the run belonged to, if any.
    [string]$PullRequest,
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

$run = gh run view $RunId --json headBranch,headSha,attempt,workflowName,url,jobs | ConvertFrom-Json
$branch = $run.headBranch
$fixBranch = 'autofix/' + ($branch -replace '[^A-Za-z0-9/_.-]', '-')

# A newer commit on the branch has its own run, and an open repair is already waiting for review.
$head = Read-Native gh @('api', "repos/{owner}/{repo}/branches/$branch", '--jq', '.commit.sha')
if ($head -and $head -ne $run.headSha) {
    Write-Host "$branch has moved past $($run.headSha); its newer run decides."
    if (-not $DryRun) { return }
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

$wantsFormat = [bool]($failedSteps -match 'cargo fmt')
$wantsLints = [bool]($failedSteps -match 'cargo clippy')
$wantsAudit = [bool]($failedSteps -match 'cargo audit')
$otherSteps = @($failedSteps | Where-Object { $_ -notmatch 'cargo fmt|cargo clippy|cargo audit' })
$transient = [bool]($log -match $transientPattern)

Write-Host "Failed steps:`n  $($failedSteps -join "`n  ")"

# Runner or network trouble: one rerun, and nothing else, since the code may be fine.
if ($transient -and $run.attempt -eq 1 -and -not ($wantsFormat -or $wantsLints -or $wantsAudit)) {
    Write-Host 'The log points at the runner or the network; rerunning the failed jobs once.'
    if (-not $DryRun) { gh run rerun $RunId --failed }
    return
}

$repaired = New-Object System.Collections.Generic.List[string]
$unrepaired = New-Object System.Collections.Generic.List[string]
Push-Location -LiteralPath $WorkTree
try {
    if ($wantsFormat) {
        [void](Invoke-Native cargo @('fmt', '--all'))
        if ((Invoke-Native cargo @('fmt', '--all', '--', '--check')) -eq 0) { $repaired.Add('formatting (`cargo fmt`)') }
        else { $unrepaired.Add('formatting that `cargo fmt` could not settle') }
    }
    if ($wantsLints) {
        [void](Invoke-Native cargo @('clippy', '--fix', '--workspace', '--all-targets', '--allow-dirty', '--allow-staged'))
        [void](Invoke-Native cargo @('fmt', '--all'))
        if ((Invoke-Native cargo @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')) -eq 0) {
            $repaired.Add('lints with a machine-applicable fix (`cargo clippy --fix`)')
        }
        elseif ($log -match '^error\[E\d+\]') { $unrepaired.Add('the code does not compile (errors below); `clippy --fix` cannot repair that') }
        else { $unrepaired.Add('clippy lints with no machine-applicable fix') }
    }
    if ($wantsAudit) {
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

    $pullRequestUrl = $null
    if ($repaired.Count -gt 0 -and (git status --porcelain)) {
        $summary = $repaired -join '; '
        Write-Host "Repaired: $summary"
        if (-not $DryRun) {
            git switch -c $fixBranch
            git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' `
                commit -am "ci: repair $($run.workflowName) on $branch" -m "Automatic repair of $($run.url): $summary."
            git push --force origin $fixBranch
            $body = "Automatic repair of [$($run.workflowName) run $RunId]($($run.url)) on ``$branch``.`n`n" +
                (($repaired | ForEach-Object { "- $_" }) -join "`n") +
                "`n`nA security-ci run was started on this branch to check it. Review and merge as usual."
            # A repair already under review is brought up to date rather than proposed twice.
            $pullRequestUrl = gh pr list --head $fixBranch --state open --json url --jq '.[0].url'
            if (-not $pullRequestUrl) {
                $pullRequestUrl = gh pr create --base $branch --head $fixBranch --label ci-autofix `
                    --title "ci: repair $($run.workflowName) on $branch" --body $body
            }
            # A pull request opened with the workflow's token starts no CI by itself.
            gh workflow run security-ci --ref $fixBranch
        }
    }
}
finally {
    Pop-Location
}

$leftOver = @($otherSteps) + @($unrepaired)
if ($leftOver.Count -eq 0) { return }

$keyLines = @($log | Where-Object { $_ -match $keyLinePattern } | Select-Object -Unique -First 40)
$report = @(
    "**$($run.workflowName) failed** on ``$branch`` at $($run.headSha.Substring(0, 7)): [run $RunId]($($run.url))"
    ''
    'Failed steps:'
    ($failedSteps | ForEach-Object { "- $_" })
)
if ($pullRequestUrl) { $report += @('', "Repaired automatically in $pullRequestUrl.") }
$report += @('', 'Needs a person:')
$report += $leftOver | ForEach-Object { "- $_" }
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
    $title = "CI failing on ${branch}: $($run.workflowName)"
    $existing = gh issue list --label ci-autofix --state open --search "in:title `"$title`"" --json number,title |
        ConvertFrom-Json | Where-Object title -eq $title | Select-Object -First 1
    # Edited rather than commented on, so a failure that persists night after night stays one quiet issue.
    if ($existing) { gh issue edit $existing.number --body $report }
    else { gh issue create --label ci-autofix --title $title --body $report }
}
