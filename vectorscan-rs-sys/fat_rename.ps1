# Windows/COFF fat-runtime symbol renamer (whole-variant pass).
#
# Usage: fat_rename.ps1 <prefix> <keepsyms_file> <object_dir>
#
# build.rs copies this into the vectorscan source tree's cmake/ dir for MSVC
# fat-runtime builds; the patched CMakeLists.txt (msvc-support.patch) runs it
# once per micro-arch variant via `powershell -File`. This is a PowerShell port
# of the former fat_rename.py, so MSVC builds need no Python on PATH.
#
# The upstream POSIX build_wrapper.sh renames symbols one object at a time,
# relying on a dump of libc's dynamic symbols to know what NOT to rename. That
# doesn't port to the MSVC toolchain (no libc.so to enumerate, no shell), and a
# per-object pass cannot rename a *reference* to a symbol defined in a sibling
# object. Instead we run once per variant after all its objects exist:
#   1. collect every external *defined* symbol across the variant's objects
#      -> these are exactly the symbols the variant owns;
#   2. apply that single rename map ("sym" -> "<prefix>_sym") to *every* object
#      with llvm-objcopy --redefine-syms, which rewrites both the definitions
#      and any (undefined) references to them.
# Symbols the variant does not define -- the CRT (memcpy, ...) and the shared
# allocator hooks in hs_exec_common -- are never in the map, so references to
# them are left intact and still resolve at link time.

$ErrorActionPreference = 'Stop'
$prefix   = $args[0]
$keepfile = $args[1]
$objdir   = $args[2]

# External, defined sections (uppercase == external). The membership test below
# is case-sensitive (-cnotcontains) so locals (t/d/b/r) are excluded, matching
# the Python set("TDBR").
$definedTypes = 'T', 'D', 'B', 'R'

# --- load keep-list: literal names vs regex patterns ---
$keepNames = [System.Collections.Generic.HashSet[string]]::new()
$keepPatterns = [System.Collections.Generic.List[regex]]::new()
foreach ($line in Get-Content -LiteralPath $keepfile) {
    $tok = $line.Trim()
    if (-not $tok -or $tok.StartsWith('#')) { continue }
    if ($tok -match '[\^$*\[\].]') {
        $keepPatterns.Add([regex]$tok)
    } else {
        [void]$keepNames.Add($tok)
    }
}

# --- collect every external defined symbol the variant owns ---
$objs = @(Get-ChildItem -LiteralPath $objdir -Recurse -Filter *.obj -File)
if ($objs.Count -eq 0) { exit 0 }

$owned = [System.Collections.Generic.HashSet[string]]::new()
foreach ($obj in $objs) {
    $nmOut = & llvm-nm $obj.FullName
    if ($LASTEXITCODE -ne 0) { Write-Error "llvm-nm failed on $($obj.FullName)"; exit $LASTEXITCODE }
    foreach ($line in $nmOut) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 3)     { $symType = $parts[1]; $name = $parts[2] }
        elseif ($parts.Count -eq 2) { $symType = $parts[0]; $name = $parts[1] }
        else { continue }
        if ($definedTypes -cnotcontains $symType) { continue }
        if ($name.StartsWith("${prefix}_")) { continue }   # already renamed (idempotent re-runs)
        if ($keepNames.Contains($name)) { continue }
        $keep = $false
        foreach ($p in $keepPatterns) { if ($p.IsMatch($name)) { $keep = $true; break } }
        if ($keep) { continue }
        [void]$owned.Add($name)
    }
}
if ($owned.Count -eq 0) { exit 0 }

# --- write the rename map and apply it to every object ---
$mapfile = Join-Path $objdir ("fat_rename_{0}.syms" -f $prefix)
# ASCII (no BOM): llvm-objcopy --redefine-syms cannot parse a UTF-16/BOM file,
# which is what Set-Content writes by default on Windows PowerShell.
($owned | Sort-Object | ForEach-Object { "$_ ${prefix}_$_" }) |
    Set-Content -LiteralPath $mapfile -Encoding ascii
try {
    foreach ($obj in $objs) {
        & llvm-objcopy "--redefine-syms=$mapfile" $obj.FullName
        if ($LASTEXITCODE -ne 0) { Write-Error "llvm-objcopy failed on $($obj.FullName)"; exit $LASTEXITCODE }
    }
} finally {
    Remove-Item -LiteralPath $mapfile -ErrorAction SilentlyContinue
}
exit 0
