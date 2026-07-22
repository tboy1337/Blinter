# Batch Language Reference (SSOT Companion)

Authoritative references used to validate Blinter's batch language SSOT (`vendor/batch-spec`) and linter spec (`spec/`).

## Primary sources

| Source | Location | Use |
|--------|----------|-----|
| cmd.exe `CALL /?` | [vendor/batch-spec/audit/cmd-help/call-help.txt](../vendor/batch-spec/audit/cmd-help/call-help.txt) | `%~` modifier syntax |
| cmd.exe `FOR /?` | [vendor/batch-spec/audit/cmd-help/for-help.txt](../vendor/batch-spec/audit/cmd-help/for-help.txt) | `FOR %%i IN (set) DO` |
| cmd.exe `IF /?` | [vendor/batch-spec/audit/cmd-help/if-help.txt](../vendor/batch-spec/audit/cmd-help/if-help.txt) | IF forms, ERRORLEVEL |
| cmd.exe `SET /?` | [vendor/batch-spec/audit/cmd-help/set-help.txt](../vendor/batch-spec/audit/cmd-help/set-help.txt) | SET syntax, spacing |
| cmd.exe `SETLOCAL /?` | [vendor/batch-spec/audit/cmd-help/setlocal-help.txt](../vendor/batch-spec/audit/cmd-help/setlocal-help.txt) | Scope, delayed expansion |
| cmd.exe `GOTO /?` | [vendor/batch-spec/audit/cmd-help/goto-help.txt](../vendor/batch-spec/audit/cmd-help/goto-help.txt) | Labels, `:EOF` |
| cmd.exe `SETX /?` | [vendor/batch-spec/audit/cmd-help/setx-help.txt](../vendor/batch-spec/audit/cmd-help/setx-help.txt) | SETX space-delimited syntax |
| cmd.exe `REN /?` | [vendor/batch-spec/audit/cmd-help/ren-help.txt](../vendor/batch-spec/audit/cmd-help/ren-help.txt) | REN destination filename-only |
| cmd.exe `CD /?` | [vendor/batch-spec/audit/cmd-help/cd-help.txt](../vendor/batch-spec/audit/cmd-help/cd-help.txt) | `/D` switch, drive vs directory |
| cmd.exe `PUSHD /?` | [vendor/batch-spec/audit/cmd-help/pushd-help.txt](../vendor/batch-spec/audit/cmd-help/pushd-help.txt) | Directory stack, UNC mapping |
| cmd.exe `POPD /?` | [vendor/batch-spec/audit/cmd-help/popd-help.txt](../vendor/batch-spec/audit/cmd-help/popd-help.txt) | Restore pushed directory |
| cmd.exe `MOVE /?` | [vendor/batch-spec/audit/cmd-help/move-help.txt](../vendor/batch-spec/audit/cmd-help/move-help.txt) | MOVE vs REN semantics |
| cmd.exe `SUBST /?` | [vendor/batch-spec/audit/cmd-help/subst-help.txt](../vendor/batch-spec/audit/cmd-help/subst-help.txt) | Virtual drive mapping |
| cmd.exe `EXIT /?` | [vendor/batch-spec/audit/cmd-help/exit-help.txt](../vendor/batch-spec/audit/cmd-help/exit-help.txt) | `EXIT /B`, exit codes |
| cmd.exe `SHIFT /?` | [vendor/batch-spec/audit/cmd-help/shift-help.txt](../vendor/batch-spec/audit/cmd-help/shift-help.txt) | Batch parameters |
| cmd.exe `CHOICE /?` | [vendor/batch-spec/audit/cmd-help/choice-help.txt](../vendor/batch-spec/audit/cmd-help/choice-help.txt) | Interactive menu selections, ERRORLEVEL index |
| Microsoft Learn | [if](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/if), [for](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/for), [setlocal](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setlocal), [set](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/set) | Behavioral semantics |
| SS64 | [IF](https://ss64.com/nt/if.html), [Errorlevel](https://ss64.com/nt/errorlevel.html), [Delayed expansion](https://ss64.com/nt/delayedexpansion.html) | ERRORLEVEL `>= n` vs `%ERRORLEVEL%`, delayed expansion |

## Conflict resolution

1. cmd.exe `/help` output wins for syntax
2. Microsoft Learn for behavioral semantics
3. SS64 for community-documented edge cases when cmd help is silent
4. Document conflicts in this file

## Documented conflicts / notes

### E006 and SEC006 legacy IDs

- **E006** uses an `E` prefix with `WARNING` severity (intentional; do not renumber).
- **SEC006** uses a `SEC` prefix with `STYLE` severity (portability, not security).

### WMIC builtin vs deprecated

`wmic` appears in `commands.yaml` `builtin_commands` (recognition) and `deprecated_commands` (W024). See `builtin_overlap_deprecated_notes`.

### FOR `IN` list parentheses

Microsoft Learn requires parentheses around the `IN` set in batch files. The ANTLR grammar enforces `IN '(' forList ')'`.

### Delayed expansion

`!VAR!` is only active after `SETLOCAL EnableDelayedExpansion` (see MS Learn `setlocal` and SS64 delayed expansion). Blinter flags missing enablement via P008/W022.

### IF EXISTS typo (E036)

cmd.exe accepts `IF EXIST` and `IF NOT EXIST`, not `IF EXISTS` (MS Learn `if`; oracle-confirmed). The trailing `S` causes a runtime syntax error. **E036** flags `IF EXISTS` and `IF NOT EXISTS`.

### String substring on empty variable (W047)

When a variable is unset or explicitly assigned empty (`SET var=`), substring expansion such as `%var:~-1%` or `%var:~0,1%` resolves to the literal text `~-1` or `~0,1` rather than an empty string (oracle-confirmed). **W047** flags substring syntax on undefined or empty-assigned variables.

### SET spacing (W044)

`SET X = value` creates a variable named `X ` (trailing space). Blinter warns via **W044**. `SET /A` is exempt: spaces around `=` are valid for arithmetic assignment.

### Pseudo-environment assignment (W049)

cmd.exe maintains dynamic pseudo-environment variables (`ERRORLEVEL`, `RANDOM`, `CD`, `DATE`, `TIME`, `CMDCMDLINE`, `CMDEXTVERSION`, `HIGHESTNUMANODENUMBER`) per `SET /?`. Assigning with `SET` or `SET /A` shadows the dynamic value and breaks expected runtime semantics. **W049** flags these assignments. Clearing a mistakenly created shadow variable with `SET "errorlevel="` is intentional recovery and is not flagged. Reading pseudo-env names in `SET /A` expressions (for example `set /a seed=%random%`) is valid; only the assignment target is checked. Variables such as `DIRCMD` and `PATHEXT` are normal environment variables (not listed in `SET /?` dynamic vars) and are not flagged by **W049**.

### SHIFT /n valid range (W050)

`SHIFT /?` states that `/n` must be between 0 and 8. Values above 8 fail at runtime with ERRORLEVEL 1. **W050** flags invalid switch values statically.

### Double-digit batch parameters (W051)

cmd.exe only supports `%0` through `%9`. References like `%10` parse as `%1` followed by a literal `0`, not the tenth argument. **W051** flags two-or-more-digit parameter references. Substring syntax such as `%PATH:~10,5%` is not affected. FOR loop variables (`%%i`) are not batch parameters and are not flagged.

### SHIFT inside parenthesized blocks (W052)

`SHIFT` inside a parenthesized command block does not change `%1`–`%9` expansion for lines inside that block; parameters shift only after the block finishes. Oracle-confirmed against cmd.exe. **W052** flags `SHIFT` at positive parenthesis depth.

### Bare SHIFT and %0 (W053)

Bare `SHIFT` (without `/n`) copies `%1` into `%0`, replacing the script name with the first argument. **W053** recommends `SHIFT /1` when `%0` must remain the script path. `SHIFT /n` with n between 0 and 8 is not flagged.

### Digit-prefixed variable names (W054)

cmd.exe cannot resolve `%digitName%` as a variable: `%1var%` expands as batch parameter `%1` plus literal `var`. Variable names starting with a digit require delayed expansion (`!1var!`) or should be renamed. **W054** flags `SET` assignments to digit-prefixed names and ambiguous `%digitLetter...%` expansions. Oracle-confirmed against cmd.exe.

### SET /A octal literals (W045)

Leading zeros in `SET /A` denote octal per cmd.exe arithmetic rules. **W045** flags literals like `010`.

### SET /A floating-point precision (documented only)

`SET /A` uses 32-bit integer arithmetic for most operations; floating-point expressions are limited in precision and rounding. Scripts that assume exact decimal cents from chained `SET /A` divisions can drift. No static rule is applied because valid use cases vary; prefer integer cents or external tools for money math.

### %TIME% leading space (documented only)

The dynamic `%TIME%` value includes a leading space before 10:00 AM (oracle-confirmed). Substring expansion such as `%TIME:~0,2%` therefore yields a leading space in the morning hours unless trimmed (for example `set "hour=%time: =0%"` before substringing). **W044** covers `SET` spacing around `=`; it does not flag `%TIME%` expansion usage. No static rule is applied because the value is time-of-day dependent.

### Smart quotes (E035)

Unicode curly quotes from word processors are not valid batch delimiters. **E035** flags U+201C/U+201D and related characters.

### SETLOCAL nesting (P027)

cmd.exe allows at most **32** nested `SETLOCAL` scopes. **P027** flags static nesting above that limit.

### Percent-tilde parameters (E017/E019/E024)

`%~` modifiers must use characters from CALL `/?` (`fdpnxsatz$`). Parameters must be `%0`–`%9`, a single FOR letter, or `%~$PATH:1` path-search form. Multi-letter names like `%~nUNDEFINED%` are **E019**.

### IF ERRORLEVEL semantics

`IF ERRORLEVEL n` is true when the previous exit code is **greater than or equal to** n. This differs from `IF %ERRORLEVEL% NEQ n` (W017).

`IF NOT ERRORLEVEL 0` is equivalent to `IF %ERRORLEVEL% LSS 0` — it matches **only negative** exit codes, not general failure. Coders often misread it as "exit code is not zero". **W017** flags this pattern. Use `IF %ERRORLEVEL% NEQ 0` or `IF NOT ERRORLEVEL 1` (success check) instead.

`IF %ERRORLEVEL% NEQ 1` matches any value except 1 (0, 2, 3, …), while `IF NOT ERRORLEVEL 1` matches only values less than 1 (i.e., 0). **W017** also flags the `NEQ 1` form when used as a traditional failure check.

### Non-zero success exit codes (robocopy and similar)

Some commands use exit codes greater than zero to indicate partial success (for example `robocopy` returns 1+ when files were copied). `IF ERRORLEVEL 1` treats those as success per `>=` semantics, while `IF %ERRORLEVEL% EQU 0` does not. Use **W017** guidance when mixing forms.

### DIR /B for processed output (P010/P013)

`DIR` has no `/F` switch. When piping or redirecting `DIR` output, `/B` produces bare filenames suitable for parsing (**P010**, **P013**).

### PUSHD/POPD balance (W061)

`PUSHD` stores the current directory on a stack and changes to a new path; `POPD` restores the most recent pushed directory per [PUSHD /?](../vendor/batch-spec/audit/cmd-help/pushd-help.txt) and [POPD /?](../vendor/batch-spec/audit/cmd-help/popd-help.txt). When `PUSHD` maps a network path, cmd.exe allocates a temporary drive letter that `POPD` removes. Unmatched `PUSHD` calls can leave mapped drives allocated after the script exits. **W061** flags unbalanced `PUSHD`/`POPD` usage at file scope.

### CD /D cross-drive navigation (W062)

`CD` and `CHDIR` accept an optional `/D` switch per [CD /?](../vendor/batch-spec/audit/cmd-help/cd-help.txt). Without `/D`, `cd Z:\folder` from another drive changes the stored directory on `Z:` but does not switch the active drive; the script remains on the current drive (SS64; oracle-confirmed). `cd Z:` alone displays the current directory on `Z:` and is not flagged. **W062** flags `CD`/`CHDIR` lines with a drive-letter path that omit `/D`.

### SUBST virtual drives

`SUBST` maps a drive letter to a path per [SUBST /?](../vendor/batch-spec/audit/cmd-help/subst-help.txt). `SUBST drive: /D` removes a mapping. Static analysis cannot reliably pair `SUBST` with cleanup across all exit paths; document and review manually.

### FOR /F USEBACKQ (W034)

Quoted filenames or paths with spaces in `FOR /F IN (...)` require `usebackq` per `FOR /?`. Command-execution forms `` IN (`command`) `` also need `usebackq` when combined with other operands. The synonym `useback` is accepted by cmd.exe and is treated equivalently by Blinter.

### IF DEFINED variable name (W055)

`IF DEFINED` expects a bare environment variable name per `IF /?`, not `%var%`. `IF DEFINED %MYVAR%` checks whether a variable literally named `%MYVAR%` exists (almost always false). **W055** flags percent-wrapped names. Dynamic forms such as `IF DEFINED stk%~1` are valid and are not flagged.

### IF pseudo AND/OR operators (W056)

cmd.exe has no `AND` or `OR` operator in `IF` conditional clauses (oracle-confirmed). `IF %A% EQU 1 AND %B% EQU 2` fails at runtime because `AND` is treated as a command separator. Use nested `IF` statements instead: `IF %A% EQU 1 IF %B% EQU 2 ...`. **W056** flags pseudo `AND`/`OR` between conditions, including on `else if` lines. Quoted string literals such as `"ORANGE"` are not flagged. The dash-concatenation pattern `IF "%A%-%B%" EQU "A-B"` is valid and is not flagged.

### IF else if chains

`else if` is valid cmd.exe syntax for multi-branch conditionals (oracle-confirmed). Example: `IF %x%==1 (echo one) ELSE IF %x%==2 (echo two) ELSE (echo other)`. This is distinct from pseudo `AND`/`OR` inside a single `IF` clause (**W056**).

### Conditional execution (`&&` and `||`)

`&&` and `||` are command-separator operators for conditional execution, not `IF` clause operators (MS Learn command separators; oracle-confirmed). `command1 && command2` runs `command2` only when `command1` succeeds (ERRORLEVEL 0). `command1 || command2` runs `command2` only when `command1` fails. **W056** does not flag `&&`/`||` on non-`IF` lines. Corpus `conditional-exec-valid` is the negative control.

### FOR loop variable case sensitivity

Unlike environment variables, FOR loop variables are **case-sensitive** per `FOR /?`, MS Learn, and SS64: `%%i` and `%%I` are distinct variables (oracle-confirmed). Nested loops may legitimately use different cases when each `FOR` declares its own variable (corpus `for-case-distinct-valid`). **W059** flags references that differ only in case from the declared loop variable within the same scope (for example `FOR %%i` with `echo %%I`). Static analysis skips files over 2500 lines and uses regex on FOR headers/bodies (not full AST).

### SETX space-delimited syntax (W060)

`SETX` uses space-delimited syntax (`SETX var value`), not `SET`-style equals per [SETX /?](../vendor/batch-spec/audit/cmd-help/setx-help.txt) (oracle-confirmed). `SETX MYVAR=value` fails at runtime with invalid syntax. **W060** flags an equals sign in the variable-name token. Valid forms include `SETX MYVAR hello`, `SETX MYVAR /K regpath`, and remote forms with `/S` `/U` switches. **W008** separately warns on `SETX PATH` modifications.

### FOR /F delims= case sensitivity

The `delims=` character set in `FOR /F` is case-sensitive per cmd.exe. `delims=D` and `delims=d` are different delimiter sets. **W035** and **W048** encourage explicit delimiter options but do not enforce case choices.

### Wildcard `?` at end of file mask

In file masks, `?` usually matches exactly one character, but when one or more `?` wildcards appear at the end of a mask or immediately before a dot, cmd.exe also treats a null (empty) as a valid match. This is a runtime filesystem behavior; no static rule is applied.

### Short-filename (8.3) wildcard matching

cmd.exe compares file masks against both long and short (8.3) filenames. A mask such as `*.???` can match a file whose long extension has four characters if the short name satisfies the mask. This requires runtime filesystem inspection; no static rule is applied.

### robocopy /MOV vs /MOVE

`robocopy /MOV` moves files only (subdirectories copied); `robocopy /MOVE` moves files and subdirectories. Both are valid switches with different semantics; static analysis cannot infer intent. See **W017** for robocopy exit-code guidance with `IF ERRORLEVEL`.

### SET /P prompt input

`SET /P` assigns user input to a variable from the prompt string (oracle-confirmed). Pressing Enter without input leaves the variable undefined. User input with metacharacters can break parsing; **SEC014** flags unescaped input in dangerous contexts.

`SET /P` requires `variable=[promptString]` per `SET /?` (oracle-confirmed). A prompt-only quoted string such as `SET /P "Enter: "` causes a cmd.exe syntax error. **E041** flags missing variable assignment.

### xcopy interactive stdin hang

When `xcopy` prompts for file-or-directory confirmation (for example copying to a destination that does not exist without `/I`), it reads from stdin and can hang unattended scripts. Use `/I` or `/Y` switches as appropriate; no static rule is applied because intent is not inferable.

### findstr stderr on invalid file masks (documented only)

When `findstr` is given a file mask that matches no files, cmd.exe writes `FINDSTR: Cannot open <mask>` to stderr (oracle-confirmed). If stdout and stderr are merged into one trace file, that message interleaves with matches. Use `2>nul` only when suppressing expected misses, or validate masks with `DIR` first. No static rule is applied because mask validity is runtime/filesystem dependent.

### Recursion stack overflow (documented only)

Deep `CALL :label` recursion pushes frames onto cmd.exe's limited call stack. When allocation nears capacity, the interpreter aborts with a stack-overflow style error. Static analysis cannot reliably bound recursion depth across branches; document limits and prefer iterative designs or explicit depth counters for self-calling scripts.

### FOR /F eol= and ampersand in code blocks (documented only)

The `eol=` option accepts only a single character per `FOR /?` (**E037**). After trailing spaces, `&` works as a command separator outside blocks but behaves differently inside parenthesized code blocks; escaped `^&` can substitute for `eol=` in some block contexts. Oracle confirmation shows `for /f "eol=&"` parses and runs. No additional E-rule is applied beyond **E037**; block-context `&` semantics are documented for review only.

### BREAK command

`BREAK` is a DOS compatibility no-op under Windows (`BREAK /?`); it does not exit loops. Use `GOTO` to break out of loops instead. No syntax rule is required.

### FOR /R literal filenames (W038)

`FOR /R` with a literal filename such as `(readme.txt)` is valid cmd.exe syntax but behaves like a batveat: without a wildcard in the `IN` set, cmd.exe walks every subdirectory and appends the literal name (even when the file is absent). **W038** is a style hint to use wildcards when matching explicit names during recursion, not a syntax error.

### Batch file invocation without CALL (W057)

Invoking another `.bat` or `.cmd` file without `CALL` transfers control to the child script; lines after the invocation do not run when the child exits (oracle-confirmed). Use `CALL helper.bat` when the caller must continue. `START` spawns a separate process and is not flagged.

### CALL vs GOTO on invalid labels

When a label is not found, `GOTO :label` aborts the batch with an error message. `CALL :label` writes an error, sets `ERRORLEVEL` to 1, and **continues** execution unless the return code is checked. Static analysis cannot reliably detect missing labels at lint time; this is documented for review guidance only.

### REN destination path (W058)

`REN` and `RENAME` rename files in place; the second argument must be a new filename only, not a path per [REN /?](../vendor/batch-spec/audit/cmd-help/ren-help.txt) (cmd.exe reports a syntax error). Use `MOVE` to relocate files. **W058** flags path separators (including forward slashes), drive letters, or UNC-style paths in the destination argument.

### FOR /F eol= single character (E037)

The `eol=` option in `FOR /F` accepts only a single end-of-line character per `FOR /?` (batveat; oracle-confirmed). Values such as `eol=XY` cause a cmd.exe syntax error at parse time. **E037** flags multi-character `eol=` values. **W037** warns when comment lines may be parsed as data because `eol=` is omitted entirely.

### FOR /F skip= and tokens= suboptions (E038)

`FOR /F` `skip=` must be a positive integer (1 or greater) per `FOR /?` and oracle-confirmed behavior; `skip=0` and non-numeric values such as `skip=abc` cause cmd.exe syntax errors. The `tokens=` clause must use ascending numeric ranges; `tokens=5-2` fails at parse time. **E038** flags invalid `skip=` and `tokens=` suboptions.

### FOR /F loop variable beyond tokens= range (W063)

`FOR /F` assigns implicit loop variables in alphabetical order from the declared variable. References beyond the `tokens=` count resolve as literal percent text (for example `%%d` becomes `%d` when only `tokens=1-3` with `%%a` is declared, and `%%b` becomes `%b` with `tokens=*`). **W063** flags out-of-range loop variable references in same-line and multiline `DO` bodies.

### IF block parenthesis placement (E039)

The open parenthesis of an `IF` block must appear on the same line as the `IF` condition (oracle-confirmed). Placing `(` on the following line causes a cmd.exe syntax error. **E039** flags this pattern.

### FOR block parenthesis placement (E040)

The open parenthesis of a `FOR` block must appear on the same line as the `DO` keyword (oracle-confirmed). Placing `(` on the following line causes a cmd.exe syntax error. **E040** flags this pattern for all `FOR` forms including `FOR /F`.

### SET /P missing variable assignment (E041)

`SET /P` requires `variable=[promptString]` per `SET /?` (oracle-confirmed). Forms such as `SET /P "Enter name: "` without a variable name before `=` cause a cmd.exe syntax error. **E041** flags missing variable assignment. Valid forms include `SET /P var=Prompt` and `SET /P "var=Prompt text"`. Reading from a file with `SET /P var=<%file` is valid syntax; no additional rule is applied.

### CHOICE command semantics

`CHOICE` maps selections to `ERRORLEVEL` indices (1-based) per [CHOICE /?](../vendor/batch-spec/audit/cmd-help/choice-help.txt). Empty `/C` lists and missing valid choices return ERRORLEVEL 255 at runtime (`ERROR: List of choices cannot be empty` or `The file is either empty or does not contain the valid choices`); these are runtime errors, not parse-time syntax failures. Default choices require both `/T` and `/D`. Blinter flags CHOICE only when used as an inefficient delay substitute (**P007**); no E-rule is applied for CHOICE syntax.

### ELSE / ELSE IF parenthesis placement

Sandwiching `ELSE` between closing and opening parentheses on one line improves readability. Oracle confirmation shows `ELSE` alone on its own line is **not** a parse-time syntax error (cmd.exe treats it as a command and continues). `ELSE IF` with the open parenthesis on the next line also runs successfully. No E-rule is applied; use **E039**/**E040** guidance for `IF`/`FOR` blocks only.

### Caret escape and exclamation marks

The caret escape character does not escape `%` or `!` reliably. Double carets before `!` (`^^!`) resolve differently from other doubled carets (`^^2` → `^2`) per cmd.exe parsing (meta-batveat). **E030–E033** cover continuation and multilevel caret issues.

### AST-first pipeline (2026-07-21)

All rules use the unified visitor pipeline (`lint_via_ast`). Grammar-backed rules (those with `grammar_nodes` in `rules.yaml`) are checked in production by the fast line scanner in `fast_syntax.py` (codes generated in `grammar_rules.py`); ANTLR parity is available via `check_ast_syntax_rules_antlr()`. Security, performance, and style rules use AST-aware heuristic visitors on command nodes.

### Opinion vs language rules

Style rules (**S001**, **S002**, **S022**, etc.) encode community conventions, not cmd.exe syntax requirements. Security and performance rules (**SEC***, **P***) mix language facts with best-practice heuristics; see `spec/audit/reference-matrix.yaml` for construct mappings.

## SSOT cross-reference

See [spec/audit/reference-matrix.yaml](../spec/audit/reference-matrix.yaml) for construct-to-corpus mappings.
