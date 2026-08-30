@echo off
echo --- text (parens) ---
for %%D in (C) do (
    echo text (parens)
    echo --- text ^(parens^) ---
    echo --- text "(parens)" ---
    rem echo --- text (parens) ---
)
if 1==1 (
    echo ok (parens)
) else (
    echo no
)
for %%A in (1) do (
    for %%D in (C) do (
        echo ok
    )
)
echo END-OK
exit /b 0
