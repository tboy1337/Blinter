# SSOT Audit Report

## ERROR (0)

_None_

## WARNING (5)

- **[reference-matrix]** Nested parentheses and block structure: corpus syntax/e001-for-f-in-quoted-valid does not assert any of ['E001']
- **[reference-matrix]** Percent-tilde (%~) parameter expansion: corpus syntax/e019-set-a-percent-tilde-params-valid does not assert any of ['E017', 'E019', 'E024', 'E025', 'W051']
- **[reference-matrix]** Percent-tilde (%~) parameter expansion: corpus syntax/e019-for-loop-tilde-z-valid does not assert any of ['E017', 'E019', 'E024', 'E025', 'W051']
- **[reference-matrix]** Percent-tilde (%~) parameter expansion: corpus syntax/e019-percent-tilde-dp0-adjacent-valid does not assert any of ['E017', 'E019', 'E024', 'E025', 'W051']
- **[reference-matrix]** FOR /F tokenization, delimiters, and CSV: corpus syntax/e038-for-f-tokens-delims-valid does not assert any of ['E037', 'E038', 'W034', 'W035', 'W037', 'W048', 'W063']

## INFO (3)

- **[commands]** dpath is both builtin and deprecated (intentional for W024 recognition)
- **[commands]** keys is both builtin and deprecated (intentional for W024 recognition)
- **[commands]** wmic is both builtin and deprecated (intentional for W024 recognition)
