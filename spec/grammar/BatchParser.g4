parser grammar BatchParser;

options { tokenVocab = BatchLexer; }

script
    : line* EOF
    ;

line
    : label
    | commandLine
    | NEWLINE
    ;

label
    : LABEL NEWLINE?
    ;

commandLine
    : statement ( (AMP | PIPE | AMPAMP | PIPEPIPE) statement )* NEWLINE?
    ;

statement
    : ifStmt
    | forStmt
    | callStmt
    | gotoStmt
    | setStmt
    | setlocalStmt
    | endlocalStmt
    | exitStmt
    | shiftStmt
    | genericCmd
    ;

exitStmt
    : EXIT exitTail?
    ;

exitTail
    : SLASH WORD
    | NUMBER
    | token+
    ;

shiftStmt
    : SHIFT token*
    ;

ifStmt
    : IF ifTail
    ;

ifTail
    : ifPredicate commandTail?
    | ifBlockStmt
    ;

ifErrorlevelStmt
    : ERRORLEVEL NUMBER
    ;

ifExistOperand
    : DQ_STRING
    | WORD
    | PERCENT_VAR
    ;

ifBlockStmt
    : ifPredicate LPAREN block RPAREN (ELSE LPAREN block RPAREN)?
    ;

ifPredicate
    : NOT? ifErrorlevelStmt
    | NOT? DEFINED WORD
    | NOT? EXIST ifExistOperand
    | comparison
    | DQ_STRING
    | PERCENT_VAR
    | WORD
    ;

comparison
    : compareOperand compareOp compareOperand
    ;

compareOp
    : EQ
    | EQU
    | NEQ
    | LSS
    | LEQ
    | GTR
    | GEQ
    | LT
    | GT
    | LE
    | GE
    ;

compareOperand
    : DQ_STRING
    | PERCENT_TILDE
    | PERCENT_VAR_SUBSTRING
    | PERCENT_VAR_REPLACE
    | PERCENT_VAR
    | PERCENT_NUM
    | WORD
    | NUMBER
    ;

forStmt
    : FOR forMod* FOR_VAR (FOR_VAR_TILDE)? IN LPAREN forList RPAREN DO (LPAREN block RPAREN | block | commandLine)
    ;

forMod
    : SLASH WORD
    ;

forList
    : forItem (forItem)*
    ;

forItem
    : SQ_STRING
    | DQ_STRING
    | PERCENT_VAR
    | WORD
    | NUMBER
    | ASTERISK
    ;

callStmt
    : CALL callTarget commandTail?
    ;

callTarget
    : COLON? EOF_KW
    | COLON? WORD
    | PERCENT_NUM
    | PERCENT_VAR
    | DQ_STRING
    ;

gotoStmt
    : GOTO callTarget commandTail?
    ;

setStmt
    : SET setTarget setOp setRest?
    ;

setlocalStmt
    : SETLOCAL setlocalRest?
    ;

setlocalRest
    : token+
    ;

endlocalStmt
    : ENDLOCAL commandTail?
    ;

setTarget
    : WORD
    | PERCENT_VAR
    | DQ_STRING
    ;

setOp
    : EQUALS
    | SET_A
    ;

setRest
    : token+
    ;

genericCmd
    : commandTail
    ;

commandTail
    : token+
    ;

token
    : DQ_STRING
    | SQ_STRING
    | PERCENT_TILDE
    | PERCENT_VAR_SUBSTRING
    | PERCENT_VAR_REPLACE
    | PERCENT_VAR
    | PERCENT_NUM
    | FOR_VAR
    | FOR_VAR_TILDE
    | BANG_VAR
    | CARET
    | LPAREN
    | RPAREN
    | GT
    | LT
    | AMP
    | PIPE
    | DOT
    | BACKSLASH
    | PLUS
    | MINUS
    | COMMA
    | SLASH
    | WORD
    | NUMBER
    | UNMATCHED_DQ
    ;

block
    : line*
    ;
