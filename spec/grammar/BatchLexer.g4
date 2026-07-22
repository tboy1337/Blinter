lexer grammar BatchLexer;

// --- DEFAULT mode ---
fragment IDENT : [a-zA-Z_][a-zA-Z0-9_]* ;
fragment DIGIT : [0-9] ;

LINE_COMMENT   : '::' ~[\r\n]* -> skip ;
REM            : [rR][eE][mM] ~[\r\n]* -> skip ;

LABEL          : {self._tokenStartColumn == 0}? ':' ~[ \t\r\n(][^\r\n]* ;

FOR            : [fF][oO][rR] ;
IF             : [iI][fF] ;
CALL           : [cC][aA][lL][lL] ;
GOTO           : [gG][oO][tT][oO] ;
SET            : [sS][eE][tT] ;
SETLOCAL       : [sS][eE][tT][lL][oO][cC][aA][lL] ;
ENDLOCAL       : [eE][nN][dD][lL][oO][cC][aA][lL] ;
DO             : [dD][oO] ;
IN             : [iI][nN] ;
EXIST          : [eE][xX][iI][sS][tT] ;
DEFINED        : [dD][eE][fF][iI][nN][eE][dD] ;
NOT            : [nN][oO][tT] ;
ERRORLEVEL     : [eE][rR][rR][oO][rR][lL][eE][vV][eE][lL] ;
ELSE           : [eE][lL][sS][eE] ;
EXIT           : [eE][xX][iI][tT] ;
SHIFT          : [sS][hH][iI][fF][tT] ;
EOF_KW         : 'EOF' ;

LPAREN         : '(' ;
RPAREN         : ')' ;
AMP            : '&' ;
PIPE           : '|' ;
AMPAMP         : '&&' ;
PIPEPIPE       : '||' ;
GT             : '>' ;
LT             : '<' ;
GE             : '>=' ;
LE             : '<=' ;
EQ             : '==' ;
COLON          : ':' ;
SET_A          : '/A' ;
SLASH          : '/' ;
EQUALS         : '=' ;
COMMA          : ',' ;
DOT            : '.' ;
BACKSLASH      : '\\' ;
PLUS           : '+' ;
MINUS          : '-' ;

EQU            : 'EQU' ;
NEQ            : 'NEQ' ;
LSS            : 'LSS' ;
LEQ            : 'LEQ' ;
GTR            : 'GTR' ;
GEQ            : 'GEQ' ;
CARET          : '^' ;
PERCENT        : '%' ;
ASTERISK         : '*' ;

DQ_STRING
    : '"' ( '\\' . | '""' | ~["\\])* '"'
    ;

SQ_STRING
    : '\'' (~'\'' | '\'\'')* '\''
    ;

PERCENT_TILDE
    : '%' '~' [a-zA-Z$]+ [0-9a-zA-Z] '%'
    ;

PERCENT_VAR_SUBSTRING
    : '%' [a-zA-Z_][a-zA-Z0-9_]* ':' '~' DIGIT+ ',' DIGIT* '%'
    ;

PERCENT_VAR_REPLACE
    : '%' [a-zA-Z_][a-zA-Z0-9_]* ':' (~'%' | '%%')+ '=' (~'%' | '%%')* '%'
    ;

PERCENT_VAR
    : '%' [a-zA-Z_][a-zA-Z0-9_]* '%'
    ;

PERCENT_NUM
    : '%' DIGIT '%'
    ;

FOR_VAR
    : '%%' [a-zA-Z]
    ;

FOR_VAR_TILDE
    : '%%' '~' [a-zA-Z$]+ [a-zA-Z]?
    ;

BANG_VAR
    : '!' [a-zA-Z_][a-zA-Z0-9_]* '!'
    ;

WORD           : [a-zA-Z_][a-zA-Z0-9_./\\:+\-]* ;
NUMBER         : DIGIT+ ;

WS             : [ \t]+ -> skip ;
NEWLINE        : [\r\n]+ ;

UNMATCHED_DQ
    : '"' ~[\r\n]*
    ;
