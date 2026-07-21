# Generated from C:/Users/Laptop/Documents/Git/Blinter/spec/grammar/BatchParser.g4 by ANTLR 4.13.2
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,60,322,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,2,32,7,32,2,33,
        7,33,2,34,7,34,1,0,5,0,72,8,0,10,0,12,0,75,9,0,1,0,1,0,1,1,1,1,1,
        1,3,1,82,8,1,1,2,1,2,3,2,86,8,2,1,3,1,3,1,3,1,3,1,3,1,3,5,3,94,8,
        3,10,3,12,3,97,9,3,1,3,3,3,100,8,3,1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,
        4,1,4,1,4,3,4,112,8,4,1,5,1,5,3,5,116,8,5,1,6,1,6,1,6,1,6,4,6,122,
        8,6,11,6,12,6,123,3,6,126,8,6,1,7,1,7,5,7,130,8,7,10,7,12,7,133,
        9,7,1,8,1,8,1,8,1,9,3,9,139,8,9,1,9,1,9,3,9,143,8,9,1,9,3,9,146,
        8,9,1,9,1,9,1,9,3,9,151,8,9,1,9,3,9,154,8,9,1,9,1,9,1,9,3,9,159,
        8,9,1,9,1,9,3,9,163,8,9,1,9,1,9,3,9,167,8,9,1,9,1,9,3,9,171,8,9,
        1,9,3,9,174,8,9,1,10,1,10,1,10,1,11,1,11,1,12,1,12,1,12,1,12,1,12,
        1,12,1,12,1,12,1,12,3,12,190,8,12,1,13,3,13,193,8,13,1,13,1,13,3,
        13,197,8,13,1,13,1,13,1,13,3,13,202,8,13,1,13,1,13,1,13,1,13,1,13,
        1,13,3,13,210,8,13,1,14,1,14,1,14,1,14,1,15,1,15,1,16,1,16,1,17,
        1,17,5,17,222,8,17,10,17,12,17,225,9,17,1,17,1,17,3,17,229,8,17,
        1,17,1,17,1,17,1,17,1,17,1,17,1,17,1,17,1,17,1,17,1,17,3,17,242,
        8,17,1,18,1,18,1,18,1,19,1,19,5,19,249,8,19,10,19,12,19,252,9,19,
        1,20,1,20,1,21,1,21,1,21,3,21,259,8,21,1,22,3,22,262,8,22,1,22,1,
        22,3,22,266,8,22,1,22,1,22,1,22,1,22,3,22,272,8,22,1,23,1,23,1,23,
        3,23,277,8,23,1,24,1,24,1,24,1,24,3,24,283,8,24,1,25,1,25,3,25,287,
        8,25,1,26,4,26,290,8,26,11,26,12,26,291,1,27,1,27,3,27,296,8,27,
        1,28,1,28,1,29,1,29,1,30,4,30,303,8,30,11,30,12,30,304,1,31,1,31,
        1,32,4,32,310,8,32,11,32,12,32,311,1,33,1,33,1,34,5,34,317,8,34,
        10,34,12,34,320,9,34,1,34,0,0,35,0,2,4,6,8,10,12,14,16,18,20,22,
        24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64,66,
        68,0,6,3,0,46,46,51,51,56,56,2,0,27,31,36,41,3,0,46,46,48,52,56,
        57,3,0,45,47,51,51,56,57,2,0,34,34,42,42,5,0,21,24,27,28,43,43,46,
        57,60,60,354,0,73,1,0,0,0,2,81,1,0,0,0,4,83,1,0,0,0,6,87,1,0,0,0,
        8,111,1,0,0,0,10,113,1,0,0,0,12,125,1,0,0,0,14,127,1,0,0,0,16,134,
        1,0,0,0,18,173,1,0,0,0,20,175,1,0,0,0,22,178,1,0,0,0,24,180,1,0,
        0,0,26,209,1,0,0,0,28,211,1,0,0,0,30,215,1,0,0,0,32,217,1,0,0,0,
        34,219,1,0,0,0,36,243,1,0,0,0,38,246,1,0,0,0,40,253,1,0,0,0,42,255,
        1,0,0,0,44,271,1,0,0,0,46,273,1,0,0,0,48,278,1,0,0,0,50,284,1,0,
        0,0,52,289,1,0,0,0,54,293,1,0,0,0,56,297,1,0,0,0,58,299,1,0,0,0,
        60,302,1,0,0,0,62,306,1,0,0,0,64,309,1,0,0,0,66,313,1,0,0,0,68,318,
        1,0,0,0,70,72,3,2,1,0,71,70,1,0,0,0,72,75,1,0,0,0,73,71,1,0,0,0,
        73,74,1,0,0,0,74,76,1,0,0,0,75,73,1,0,0,0,76,77,5,0,0,1,77,1,1,0,
        0,0,78,82,3,4,2,0,79,82,3,6,3,0,80,82,5,59,0,0,81,78,1,0,0,0,81,
        79,1,0,0,0,81,80,1,0,0,0,82,3,1,0,0,0,83,85,5,3,0,0,84,86,5,59,0,
        0,85,84,1,0,0,0,85,86,1,0,0,0,86,5,1,0,0,0,87,95,3,8,4,0,88,94,5,
        23,0,0,89,94,5,24,0,0,90,94,5,25,0,0,91,92,5,26,0,0,92,94,3,8,4,
        0,93,88,1,0,0,0,93,89,1,0,0,0,93,90,1,0,0,0,93,91,1,0,0,0,94,97,
        1,0,0,0,95,93,1,0,0,0,95,96,1,0,0,0,96,99,1,0,0,0,97,95,1,0,0,0,
        98,100,5,59,0,0,99,98,1,0,0,0,99,100,1,0,0,0,100,7,1,0,0,0,101,112,
        3,16,8,0,102,112,3,34,17,0,103,112,3,42,21,0,104,112,3,46,23,0,105,
        112,3,48,24,0,106,112,3,50,25,0,107,112,3,54,27,0,108,112,3,10,5,
        0,109,112,3,14,7,0,110,112,3,62,31,0,111,101,1,0,0,0,111,102,1,0,
        0,0,111,103,1,0,0,0,111,104,1,0,0,0,111,105,1,0,0,0,111,106,1,0,
        0,0,111,107,1,0,0,0,111,108,1,0,0,0,111,109,1,0,0,0,111,110,1,0,
        0,0,112,9,1,0,0,0,113,115,5,18,0,0,114,116,3,12,6,0,115,114,1,0,
        0,0,115,116,1,0,0,0,116,11,1,0,0,0,117,118,5,33,0,0,118,126,5,56,
        0,0,119,126,5,57,0,0,120,122,3,66,33,0,121,120,1,0,0,0,122,123,1,
        0,0,0,123,121,1,0,0,0,123,124,1,0,0,0,124,126,1,0,0,0,125,117,1,
        0,0,0,125,119,1,0,0,0,125,121,1,0,0,0,126,13,1,0,0,0,127,131,5,19,
        0,0,128,130,3,66,33,0,129,128,1,0,0,0,130,133,1,0,0,0,131,129,1,
        0,0,0,131,132,1,0,0,0,132,15,1,0,0,0,133,131,1,0,0,0,134,135,5,5,
        0,0,135,136,3,18,9,0,136,17,1,0,0,0,137,139,5,15,0,0,138,137,1,0,
        0,0,138,139,1,0,0,0,139,140,1,0,0,0,140,142,3,20,10,0,141,143,3,
        64,32,0,142,141,1,0,0,0,142,143,1,0,0,0,143,174,1,0,0,0,144,146,
        5,15,0,0,145,144,1,0,0,0,145,146,1,0,0,0,146,147,1,0,0,0,147,148,
        5,14,0,0,148,150,5,56,0,0,149,151,3,64,32,0,150,149,1,0,0,0,150,
        151,1,0,0,0,151,174,1,0,0,0,152,154,5,15,0,0,153,152,1,0,0,0,153,
        154,1,0,0,0,154,155,1,0,0,0,155,156,5,13,0,0,156,158,3,22,11,0,157,
        159,3,64,32,0,158,157,1,0,0,0,158,159,1,0,0,0,159,174,1,0,0,0,160,
        162,3,28,14,0,161,163,3,64,32,0,162,161,1,0,0,0,162,163,1,0,0,0,
        163,174,1,0,0,0,164,166,5,46,0,0,165,167,3,64,32,0,166,165,1,0,0,
        0,166,167,1,0,0,0,167,174,1,0,0,0,168,170,5,51,0,0,169,171,3,64,
        32,0,170,169,1,0,0,0,170,171,1,0,0,0,171,174,1,0,0,0,172,174,3,24,
        12,0,173,138,1,0,0,0,173,145,1,0,0,0,173,153,1,0,0,0,173,160,1,0,
        0,0,173,164,1,0,0,0,173,168,1,0,0,0,173,172,1,0,0,0,174,19,1,0,0,
        0,175,176,5,16,0,0,176,177,5,57,0,0,177,21,1,0,0,0,178,179,7,0,0,
        0,179,23,1,0,0,0,180,181,3,26,13,0,181,182,5,21,0,0,182,183,3,68,
        34,0,183,189,5,22,0,0,184,185,5,17,0,0,185,186,5,21,0,0,186,187,
        3,68,34,0,187,188,5,22,0,0,188,190,1,0,0,0,189,184,1,0,0,0,189,190,
        1,0,0,0,190,25,1,0,0,0,191,193,5,15,0,0,192,191,1,0,0,0,192,193,
        1,0,0,0,193,194,1,0,0,0,194,210,3,20,10,0,195,197,5,15,0,0,196,195,
        1,0,0,0,196,197,1,0,0,0,197,198,1,0,0,0,198,199,5,14,0,0,199,210,
        5,56,0,0,200,202,5,15,0,0,201,200,1,0,0,0,201,202,1,0,0,0,202,203,
        1,0,0,0,203,204,5,13,0,0,204,210,3,22,11,0,205,210,3,28,14,0,206,
        210,5,46,0,0,207,210,5,51,0,0,208,210,5,56,0,0,209,192,1,0,0,0,209,
        196,1,0,0,0,209,201,1,0,0,0,209,205,1,0,0,0,209,206,1,0,0,0,209,
        207,1,0,0,0,209,208,1,0,0,0,210,27,1,0,0,0,211,212,3,32,16,0,212,
        213,3,30,15,0,213,214,3,32,16,0,214,29,1,0,0,0,215,216,7,1,0,0,216,
        31,1,0,0,0,217,218,7,2,0,0,218,33,1,0,0,0,219,223,5,4,0,0,220,222,
        3,36,18,0,221,220,1,0,0,0,222,225,1,0,0,0,223,221,1,0,0,0,223,224,
        1,0,0,0,224,226,1,0,0,0,225,223,1,0,0,0,226,228,5,53,0,0,227,229,
        5,54,0,0,228,227,1,0,0,0,228,229,1,0,0,0,229,230,1,0,0,0,230,231,
        5,12,0,0,231,232,5,21,0,0,232,233,3,38,19,0,233,234,5,22,0,0,234,
        241,5,11,0,0,235,236,5,21,0,0,236,237,3,68,34,0,237,238,5,22,0,0,
        238,242,1,0,0,0,239,242,3,68,34,0,240,242,3,6,3,0,241,235,1,0,0,
        0,241,239,1,0,0,0,241,240,1,0,0,0,242,35,1,0,0,0,243,244,5,33,0,
        0,244,245,5,56,0,0,245,37,1,0,0,0,246,250,3,40,20,0,247,249,3,40,
        20,0,248,247,1,0,0,0,249,252,1,0,0,0,250,248,1,0,0,0,250,251,1,0,
        0,0,251,39,1,0,0,0,252,250,1,0,0,0,253,254,7,3,0,0,254,41,1,0,0,
        0,255,256,5,6,0,0,256,258,3,44,22,0,257,259,3,64,32,0,258,257,1,
        0,0,0,258,259,1,0,0,0,259,43,1,0,0,0,260,262,5,32,0,0,261,260,1,
        0,0,0,261,262,1,0,0,0,262,263,1,0,0,0,263,272,5,20,0,0,264,266,5,
        32,0,0,265,264,1,0,0,0,265,266,1,0,0,0,266,267,1,0,0,0,267,272,5,
        56,0,0,268,272,5,52,0,0,269,272,5,51,0,0,270,272,5,46,0,0,271,261,
        1,0,0,0,271,265,1,0,0,0,271,268,1,0,0,0,271,269,1,0,0,0,271,270,
        1,0,0,0,272,45,1,0,0,0,273,274,5,7,0,0,274,276,3,44,22,0,275,277,
        3,64,32,0,276,275,1,0,0,0,276,277,1,0,0,0,277,47,1,0,0,0,278,279,
        5,8,0,0,279,280,3,56,28,0,280,282,3,58,29,0,281,283,3,60,30,0,282,
        281,1,0,0,0,282,283,1,0,0,0,283,49,1,0,0,0,284,286,5,9,0,0,285,287,
        3,52,26,0,286,285,1,0,0,0,286,287,1,0,0,0,287,51,1,0,0,0,288,290,
        3,66,33,0,289,288,1,0,0,0,290,291,1,0,0,0,291,289,1,0,0,0,291,292,
        1,0,0,0,292,53,1,0,0,0,293,295,5,10,0,0,294,296,3,64,32,0,295,294,
        1,0,0,0,295,296,1,0,0,0,296,55,1,0,0,0,297,298,7,0,0,0,298,57,1,
        0,0,0,299,300,7,4,0,0,300,59,1,0,0,0,301,303,3,66,33,0,302,301,1,
        0,0,0,303,304,1,0,0,0,304,302,1,0,0,0,304,305,1,0,0,0,305,61,1,0,
        0,0,306,307,3,64,32,0,307,63,1,0,0,0,308,310,3,66,33,0,309,308,1,
        0,0,0,310,311,1,0,0,0,311,309,1,0,0,0,311,312,1,0,0,0,312,65,1,0,
        0,0,313,314,7,5,0,0,314,67,1,0,0,0,315,317,3,2,1,0,316,315,1,0,0,
        0,317,320,1,0,0,0,318,316,1,0,0,0,318,319,1,0,0,0,319,69,1,0,0,0,
        320,318,1,0,0,0,42,73,81,85,93,95,99,111,115,123,125,131,138,142,
        145,150,153,158,162,166,170,173,189,192,196,201,209,223,228,241,
        250,258,261,265,271,276,282,286,291,295,304,311,318
    ]

class BatchParser ( Parser ):

    grammarFileName = "BatchParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "'EOF'", "'('", "')'", "'&'", "'|'", "'&&'", "'||'",
                     "'>'", "'<'", "'>='", "'<='", "'=='", "':'", "'/'",
                     "'='", "','", "'EQU'", "'NEQ'", "'LSS'", "'LEQ'", "'GTR'",
                     "'GEQ'", "'/A'", "'^'", "'%'", "'*'" ]

    symbolicNames = [ "<INVALID>", "LINE_COMMENT", "REM", "LABEL", "FOR",
                      "IF", "CALL", "GOTO", "SET", "SETLOCAL", "ENDLOCAL",
                      "DO", "IN", "EXIST", "DEFINED", "NOT", "ERRORLEVEL",
                      "ELSE", "EXIT", "SHIFT", "EOF_KW", "LPAREN", "RPAREN",
                      "AMP", "PIPE", "AMPAMP", "PIPEPIPE", "GT", "LT", "GE",
                      "LE", "EQ", "COLON", "SLASH", "EQUALS", "COMMA", "EQU",
                      "NEQ", "LSS", "LEQ", "GTR", "GEQ", "SET_A", "CARET",
                      "PERCENT", "ASTERISK", "DQ_STRING", "SQ_STRING", "PERCENT_TILDE",
                      "PERCENT_VAR_SUBSTRING", "PERCENT_VAR_REPLACE", "PERCENT_VAR",
                      "PERCENT_NUM", "FOR_VAR", "FOR_VAR_TILDE", "BANG_VAR",
                      "WORD", "NUMBER", "WS", "NEWLINE", "UNMATCHED_DQ" ]

    RULE_script = 0
    RULE_line = 1
    RULE_label = 2
    RULE_commandLine = 3
    RULE_statement = 4
    RULE_exitStmt = 5
    RULE_exitTail = 6
    RULE_shiftStmt = 7
    RULE_ifStmt = 8
    RULE_ifTail = 9
    RULE_ifErrorlevelStmt = 10
    RULE_ifExistOperand = 11
    RULE_ifBlockStmt = 12
    RULE_ifCondition = 13
    RULE_comparison = 14
    RULE_compareOp = 15
    RULE_compareOperand = 16
    RULE_forStmt = 17
    RULE_forMod = 18
    RULE_forList = 19
    RULE_forItem = 20
    RULE_callStmt = 21
    RULE_callTarget = 22
    RULE_gotoStmt = 23
    RULE_setStmt = 24
    RULE_setlocalStmt = 25
    RULE_setlocalRest = 26
    RULE_endlocalStmt = 27
    RULE_setTarget = 28
    RULE_setOp = 29
    RULE_setRest = 30
    RULE_genericCmd = 31
    RULE_commandTail = 32
    RULE_token = 33
    RULE_block = 34

    ruleNames =  [ "script", "line", "label", "commandLine", "statement",
                   "exitStmt", "exitTail", "shiftStmt", "ifStmt", "ifTail",
                   "ifErrorlevelStmt", "ifExistOperand", "ifBlockStmt",
                   "ifCondition", "comparison", "compareOp", "compareOperand",
                   "forStmt", "forMod", "forList", "forItem", "callStmt",
                   "callTarget", "gotoStmt", "setStmt", "setlocalStmt",
                   "setlocalRest", "endlocalStmt", "setTarget", "setOp",
                   "setRest", "genericCmd", "commandTail", "token", "block" ]

    EOF = Token.EOF
    LINE_COMMENT=1
    REM=2
    LABEL=3
    FOR=4
    IF=5
    CALL=6
    GOTO=7
    SET=8
    SETLOCAL=9
    ENDLOCAL=10
    DO=11
    IN=12
    EXIST=13
    DEFINED=14
    NOT=15
    ERRORLEVEL=16
    ELSE=17
    EXIT=18
    SHIFT=19
    EOF_KW=20
    LPAREN=21
    RPAREN=22
    AMP=23
    PIPE=24
    AMPAMP=25
    PIPEPIPE=26
    GT=27
    LT=28
    GE=29
    LE=30
    EQ=31
    COLON=32
    SLASH=33
    EQUALS=34
    COMMA=35
    EQU=36
    NEQ=37
    LSS=38
    LEQ=39
    GTR=40
    GEQ=41
    SET_A=42
    CARET=43
    PERCENT=44
    ASTERISK=45
    DQ_STRING=46
    SQ_STRING=47
    PERCENT_TILDE=48
    PERCENT_VAR_SUBSTRING=49
    PERCENT_VAR_REPLACE=50
    PERCENT_VAR=51
    PERCENT_NUM=52
    FOR_VAR=53
    FOR_VAR_TILDE=54
    BANG_VAR=55
    WORD=56
    NUMBER=57
    WS=58
    NEWLINE=59
    UNMATCHED_DQ=60

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.2")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class ScriptContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EOF(self):
            return self.getToken(BatchParser.EOF, 0)

        def line(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.LineContext)
            else:
                return self.getTypedRuleContext(BatchParser.LineContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_script

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitScript" ):
                return visitor.visitScript(self)
            else:
                return visitor.visitChildren(self)




    def script(self):

        localctx = BatchParser.ScriptContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_script)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 73
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & 2017551060845725688) != 0):
                self.state = 70
                self.line()
                self.state = 75
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 76
            self.match(BatchParser.EOF)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class LineContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def label(self):
            return self.getTypedRuleContext(BatchParser.LabelContext,0)


        def commandLine(self):
            return self.getTypedRuleContext(BatchParser.CommandLineContext,0)


        def NEWLINE(self):
            return self.getToken(BatchParser.NEWLINE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_line

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLine" ):
                return visitor.visitLine(self)
            else:
                return visitor.visitChildren(self)




    def line(self):

        localctx = BatchParser.LineContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_line)
        try:
            self.state = 81
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [3]:
                self.enterOuterAlt(localctx, 1)
                self.state = 78
                self.label()
                pass
            elif token in [4, 5, 6, 7, 8, 9, 10, 18, 19, 21, 22, 23, 24, 27, 28, 43, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 60]:
                self.enterOuterAlt(localctx, 2)
                self.state = 79
                self.commandLine()
                pass
            elif token in [59]:
                self.enterOuterAlt(localctx, 3)
                self.state = 80
                self.match(BatchParser.NEWLINE)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class LabelContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LABEL(self):
            return self.getToken(BatchParser.LABEL, 0)

        def NEWLINE(self):
            return self.getToken(BatchParser.NEWLINE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_label

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLabel" ):
                return visitor.visitLabel(self)
            else:
                return visitor.visitChildren(self)




    def label(self):

        localctx = BatchParser.LabelContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_label)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 83
            self.match(BatchParser.LABEL)
            self.state = 85
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
            if la_ == 1:
                self.state = 84
                self.match(BatchParser.NEWLINE)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CommandLineContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def statement(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.StatementContext)
            else:
                return self.getTypedRuleContext(BatchParser.StatementContext,i)


        def AMP(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.AMP)
            else:
                return self.getToken(BatchParser.AMP, i)

        def PIPE(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.PIPE)
            else:
                return self.getToken(BatchParser.PIPE, i)

        def AMPAMP(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.AMPAMP)
            else:
                return self.getToken(BatchParser.AMPAMP, i)

        def PIPEPIPE(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.PIPEPIPE)
            else:
                return self.getToken(BatchParser.PIPEPIPE, i)

        def NEWLINE(self):
            return self.getToken(BatchParser.NEWLINE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_commandLine

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCommandLine" ):
                return visitor.visitCommandLine(self)
            else:
                return visitor.visitChildren(self)




    def commandLine(self):

        localctx = BatchParser.CommandLineContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_commandLine)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 87
            self.statement()
            self.state = 95
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,4,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 93
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [23]:
                        self.state = 88
                        self.match(BatchParser.AMP)
                        pass
                    elif token in [24]:
                        self.state = 89
                        self.match(BatchParser.PIPE)
                        pass
                    elif token in [25]:
                        self.state = 90
                        self.match(BatchParser.AMPAMP)
                        pass
                    elif token in [26]:
                        self.state = 91
                        self.match(BatchParser.PIPEPIPE)
                        self.state = 92
                        self.statement()
                        pass
                    else:
                        raise NoViableAltException(self)

                self.state = 97
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,4,self._ctx)

            self.state = 99
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
            if la_ == 1:
                self.state = 98
                self.match(BatchParser.NEWLINE)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class StatementContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ifStmt(self):
            return self.getTypedRuleContext(BatchParser.IfStmtContext,0)


        def forStmt(self):
            return self.getTypedRuleContext(BatchParser.ForStmtContext,0)


        def callStmt(self):
            return self.getTypedRuleContext(BatchParser.CallStmtContext,0)


        def gotoStmt(self):
            return self.getTypedRuleContext(BatchParser.GotoStmtContext,0)


        def setStmt(self):
            return self.getTypedRuleContext(BatchParser.SetStmtContext,0)


        def setlocalStmt(self):
            return self.getTypedRuleContext(BatchParser.SetlocalStmtContext,0)


        def endlocalStmt(self):
            return self.getTypedRuleContext(BatchParser.EndlocalStmtContext,0)


        def exitStmt(self):
            return self.getTypedRuleContext(BatchParser.ExitStmtContext,0)


        def shiftStmt(self):
            return self.getTypedRuleContext(BatchParser.ShiftStmtContext,0)


        def genericCmd(self):
            return self.getTypedRuleContext(BatchParser.GenericCmdContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_statement

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStatement" ):
                return visitor.visitStatement(self)
            else:
                return visitor.visitChildren(self)




    def statement(self):

        localctx = BatchParser.StatementContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_statement)
        try:
            self.state = 111
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [5]:
                self.enterOuterAlt(localctx, 1)
                self.state = 101
                self.ifStmt()
                pass
            elif token in [4]:
                self.enterOuterAlt(localctx, 2)
                self.state = 102
                self.forStmt()
                pass
            elif token in [6]:
                self.enterOuterAlt(localctx, 3)
                self.state = 103
                self.callStmt()
                pass
            elif token in [7]:
                self.enterOuterAlt(localctx, 4)
                self.state = 104
                self.gotoStmt()
                pass
            elif token in [8]:
                self.enterOuterAlt(localctx, 5)
                self.state = 105
                self.setStmt()
                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 6)
                self.state = 106
                self.setlocalStmt()
                pass
            elif token in [10]:
                self.enterOuterAlt(localctx, 7)
                self.state = 107
                self.endlocalStmt()
                pass
            elif token in [18]:
                self.enterOuterAlt(localctx, 8)
                self.state = 108
                self.exitStmt()
                pass
            elif token in [19]:
                self.enterOuterAlt(localctx, 9)
                self.state = 109
                self.shiftStmt()
                pass
            elif token in [21, 22, 23, 24, 27, 28, 43, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 60]:
                self.enterOuterAlt(localctx, 10)
                self.state = 110
                self.genericCmd()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ExitStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EXIT(self):
            return self.getToken(BatchParser.EXIT, 0)

        def exitTail(self):
            return self.getTypedRuleContext(BatchParser.ExitTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_exitStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExitStmt" ):
                return visitor.visitExitStmt(self)
            else:
                return visitor.visitChildren(self)




    def exitStmt(self):

        localctx = BatchParser.ExitStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_exitStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 113
            self.match(BatchParser.EXIT)
            self.state = 115
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,7,self._ctx)
            if la_ == 1:
                self.state = 114
                self.exitTail()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ExitTailContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SLASH(self):
            return self.getToken(BatchParser.SLASH, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def NUMBER(self):
            return self.getToken(BatchParser.NUMBER, 0)

        def token(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.TokenContext)
            else:
                return self.getTypedRuleContext(BatchParser.TokenContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_exitTail

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExitTail" ):
                return visitor.visitExitTail(self)
            else:
                return visitor.visitChildren(self)




    def exitTail(self):

        localctx = BatchParser.ExitTailContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_exitTail)
        try:
            self.state = 125
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,9,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 117
                self.match(BatchParser.SLASH)
                self.state = 118
                self.match(BatchParser.WORD)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 119
                self.match(BatchParser.NUMBER)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 121
                self._errHandler.sync(self)
                _alt = 1
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt == 1:
                        self.state = 120
                        self.token()

                    else:
                        raise NoViableAltException(self)
                    self.state = 123
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,8,self._ctx)

                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ShiftStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SHIFT(self):
            return self.getToken(BatchParser.SHIFT, 0)

        def token(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.TokenContext)
            else:
                return self.getTypedRuleContext(BatchParser.TokenContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_shiftStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitShiftStmt" ):
                return visitor.visitShiftStmt(self)
            else:
                return visitor.visitChildren(self)




    def shiftStmt(self):

        localctx = BatchParser.ShiftStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_shiftStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 127
            self.match(BatchParser.SHIFT)
            self.state = 131
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,10,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 128
                    self.token()
                self.state = 133
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,10,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def IF(self):
            return self.getToken(BatchParser.IF, 0)

        def ifTail(self):
            return self.getTypedRuleContext(BatchParser.IfTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_ifStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfStmt" ):
                return visitor.visitIfStmt(self)
            else:
                return visitor.visitChildren(self)




    def ifStmt(self):

        localctx = BatchParser.IfStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_ifStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 134
            self.match(BatchParser.IF)
            self.state = 135
            self.ifTail()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfTailContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ifErrorlevelStmt(self):
            return self.getTypedRuleContext(BatchParser.IfErrorlevelStmtContext,0)


        def NOT(self):
            return self.getToken(BatchParser.NOT, 0)

        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


        def DEFINED(self):
            return self.getToken(BatchParser.DEFINED, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def EXIST(self):
            return self.getToken(BatchParser.EXIST, 0)

        def ifExistOperand(self):
            return self.getTypedRuleContext(BatchParser.IfExistOperandContext,0)


        def comparison(self):
            return self.getTypedRuleContext(BatchParser.ComparisonContext,0)


        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def ifBlockStmt(self):
            return self.getTypedRuleContext(BatchParser.IfBlockStmtContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_ifTail

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfTail" ):
                return visitor.visitIfTail(self)
            else:
                return visitor.visitChildren(self)




    def ifTail(self):

        localctx = BatchParser.IfTailContext(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_ifTail)
        self._la = 0 # Token type
        try:
            self.state = 173
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,20,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 138
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 137
                    self.match(BatchParser.NOT)


                self.state = 140
                self.ifErrorlevelStmt()
                self.state = 142
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,12,self._ctx)
                if la_ == 1:
                    self.state = 141
                    self.commandTail()


                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 145
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 144
                    self.match(BatchParser.NOT)


                self.state = 147
                self.match(BatchParser.DEFINED)
                self.state = 148
                self.match(BatchParser.WORD)
                self.state = 150
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,14,self._ctx)
                if la_ == 1:
                    self.state = 149
                    self.commandTail()


                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 153
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 152
                    self.match(BatchParser.NOT)


                self.state = 155
                self.match(BatchParser.EXIST)
                self.state = 156
                self.ifExistOperand()
                self.state = 158
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,16,self._ctx)
                if la_ == 1:
                    self.state = 157
                    self.commandTail()


                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 160
                self.comparison()
                self.state = 162
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,17,self._ctx)
                if la_ == 1:
                    self.state = 161
                    self.commandTail()


                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 164
                self.match(BatchParser.DQ_STRING)
                self.state = 166
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,18,self._ctx)
                if la_ == 1:
                    self.state = 165
                    self.commandTail()


                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 168
                self.match(BatchParser.PERCENT_VAR)
                self.state = 170
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
                if la_ == 1:
                    self.state = 169
                    self.commandTail()


                pass

            elif la_ == 7:
                self.enterOuterAlt(localctx, 7)
                self.state = 172
                self.ifBlockStmt()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfErrorlevelStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ERRORLEVEL(self):
            return self.getToken(BatchParser.ERRORLEVEL, 0)

        def NUMBER(self):
            return self.getToken(BatchParser.NUMBER, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_ifErrorlevelStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfErrorlevelStmt" ):
                return visitor.visitIfErrorlevelStmt(self)
            else:
                return visitor.visitChildren(self)




    def ifErrorlevelStmt(self):

        localctx = BatchParser.IfErrorlevelStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_ifErrorlevelStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 175
            self.match(BatchParser.ERRORLEVEL)
            self.state = 176
            self.match(BatchParser.NUMBER)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfExistOperandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_ifExistOperand

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfExistOperand" ):
                return visitor.visitIfExistOperand(self)
            else:
                return visitor.visitChildren(self)




    def ifExistOperand(self):

        localctx = BatchParser.IfExistOperandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_ifExistOperand)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 178
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 74379762595790848) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfBlockStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ifCondition(self):
            return self.getTypedRuleContext(BatchParser.IfConditionContext,0)


        def LPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.LPAREN)
            else:
                return self.getToken(BatchParser.LPAREN, i)

        def block(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.BlockContext)
            else:
                return self.getTypedRuleContext(BatchParser.BlockContext,i)


        def RPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.RPAREN)
            else:
                return self.getToken(BatchParser.RPAREN, i)

        def ELSE(self):
            return self.getToken(BatchParser.ELSE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_ifBlockStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfBlockStmt" ):
                return visitor.visitIfBlockStmt(self)
            else:
                return visitor.visitChildren(self)




    def ifBlockStmt(self):

        localctx = BatchParser.IfBlockStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_ifBlockStmt)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 180
            self.ifCondition()
            self.state = 181
            self.match(BatchParser.LPAREN)
            self.state = 182
            self.block()
            self.state = 183
            self.match(BatchParser.RPAREN)
            self.state = 189
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==17:
                self.state = 184
                self.match(BatchParser.ELSE)
                self.state = 185
                self.match(BatchParser.LPAREN)
                self.state = 186
                self.block()
                self.state = 187
                self.match(BatchParser.RPAREN)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfConditionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ifErrorlevelStmt(self):
            return self.getTypedRuleContext(BatchParser.IfErrorlevelStmtContext,0)


        def NOT(self):
            return self.getToken(BatchParser.NOT, 0)

        def DEFINED(self):
            return self.getToken(BatchParser.DEFINED, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def EXIST(self):
            return self.getToken(BatchParser.EXIST, 0)

        def ifExistOperand(self):
            return self.getTypedRuleContext(BatchParser.IfExistOperandContext,0)


        def comparison(self):
            return self.getTypedRuleContext(BatchParser.ComparisonContext,0)


        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_ifCondition

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfCondition" ):
                return visitor.visitIfCondition(self)
            else:
                return visitor.visitChildren(self)




    def ifCondition(self):

        localctx = BatchParser.IfConditionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_ifCondition)
        self._la = 0 # Token type
        try:
            self.state = 209
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,25,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 192
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 191
                    self.match(BatchParser.NOT)


                self.state = 194
                self.ifErrorlevelStmt()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 196
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 195
                    self.match(BatchParser.NOT)


                self.state = 198
                self.match(BatchParser.DEFINED)
                self.state = 199
                self.match(BatchParser.WORD)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 201
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 200
                    self.match(BatchParser.NOT)


                self.state = 203
                self.match(BatchParser.EXIST)
                self.state = 204
                self.ifExistOperand()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 205
                self.comparison()
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 206
                self.match(BatchParser.DQ_STRING)
                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 207
                self.match(BatchParser.PERCENT_VAR)
                pass

            elif la_ == 7:
                self.enterOuterAlt(localctx, 7)
                self.state = 208
                self.match(BatchParser.WORD)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ComparisonContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def compareOperand(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.CompareOperandContext)
            else:
                return self.getTypedRuleContext(BatchParser.CompareOperandContext,i)


        def compareOp(self):
            return self.getTypedRuleContext(BatchParser.CompareOpContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_comparison

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitComparison" ):
                return visitor.visitComparison(self)
            else:
                return visitor.visitChildren(self)




    def comparison(self):

        localctx = BatchParser.ComparisonContext(self, self._ctx, self.state)
        self.enterRule(localctx, 28, self.RULE_comparison)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 211
            self.compareOperand()
            self.state = 212
            self.compareOp()
            self.state = 213
            self.compareOperand()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CompareOpContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EQ(self):
            return self.getToken(BatchParser.EQ, 0)

        def EQU(self):
            return self.getToken(BatchParser.EQU, 0)

        def NEQ(self):
            return self.getToken(BatchParser.NEQ, 0)

        def LSS(self):
            return self.getToken(BatchParser.LSS, 0)

        def LEQ(self):
            return self.getToken(BatchParser.LEQ, 0)

        def GTR(self):
            return self.getToken(BatchParser.GTR, 0)

        def GEQ(self):
            return self.getToken(BatchParser.GEQ, 0)

        def LT(self):
            return self.getToken(BatchParser.LT, 0)

        def GT(self):
            return self.getToken(BatchParser.GT, 0)

        def LE(self):
            return self.getToken(BatchParser.LE, 0)

        def GE(self):
            return self.getToken(BatchParser.GE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_compareOp

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCompareOp" ):
                return visitor.visitCompareOp(self)
            else:
                return visitor.visitChildren(self)




    def compareOp(self):

        localctx = BatchParser.CompareOpContext(self, self._ctx, self.state)
        self.enterRule(localctx, 30, self.RULE_compareOp)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 215
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 4333487783936) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CompareOperandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def PERCENT_TILDE(self):
            return self.getToken(BatchParser.PERCENT_TILDE, 0)

        def PERCENT_VAR_SUBSTRING(self):
            return self.getToken(BatchParser.PERCENT_VAR_SUBSTRING, 0)

        def PERCENT_VAR_REPLACE(self):
            return self.getToken(BatchParser.PERCENT_VAR_REPLACE, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def PERCENT_NUM(self):
            return self.getToken(BatchParser.PERCENT_NUM, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def NUMBER(self):
            return self.getToken(BatchParser.NUMBER, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_compareOperand

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCompareOperand" ):
                return visitor.visitCompareOperand(self)
            else:
                return visitor.visitChildren(self)




    def compareOperand(self):

        localctx = BatchParser.CompareOperandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_compareOperand)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 217
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 224968875135991808) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ForStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def FOR(self):
            return self.getToken(BatchParser.FOR, 0)

        def FOR_VAR(self):
            return self.getToken(BatchParser.FOR_VAR, 0)

        def IN(self):
            return self.getToken(BatchParser.IN, 0)

        def LPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.LPAREN)
            else:
                return self.getToken(BatchParser.LPAREN, i)

        def forList(self):
            return self.getTypedRuleContext(BatchParser.ForListContext,0)


        def RPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(BatchParser.RPAREN)
            else:
                return self.getToken(BatchParser.RPAREN, i)

        def DO(self):
            return self.getToken(BatchParser.DO, 0)

        def block(self):
            return self.getTypedRuleContext(BatchParser.BlockContext,0)


        def commandLine(self):
            return self.getTypedRuleContext(BatchParser.CommandLineContext,0)


        def forMod(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.ForModContext)
            else:
                return self.getTypedRuleContext(BatchParser.ForModContext,i)


        def FOR_VAR_TILDE(self):
            return self.getToken(BatchParser.FOR_VAR_TILDE, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_forStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitForStmt" ):
                return visitor.visitForStmt(self)
            else:
                return visitor.visitChildren(self)




    def forStmt(self):

        localctx = BatchParser.ForStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 34, self.RULE_forStmt)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 219
            self.match(BatchParser.FOR)
            self.state = 223
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==33:
                self.state = 220
                self.forMod()
                self.state = 225
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 226
            self.match(BatchParser.FOR_VAR)
            self.state = 228
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==54:
                self.state = 227
                self.match(BatchParser.FOR_VAR_TILDE)


            self.state = 230
            self.match(BatchParser.IN)
            self.state = 231
            self.match(BatchParser.LPAREN)
            self.state = 232
            self.forList()
            self.state = 233
            self.match(BatchParser.RPAREN)
            self.state = 234
            self.match(BatchParser.DO)
            self.state = 241
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,28,self._ctx)
            if la_ == 1:
                self.state = 235
                self.match(BatchParser.LPAREN)
                self.state = 236
                self.block()
                self.state = 237
                self.match(BatchParser.RPAREN)
                pass

            elif la_ == 2:
                self.state = 239
                self.block()
                pass

            elif la_ == 3:
                self.state = 240
                self.commandLine()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ForModContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SLASH(self):
            return self.getToken(BatchParser.SLASH, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_forMod

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitForMod" ):
                return visitor.visitForMod(self)
            else:
                return visitor.visitChildren(self)




    def forMod(self):

        localctx = BatchParser.ForModContext(self, self._ctx, self.state)
        self.enterRule(localctx, 36, self.RULE_forMod)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 243
            self.match(BatchParser.SLASH)
            self.state = 244
            self.match(BatchParser.WORD)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ForListContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def forItem(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.ForItemContext)
            else:
                return self.getTypedRuleContext(BatchParser.ForItemContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_forList

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitForList" ):
                return visitor.visitForList(self)
            else:
                return visitor.visitChildren(self)




    def forList(self):

        localctx = BatchParser.ForListContext(self, self._ctx, self.state)
        self.enterRule(localctx, 38, self.RULE_forList)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 246
            self.forItem()
            self.state = 250
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & 218670872532090880) != 0):
                self.state = 247
                self.forItem()
                self.state = 252
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ForItemContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SQ_STRING(self):
            return self.getToken(BatchParser.SQ_STRING, 0)

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def NUMBER(self):
            return self.getToken(BatchParser.NUMBER, 0)

        def ASTERISK(self):
            return self.getToken(BatchParser.ASTERISK, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_forItem

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitForItem" ):
                return visitor.visitForItem(self)
            else:
                return visitor.visitChildren(self)




    def forItem(self):

        localctx = BatchParser.ForItemContext(self, self._ctx, self.state)
        self.enterRule(localctx, 40, self.RULE_forItem)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 253
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 218670872532090880) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CallStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def CALL(self):
            return self.getToken(BatchParser.CALL, 0)

        def callTarget(self):
            return self.getTypedRuleContext(BatchParser.CallTargetContext,0)


        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_callStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCallStmt" ):
                return visitor.visitCallStmt(self)
            else:
                return visitor.visitChildren(self)




    def callStmt(self):

        localctx = BatchParser.CallStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 42, self.RULE_callStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 255
            self.match(BatchParser.CALL)
            self.state = 256
            self.callTarget()
            self.state = 258
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,30,self._ctx)
            if la_ == 1:
                self.state = 257
                self.commandTail()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CallTargetContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EOF_KW(self):
            return self.getToken(BatchParser.EOF_KW, 0)

        def COLON(self):
            return self.getToken(BatchParser.COLON, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def PERCENT_NUM(self):
            return self.getToken(BatchParser.PERCENT_NUM, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_callTarget

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCallTarget" ):
                return visitor.visitCallTarget(self)
            else:
                return visitor.visitChildren(self)




    def callTarget(self):

        localctx = BatchParser.CallTargetContext(self, self._ctx, self.state)
        self.enterRule(localctx, 44, self.RULE_callTarget)
        self._la = 0 # Token type
        try:
            self.state = 271
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,33,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 261
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==32:
                    self.state = 260
                    self.match(BatchParser.COLON)


                self.state = 263
                self.match(BatchParser.EOF_KW)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 265
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==32:
                    self.state = 264
                    self.match(BatchParser.COLON)


                self.state = 267
                self.match(BatchParser.WORD)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 268
                self.match(BatchParser.PERCENT_NUM)
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 269
                self.match(BatchParser.PERCENT_VAR)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 270
                self.match(BatchParser.DQ_STRING)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class GotoStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def GOTO(self):
            return self.getToken(BatchParser.GOTO, 0)

        def callTarget(self):
            return self.getTypedRuleContext(BatchParser.CallTargetContext,0)


        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_gotoStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitGotoStmt" ):
                return visitor.visitGotoStmt(self)
            else:
                return visitor.visitChildren(self)




    def gotoStmt(self):

        localctx = BatchParser.GotoStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 46, self.RULE_gotoStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 273
            self.match(BatchParser.GOTO)
            self.state = 274
            self.callTarget()
            self.state = 276
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,34,self._ctx)
            if la_ == 1:
                self.state = 275
                self.commandTail()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SET(self):
            return self.getToken(BatchParser.SET, 0)

        def setTarget(self):
            return self.getTypedRuleContext(BatchParser.SetTargetContext,0)


        def setOp(self):
            return self.getTypedRuleContext(BatchParser.SetOpContext,0)


        def setRest(self):
            return self.getTypedRuleContext(BatchParser.SetRestContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_setStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetStmt" ):
                return visitor.visitSetStmt(self)
            else:
                return visitor.visitChildren(self)




    def setStmt(self):

        localctx = BatchParser.SetStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 48, self.RULE_setStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 278
            self.match(BatchParser.SET)
            self.state = 279
            self.setTarget()
            self.state = 280
            self.setOp()
            self.state = 282
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,35,self._ctx)
            if la_ == 1:
                self.state = 281
                self.setRest()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetlocalStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SETLOCAL(self):
            return self.getToken(BatchParser.SETLOCAL, 0)

        def setlocalRest(self):
            return self.getTypedRuleContext(BatchParser.SetlocalRestContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_setlocalStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetlocalStmt" ):
                return visitor.visitSetlocalStmt(self)
            else:
                return visitor.visitChildren(self)




    def setlocalStmt(self):

        localctx = BatchParser.SetlocalStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 50, self.RULE_setlocalStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 284
            self.match(BatchParser.SETLOCAL)
            self.state = 286
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,36,self._ctx)
            if la_ == 1:
                self.state = 285
                self.setlocalRest()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetlocalRestContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def token(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.TokenContext)
            else:
                return self.getTypedRuleContext(BatchParser.TokenContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_setlocalRest

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetlocalRest" ):
                return visitor.visitSetlocalRest(self)
            else:
                return visitor.visitChildren(self)




    def setlocalRest(self):

        localctx = BatchParser.SetlocalRestContext(self, self._ctx, self.state)
        self.enterRule(localctx, 52, self.RULE_setlocalRest)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 289
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 288
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 291
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,37,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EndlocalStmtContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ENDLOCAL(self):
            return self.getToken(BatchParser.ENDLOCAL, 0)

        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_endlocalStmt

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEndlocalStmt" ):
                return visitor.visitEndlocalStmt(self)
            else:
                return visitor.visitChildren(self)




    def endlocalStmt(self):

        localctx = BatchParser.EndlocalStmtContext(self, self._ctx, self.state)
        self.enterRule(localctx, 54, self.RULE_endlocalStmt)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 293
            self.match(BatchParser.ENDLOCAL)
            self.state = 295
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,38,self._ctx)
            if la_ == 1:
                self.state = 294
                self.commandTail()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetTargetContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_setTarget

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetTarget" ):
                return visitor.visitSetTarget(self)
            else:
                return visitor.visitChildren(self)




    def setTarget(self):

        localctx = BatchParser.SetTargetContext(self, self._ctx, self.state)
        self.enterRule(localctx, 56, self.RULE_setTarget)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 297
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 74379762595790848) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetOpContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EQUALS(self):
            return self.getToken(BatchParser.EQUALS, 0)

        def SET_A(self):
            return self.getToken(BatchParser.SET_A, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_setOp

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetOp" ):
                return visitor.visitSetOp(self)
            else:
                return visitor.visitChildren(self)




    def setOp(self):

        localctx = BatchParser.SetOpContext(self, self._ctx, self.state)
        self.enterRule(localctx, 58, self.RULE_setOp)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 299
            _la = self._input.LA(1)
            if not(_la==34 or _la==42):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SetRestContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def token(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.TokenContext)
            else:
                return self.getTypedRuleContext(BatchParser.TokenContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_setRest

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSetRest" ):
                return visitor.visitSetRest(self)
            else:
                return visitor.visitChildren(self)




    def setRest(self):

        localctx = BatchParser.SetRestContext(self, self._ctx, self.state)
        self.enterRule(localctx, 60, self.RULE_setRest)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 302
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 301
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 304
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,39,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class GenericCmdContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


        def getRuleIndex(self):
            return BatchParser.RULE_genericCmd

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitGenericCmd" ):
                return visitor.visitGenericCmd(self)
            else:
                return visitor.visitChildren(self)




    def genericCmd(self):

        localctx = BatchParser.GenericCmdContext(self, self._ctx, self.state)
        self.enterRule(localctx, 62, self.RULE_genericCmd)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 306
            self.commandTail()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CommandTailContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def token(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.TokenContext)
            else:
                return self.getTypedRuleContext(BatchParser.TokenContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_commandTail

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCommandTail" ):
                return visitor.visitCommandTail(self)
            else:
                return visitor.visitChildren(self)




    def commandTail(self):

        localctx = BatchParser.CommandTailContext(self, self._ctx, self.state)
        self.enterRule(localctx, 64, self.RULE_commandTail)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 309
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 308
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 311
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,40,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class TokenContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DQ_STRING(self):
            return self.getToken(BatchParser.DQ_STRING, 0)

        def SQ_STRING(self):
            return self.getToken(BatchParser.SQ_STRING, 0)

        def PERCENT_TILDE(self):
            return self.getToken(BatchParser.PERCENT_TILDE, 0)

        def PERCENT_VAR_SUBSTRING(self):
            return self.getToken(BatchParser.PERCENT_VAR_SUBSTRING, 0)

        def PERCENT_VAR_REPLACE(self):
            return self.getToken(BatchParser.PERCENT_VAR_REPLACE, 0)

        def PERCENT_VAR(self):
            return self.getToken(BatchParser.PERCENT_VAR, 0)

        def PERCENT_NUM(self):
            return self.getToken(BatchParser.PERCENT_NUM, 0)

        def FOR_VAR(self):
            return self.getToken(BatchParser.FOR_VAR, 0)

        def FOR_VAR_TILDE(self):
            return self.getToken(BatchParser.FOR_VAR_TILDE, 0)

        def BANG_VAR(self):
            return self.getToken(BatchParser.BANG_VAR, 0)

        def CARET(self):
            return self.getToken(BatchParser.CARET, 0)

        def LPAREN(self):
            return self.getToken(BatchParser.LPAREN, 0)

        def RPAREN(self):
            return self.getToken(BatchParser.RPAREN, 0)

        def GT(self):
            return self.getToken(BatchParser.GT, 0)

        def LT(self):
            return self.getToken(BatchParser.LT, 0)

        def AMP(self):
            return self.getToken(BatchParser.AMP, 0)

        def PIPE(self):
            return self.getToken(BatchParser.PIPE, 0)

        def WORD(self):
            return self.getToken(BatchParser.WORD, 0)

        def NUMBER(self):
            return self.getToken(BatchParser.NUMBER, 0)

        def UNMATCHED_DQ(self):
            return self.getToken(BatchParser.UNMATCHED_DQ, 0)

        def getRuleIndex(self):
            return BatchParser.RULE_token

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitToken" ):
                return visitor.visitToken(self)
            else:
                return visitor.visitChildren(self)




    def token(self):

        localctx = BatchParser.TokenContext(self, self._ctx, self.state)
        self.enterRule(localctx, 66, self.RULE_token)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 313
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1441090308541513728) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class BlockContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def line(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(BatchParser.LineContext)
            else:
                return self.getTypedRuleContext(BatchParser.LineContext,i)


        def getRuleIndex(self):
            return BatchParser.RULE_block

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBlock" ):
                return visitor.visitBlock(self)
            else:
                return visitor.visitChildren(self)




    def block(self):

        localctx = BatchParser.BlockContext(self, self._ctx, self.state)
        self.enterRule(localctx, 68, self.RULE_block)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 318
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,41,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 315
                    self.line()
                self.state = 320
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,41,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





