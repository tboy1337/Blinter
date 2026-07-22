# Generated from C:/Users/Laptop/Documents/Git/Blinter/vendor/batch-spec/grammar/BatchParser.g4 by ANTLR 4.13.2
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
        4,1,64,288,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,2,32,7,32,2,33,
        7,33,2,34,7,34,1,0,5,0,72,8,0,10,0,12,0,75,9,0,1,0,1,0,1,1,1,1,1,
        1,3,1,82,8,1,1,2,1,2,3,2,86,8,2,1,3,1,3,1,3,5,3,91,8,3,10,3,12,3,
        94,9,3,1,3,3,3,97,8,3,1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,3,
        4,109,8,4,1,5,1,5,3,5,113,8,5,1,6,1,6,1,6,1,6,4,6,119,8,6,11,6,12,
        6,120,3,6,123,8,6,1,7,1,7,5,7,127,8,7,10,7,12,7,130,9,7,1,8,1,8,
        1,8,1,9,1,9,3,9,137,8,9,1,9,3,9,140,8,9,1,10,1,10,1,10,1,11,1,11,
        1,12,1,12,1,12,1,12,1,12,1,12,1,12,1,12,1,12,3,12,156,8,12,1,13,
        3,13,159,8,13,1,13,1,13,3,13,163,8,13,1,13,1,13,1,13,3,13,168,8,
        13,1,13,1,13,1,13,1,13,1,13,1,13,3,13,176,8,13,1,14,1,14,1,14,1,
        14,1,15,1,15,1,16,1,16,1,17,1,17,5,17,188,8,17,10,17,12,17,191,9,
        17,1,17,1,17,3,17,195,8,17,1,17,1,17,1,17,1,17,1,17,1,17,1,17,1,
        17,1,17,1,17,1,17,3,17,208,8,17,1,18,1,18,1,18,1,19,1,19,5,19,215,
        8,19,10,19,12,19,218,9,19,1,20,1,20,1,21,1,21,1,21,3,21,225,8,21,
        1,22,3,22,228,8,22,1,22,1,22,3,22,232,8,22,1,22,1,22,1,22,1,22,3,
        22,238,8,22,1,23,1,23,1,23,3,23,243,8,23,1,24,1,24,1,24,1,24,3,24,
        249,8,24,1,25,1,25,3,25,253,8,25,1,26,4,26,256,8,26,11,26,12,26,
        257,1,27,1,27,3,27,262,8,27,1,28,1,28,1,29,1,29,1,30,4,30,269,8,
        30,11,30,12,30,270,1,31,1,31,1,32,4,32,276,8,32,11,32,12,32,277,
        1,33,1,33,1,34,5,34,283,8,34,10,34,12,34,286,9,34,1,34,0,0,35,0,
        2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,
        48,50,52,54,56,58,60,62,64,66,68,0,7,1,0,23,26,3,0,50,50,55,55,60,
        60,2,0,27,31,41,46,3,0,50,50,52,56,60,61,3,0,49,51,55,55,60,61,2,
        0,33,33,35,35,7,0,21,24,27,28,34,34,36,40,47,47,50,61,64,64,304,
        0,73,1,0,0,0,2,81,1,0,0,0,4,83,1,0,0,0,6,87,1,0,0,0,8,108,1,0,0,
        0,10,110,1,0,0,0,12,122,1,0,0,0,14,124,1,0,0,0,16,131,1,0,0,0,18,
        139,1,0,0,0,20,141,1,0,0,0,22,144,1,0,0,0,24,146,1,0,0,0,26,175,
        1,0,0,0,28,177,1,0,0,0,30,181,1,0,0,0,32,183,1,0,0,0,34,185,1,0,
        0,0,36,209,1,0,0,0,38,212,1,0,0,0,40,219,1,0,0,0,42,221,1,0,0,0,
        44,237,1,0,0,0,46,239,1,0,0,0,48,244,1,0,0,0,50,250,1,0,0,0,52,255,
        1,0,0,0,54,259,1,0,0,0,56,263,1,0,0,0,58,265,1,0,0,0,60,268,1,0,
        0,0,62,272,1,0,0,0,64,275,1,0,0,0,66,279,1,0,0,0,68,284,1,0,0,0,
        70,72,3,2,1,0,71,70,1,0,0,0,72,75,1,0,0,0,73,71,1,0,0,0,73,74,1,
        0,0,0,74,76,1,0,0,0,75,73,1,0,0,0,76,77,5,0,0,1,77,1,1,0,0,0,78,
        82,3,4,2,0,79,82,3,6,3,0,80,82,5,63,0,0,81,78,1,0,0,0,81,79,1,0,
        0,0,81,80,1,0,0,0,82,3,1,0,0,0,83,85,5,3,0,0,84,86,5,63,0,0,85,84,
        1,0,0,0,85,86,1,0,0,0,86,5,1,0,0,0,87,92,3,8,4,0,88,89,7,0,0,0,89,
        91,3,8,4,0,90,88,1,0,0,0,91,94,1,0,0,0,92,90,1,0,0,0,92,93,1,0,0,
        0,93,96,1,0,0,0,94,92,1,0,0,0,95,97,5,63,0,0,96,95,1,0,0,0,96,97,
        1,0,0,0,97,7,1,0,0,0,98,109,3,16,8,0,99,109,3,34,17,0,100,109,3,
        42,21,0,101,109,3,46,23,0,102,109,3,48,24,0,103,109,3,50,25,0,104,
        109,3,54,27,0,105,109,3,10,5,0,106,109,3,14,7,0,107,109,3,62,31,
        0,108,98,1,0,0,0,108,99,1,0,0,0,108,100,1,0,0,0,108,101,1,0,0,0,
        108,102,1,0,0,0,108,103,1,0,0,0,108,104,1,0,0,0,108,105,1,0,0,0,
        108,106,1,0,0,0,108,107,1,0,0,0,109,9,1,0,0,0,110,112,5,18,0,0,111,
        113,3,12,6,0,112,111,1,0,0,0,112,113,1,0,0,0,113,11,1,0,0,0,114,
        115,5,34,0,0,115,123,5,60,0,0,116,123,5,61,0,0,117,119,3,66,33,0,
        118,117,1,0,0,0,119,120,1,0,0,0,120,118,1,0,0,0,120,121,1,0,0,0,
        121,123,1,0,0,0,122,114,1,0,0,0,122,116,1,0,0,0,122,118,1,0,0,0,
        123,13,1,0,0,0,124,128,5,19,0,0,125,127,3,66,33,0,126,125,1,0,0,
        0,127,130,1,0,0,0,128,126,1,0,0,0,128,129,1,0,0,0,129,15,1,0,0,0,
        130,128,1,0,0,0,131,132,5,5,0,0,132,133,3,18,9,0,133,17,1,0,0,0,
        134,136,3,26,13,0,135,137,3,64,32,0,136,135,1,0,0,0,136,137,1,0,
        0,0,137,140,1,0,0,0,138,140,3,24,12,0,139,134,1,0,0,0,139,138,1,
        0,0,0,140,19,1,0,0,0,141,142,5,16,0,0,142,143,5,61,0,0,143,21,1,
        0,0,0,144,145,7,1,0,0,145,23,1,0,0,0,146,147,3,26,13,0,147,148,5,
        21,0,0,148,149,3,68,34,0,149,155,5,22,0,0,150,151,5,17,0,0,151,152,
        5,21,0,0,152,153,3,68,34,0,153,154,5,22,0,0,154,156,1,0,0,0,155,
        150,1,0,0,0,155,156,1,0,0,0,156,25,1,0,0,0,157,159,5,15,0,0,158,
        157,1,0,0,0,158,159,1,0,0,0,159,160,1,0,0,0,160,176,3,20,10,0,161,
        163,5,15,0,0,162,161,1,0,0,0,162,163,1,0,0,0,163,164,1,0,0,0,164,
        165,5,14,0,0,165,176,5,60,0,0,166,168,5,15,0,0,167,166,1,0,0,0,167,
        168,1,0,0,0,168,169,1,0,0,0,169,170,5,13,0,0,170,176,3,22,11,0,171,
        176,3,28,14,0,172,176,5,50,0,0,173,176,5,55,0,0,174,176,5,60,0,0,
        175,158,1,0,0,0,175,162,1,0,0,0,175,167,1,0,0,0,175,171,1,0,0,0,
        175,172,1,0,0,0,175,173,1,0,0,0,175,174,1,0,0,0,176,27,1,0,0,0,177,
        178,3,32,16,0,178,179,3,30,15,0,179,180,3,32,16,0,180,29,1,0,0,0,
        181,182,7,2,0,0,182,31,1,0,0,0,183,184,7,3,0,0,184,33,1,0,0,0,185,
        189,5,4,0,0,186,188,3,36,18,0,187,186,1,0,0,0,188,191,1,0,0,0,189,
        187,1,0,0,0,189,190,1,0,0,0,190,192,1,0,0,0,191,189,1,0,0,0,192,
        194,5,57,0,0,193,195,5,58,0,0,194,193,1,0,0,0,194,195,1,0,0,0,195,
        196,1,0,0,0,196,197,5,12,0,0,197,198,5,21,0,0,198,199,3,38,19,0,
        199,200,5,22,0,0,200,207,5,11,0,0,201,202,5,21,0,0,202,203,3,68,
        34,0,203,204,5,22,0,0,204,208,1,0,0,0,205,208,3,68,34,0,206,208,
        3,6,3,0,207,201,1,0,0,0,207,205,1,0,0,0,207,206,1,0,0,0,208,35,1,
        0,0,0,209,210,5,34,0,0,210,211,5,60,0,0,211,37,1,0,0,0,212,216,3,
        40,20,0,213,215,3,40,20,0,214,213,1,0,0,0,215,218,1,0,0,0,216,214,
        1,0,0,0,216,217,1,0,0,0,217,39,1,0,0,0,218,216,1,0,0,0,219,220,7,
        4,0,0,220,41,1,0,0,0,221,222,5,6,0,0,222,224,3,44,22,0,223,225,3,
        64,32,0,224,223,1,0,0,0,224,225,1,0,0,0,225,43,1,0,0,0,226,228,5,
        32,0,0,227,226,1,0,0,0,227,228,1,0,0,0,228,229,1,0,0,0,229,238,5,
        20,0,0,230,232,5,32,0,0,231,230,1,0,0,0,231,232,1,0,0,0,232,233,
        1,0,0,0,233,238,5,60,0,0,234,238,5,56,0,0,235,238,5,55,0,0,236,238,
        5,50,0,0,237,227,1,0,0,0,237,231,1,0,0,0,237,234,1,0,0,0,237,235,
        1,0,0,0,237,236,1,0,0,0,238,45,1,0,0,0,239,240,5,7,0,0,240,242,3,
        44,22,0,241,243,3,64,32,0,242,241,1,0,0,0,242,243,1,0,0,0,243,47,
        1,0,0,0,244,245,5,8,0,0,245,246,3,56,28,0,246,248,3,58,29,0,247,
        249,3,60,30,0,248,247,1,0,0,0,248,249,1,0,0,0,249,49,1,0,0,0,250,
        252,5,9,0,0,251,253,3,52,26,0,252,251,1,0,0,0,252,253,1,0,0,0,253,
        51,1,0,0,0,254,256,3,66,33,0,255,254,1,0,0,0,256,257,1,0,0,0,257,
        255,1,0,0,0,257,258,1,0,0,0,258,53,1,0,0,0,259,261,5,10,0,0,260,
        262,3,64,32,0,261,260,1,0,0,0,261,262,1,0,0,0,262,55,1,0,0,0,263,
        264,7,1,0,0,264,57,1,0,0,0,265,266,7,5,0,0,266,59,1,0,0,0,267,269,
        3,66,33,0,268,267,1,0,0,0,269,270,1,0,0,0,270,268,1,0,0,0,270,271,
        1,0,0,0,271,61,1,0,0,0,272,273,3,64,32,0,273,63,1,0,0,0,274,276,
        3,66,33,0,275,274,1,0,0,0,276,277,1,0,0,0,277,275,1,0,0,0,277,278,
        1,0,0,0,278,65,1,0,0,0,279,280,7,6,0,0,280,67,1,0,0,0,281,283,3,
        2,1,0,282,281,1,0,0,0,283,286,1,0,0,0,284,282,1,0,0,0,284,285,1,
        0,0,0,285,69,1,0,0,0,286,284,1,0,0,0,33,73,81,85,92,96,108,112,120,
        122,128,136,139,155,158,162,167,175,189,194,207,216,224,227,231,
        237,242,248,252,257,261,270,277,284
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
                     "'>'", "'<'", "'>='", "'<='", "'=='", "':'", "'/A'", 
                     "'/'", "'='", "','", "'.'", "'\\'", "'+'", "'-'", "'EQU'", 
                     "'NEQ'", "'LSS'", "'LEQ'", "'GTR'", "'GEQ'", "'^'", 
                     "'%'", "'*'" ]

    symbolicNames = [ "<INVALID>", "LINE_COMMENT", "REM", "LABEL", "FOR", 
                      "IF", "CALL", "GOTO", "SET", "SETLOCAL", "ENDLOCAL", 
                      "DO", "IN", "EXIST", "DEFINED", "NOT", "ERRORLEVEL", 
                      "ELSE", "EXIT", "SHIFT", "EOF_KW", "LPAREN", "RPAREN", 
                      "AMP", "PIPE", "AMPAMP", "PIPEPIPE", "GT", "LT", "GE", 
                      "LE", "EQ", "COLON", "SET_A", "SLASH", "EQUALS", "COMMA", 
                      "DOT", "BACKSLASH", "PLUS", "MINUS", "EQU", "NEQ", 
                      "LSS", "LEQ", "GTR", "GEQ", "CARET", "PERCENT", "ASTERISK", 
                      "DQ_STRING", "SQ_STRING", "PERCENT_TILDE", "PERCENT_VAR_SUBSTRING", 
                      "PERCENT_VAR_REPLACE", "PERCENT_VAR", "PERCENT_NUM", 
                      "FOR_VAR", "FOR_VAR_TILDE", "BANG_VAR", "WORD", "NUMBER", 
                      "WS", "NEWLINE", "UNMATCHED_DQ" ]

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
    RULE_ifPredicate = 13
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
                   "ifPredicate", "comparison", "compareOp", "compareOperand", 
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
    SET_A=33
    SLASH=34
    EQUALS=35
    COMMA=36
    DOT=37
    BACKSLASH=38
    PLUS=39
    MINUS=40
    EQU=41
    NEQ=42
    LSS=43
    LEQ=44
    GTR=45
    GEQ=46
    CARET=47
    PERCENT=48
    ASTERISK=49
    DQ_STRING=50
    SQ_STRING=51
    PERCENT_TILDE=52
    PERCENT_VAR_SUBSTRING=53
    PERCENT_VAR_REPLACE=54
    PERCENT_VAR=55
    PERCENT_NUM=56
    FOR_VAR=57
    FOR_VAR_TILDE=58
    BANG_VAR=59
    WORD=60
    NUMBER=61
    WS=62
    NEWLINE=63
    UNMATCHED_DQ=64

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
            while ((((_la - 3)) & ~0x3f) == 0 and ((1 << (_la - 3)) & 4035102389311471871) != 0):
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
            elif token in [4, 5, 6, 7, 8, 9, 10, 18, 19, 21, 22, 23, 24, 27, 28, 34, 36, 37, 38, 39, 40, 47, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64]:
                self.enterOuterAlt(localctx, 2)
                self.state = 79
                self.commandLine()
                pass
            elif token in [63]:
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


        def NEWLINE(self):
            return self.getToken(BatchParser.NEWLINE, 0)

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
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 87
            self.statement()
            self.state = 92
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,3,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 88
                    _la = self._input.LA(1)
                    if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 125829120) != 0)):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()
                    self.state = 89
                    self.statement() 
                self.state = 94
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,3,self._ctx)

            self.state = 96
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,4,self._ctx)
            if la_ == 1:
                self.state = 95
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
            self.state = 108
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [5]:
                self.enterOuterAlt(localctx, 1)
                self.state = 98
                self.ifStmt()
                pass
            elif token in [4]:
                self.enterOuterAlt(localctx, 2)
                self.state = 99
                self.forStmt()
                pass
            elif token in [6]:
                self.enterOuterAlt(localctx, 3)
                self.state = 100
                self.callStmt()
                pass
            elif token in [7]:
                self.enterOuterAlt(localctx, 4)
                self.state = 101
                self.gotoStmt()
                pass
            elif token in [8]:
                self.enterOuterAlt(localctx, 5)
                self.state = 102
                self.setStmt()
                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 6)
                self.state = 103
                self.setlocalStmt()
                pass
            elif token in [10]:
                self.enterOuterAlt(localctx, 7)
                self.state = 104
                self.endlocalStmt()
                pass
            elif token in [18]:
                self.enterOuterAlt(localctx, 8)
                self.state = 105
                self.exitStmt()
                pass
            elif token in [19]:
                self.enterOuterAlt(localctx, 9)
                self.state = 106
                self.shiftStmt()
                pass
            elif token in [21, 22, 23, 24, 27, 28, 34, 36, 37, 38, 39, 40, 47, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64]:
                self.enterOuterAlt(localctx, 10)
                self.state = 107
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
            self.state = 110
            self.match(BatchParser.EXIT)
            self.state = 112
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,6,self._ctx)
            if la_ == 1:
                self.state = 111
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
            self.state = 122
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,8,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 114
                self.match(BatchParser.SLASH)
                self.state = 115
                self.match(BatchParser.WORD)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 116
                self.match(BatchParser.NUMBER)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 118 
                self._errHandler.sync(self)
                _alt = 1
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt == 1:
                        self.state = 117
                        self.token()

                    else:
                        raise NoViableAltException(self)
                    self.state = 120 
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,7,self._ctx)

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
            self.state = 124
            self.match(BatchParser.SHIFT)
            self.state = 128
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,9,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 125
                    self.token() 
                self.state = 130
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,9,self._ctx)

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
            self.state = 131
            self.match(BatchParser.IF)
            self.state = 132
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

        def ifPredicate(self):
            return self.getTypedRuleContext(BatchParser.IfPredicateContext,0)


        def commandTail(self):
            return self.getTypedRuleContext(BatchParser.CommandTailContext,0)


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
        try:
            self.state = 139
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,11,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 134
                self.ifPredicate()
                self.state = 136
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,10,self._ctx)
                if la_ == 1:
                    self.state = 135
                    self.commandTail()


                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 138
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
            self.state = 141
            self.match(BatchParser.ERRORLEVEL)
            self.state = 142
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
            self.state = 144
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1190076201532653568) != 0)):
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

        def ifPredicate(self):
            return self.getTypedRuleContext(BatchParser.IfPredicateContext,0)


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
            self.state = 146
            self.ifPredicate()
            self.state = 147
            self.match(BatchParser.LPAREN)
            self.state = 148
            self.block()
            self.state = 149
            self.match(BatchParser.RPAREN)
            self.state = 155
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==17:
                self.state = 150
                self.match(BatchParser.ELSE)
                self.state = 151
                self.match(BatchParser.LPAREN)
                self.state = 152
                self.block()
                self.state = 153
                self.match(BatchParser.RPAREN)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IfPredicateContext(ParserRuleContext):
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
            return BatchParser.RULE_ifPredicate

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIfPredicate" ):
                return visitor.visitIfPredicate(self)
            else:
                return visitor.visitChildren(self)




    def ifPredicate(self):

        localctx = BatchParser.IfPredicateContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_ifPredicate)
        self._la = 0 # Token type
        try:
            self.state = 175
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,16,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 158
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 157
                    self.match(BatchParser.NOT)


                self.state = 160
                self.ifErrorlevelStmt()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 162
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 161
                    self.match(BatchParser.NOT)


                self.state = 164
                self.match(BatchParser.DEFINED)
                self.state = 165
                self.match(BatchParser.WORD)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 167
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 166
                    self.match(BatchParser.NOT)


                self.state = 169
                self.match(BatchParser.EXIST)
                self.state = 170
                self.ifExistOperand()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 171
                self.comparison()
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 172
                self.match(BatchParser.DQ_STRING)
                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 173
                self.match(BatchParser.PERCENT_VAR)
                pass

            elif la_ == 7:
                self.enterOuterAlt(localctx, 7)
                self.state = 174
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
            self.state = 177
            self.compareOperand()
            self.state = 178
            self.compareOp()
            self.state = 179
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
            self.state = 181
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 138542625849344) != 0)):
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
            self.state = 183
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 3599502002175868928) != 0)):
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
            self.state = 185
            self.match(BatchParser.FOR)
            self.state = 189
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==34:
                self.state = 186
                self.forMod()
                self.state = 191
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 192
            self.match(BatchParser.FOR_VAR)
            self.state = 194
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==58:
                self.state = 193
                self.match(BatchParser.FOR_VAR_TILDE)


            self.state = 196
            self.match(BatchParser.IN)
            self.state = 197
            self.match(BatchParser.LPAREN)
            self.state = 198
            self.forList()
            self.state = 199
            self.match(BatchParser.RPAREN)
            self.state = 200
            self.match(BatchParser.DO)
            self.state = 207
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                self.state = 201
                self.match(BatchParser.LPAREN)
                self.state = 202
                self.block()
                self.state = 203
                self.match(BatchParser.RPAREN)
                pass

            elif la_ == 2:
                self.state = 205
                self.block()
                pass

            elif la_ == 3:
                self.state = 206
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
            self.state = 209
            self.match(BatchParser.SLASH)
            self.state = 210
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
            self.state = 212
            self.forItem()
            self.state = 216
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & 3498733960513454080) != 0):
                self.state = 213
                self.forItem()
                self.state = 218
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
            self.state = 219
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 3498733960513454080) != 0)):
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
            self.state = 221
            self.match(BatchParser.CALL)
            self.state = 222
            self.callTarget()
            self.state = 224
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,21,self._ctx)
            if la_ == 1:
                self.state = 223
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
            self.state = 237
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,24,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 227
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==32:
                    self.state = 226
                    self.match(BatchParser.COLON)


                self.state = 229
                self.match(BatchParser.EOF_KW)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 231
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==32:
                    self.state = 230
                    self.match(BatchParser.COLON)


                self.state = 233
                self.match(BatchParser.WORD)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 234
                self.match(BatchParser.PERCENT_NUM)
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 235
                self.match(BatchParser.PERCENT_VAR)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 236
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
            self.state = 239
            self.match(BatchParser.GOTO)
            self.state = 240
            self.callTarget()
            self.state = 242
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,25,self._ctx)
            if la_ == 1:
                self.state = 241
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
            self.state = 244
            self.match(BatchParser.SET)
            self.state = 245
            self.setTarget()
            self.state = 246
            self.setOp()
            self.state = 248
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,26,self._ctx)
            if la_ == 1:
                self.state = 247
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
            self.state = 250
            self.match(BatchParser.SETLOCAL)
            self.state = 252
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,27,self._ctx)
            if la_ == 1:
                self.state = 251
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
            self.state = 255 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 254
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 257 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,28,self._ctx)

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
            self.state = 259
            self.match(BatchParser.ENDLOCAL)
            self.state = 261
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,29,self._ctx)
            if la_ == 1:
                self.state = 260
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
            self.state = 263
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1190076201532653568) != 0)):
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
            self.state = 265
            _la = self._input.LA(1)
            if not(_la==33 or _la==35):
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
            self.state = 268 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 267
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 270 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,30,self._ctx)

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
            self.state = 272
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
            self.state = 275 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 274
                    self.token()

                else:
                    raise NoViableAltException(self)
                self.state = 277 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,31,self._ctx)

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

        def DOT(self):
            return self.getToken(BatchParser.DOT, 0)

        def BACKSLASH(self):
            return self.getToken(BatchParser.BACKSLASH, 0)

        def PLUS(self):
            return self.getToken(BatchParser.PLUS, 0)

        def MINUS(self):
            return self.getToken(BatchParser.MINUS, 0)

        def COMMA(self):
            return self.getToken(BatchParser.COMMA, 0)

        def SLASH(self):
            return self.getToken(BatchParser.SLASH, 0)

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
            self.state = 279
            _la = self._input.LA(1)
            if not(((((_la - 21)) & ~0x3f) == 0 and ((1 << (_la - 21)) & 10994647539919) != 0)):
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
            self.state = 284
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,32,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 281
                    self.line() 
                self.state = 286
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,32,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





