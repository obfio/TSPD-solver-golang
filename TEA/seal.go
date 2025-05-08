package TEA

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

func Seal(str, scope, decryptedStr string) string {
	e := oz(str, scope, nil, nil, decryptedStr)
	return oJ(e)
}

/*
	OZ: function (S, _, oj, Oj) {
	              Oj = I(Oj);
	              oj = oj || L;
	                _["length"] === 4 && _["substring"](0, 2) === "0x" && (_ = _["substring"](2));
	                if (_["length"] != 2) throw _o("bad scope_hex.length " + _["length"]), "";
	                var _j = oo.jl(_),
	                  jJ = oo.J_(Oj, S, false),
	                  lJ = oo.IS(Oj, jJ + oj + _j) + jJ;
	                if (lJ["length"] >= 4096) throw _o("securemsg: Seal failed - Payload is too long."), "";
	                var Sj = oo.Z_(lJ["length"], 2);
	                return lJ = z + oj + _j + Sj + lJ;
	            }
*/
func oz(S, underscore string, _, _ interface{}, decryptedStr string) string {
	Oj := getKey(-1)
	oj := decryptedStr
	if len(underscore) == 4 && underscore[0:2] == "0x" {
		underscore = underscore[2:]
	}
	if len(underscore) != 2 {
		panic("bad scope_hex.length " + fmt.Sprint(len(underscore)))
	}
	_j := jl(underscore)
	jJ := j_(Oj, S, false)
	fmt.Println(len(utf16.Encode([]rune(jJ))), "A")
	fmt.Println(len(utf16.Encode([]rune(S))), "B")
	fmt.Println([]byte(jJ), "C")
	fmt.Println(len(jJ))
	lJ := is(Oj, jJ+oj+_j) + jJ
	if len(lJ) >= 4096 {
		panic("securemsg: Seal failed - Payload is too long.")
	}
	Sj := z_(len(utf16.Encode([]rune(lJ))), 2)
	return z_(8, 1) + oj + _j + Sj + lJ
}

/*
	Z_: function (J, L) {
	        for (var S = "", _ = "0" + J["toString"](16), I = _["length"]; I > 0; I -= 2) S += String["fromCharCode"](parseInt(_["slice"](I - 2, I), 16));
	        L = L || S["length"];
	        S += Array(1 + L - S["length"])["join"]("\0");
	        if (S["length"] !== L) throw _o("cannot pack integer"), "";
	        return S;
	      }
*/
func z_(J, L int) string {
	fmt.Println(J, L)
	S := ""
	underscore := "0" + toStringHex(int64(J))
	I := len(underscore)
	for ; I > 0; I -= 2 {
		S += string(byte(parseInt(underscore[I-2:I], 16)))
	}
	if L == 0 {
		L = len(S)
	}
	S += strings.Join(make([]string, 1+L-len(S)), "\000")
	if len(S) != L {
		panic("cannot pack integer")
	}
	return S
}
