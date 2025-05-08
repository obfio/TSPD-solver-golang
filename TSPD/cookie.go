package TSPD

import (
	"TSPD-solver-golang/TEA"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

func GenerateCookie(bob []interface{}, loaderStr string) string {
	out := ""
	out += doubleInt(bob[13].(int64))
	out += doubleInt(bob[14].(int64))
	decrypted := TEA.DecryptLoaderStr(loaderStr)
	p := &Payload{}
	json.Unmarshal([]byte(defaultPayload), &p)
	payloadStr := p.generatePayloadStr()
	// warning for future me, if you do `[]byte(payloadStr)` it will double the weirdStr bytes
	// utf-16 encoding will fix this but holy moly is that aids
	sealed := TEA.Seal(payloadStr, "04", decrypted)
	fmt.Println(sealed)
	return out
}

/*
	{
	    "10": "en-US",
	    "11": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
	    "12": "ÿ¿Þÿÿöýûþ¾÷ÿÿÿÿÿ",
	    "13": 0,
	    "14": "",
	    "00": 0,
	    "01": 0,
	    "02": 1,
	    "03": 0,
	    "04": 0,
	    "05": 1,
	    "06": 0,
	    "07": 0,
	    "08": 0,
	    "09": 0
	}

[

	{
	    "name": "00",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "01",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "02",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "03",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "04",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "05",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "06",
	    "type": 0,
	    "O": 1
	},
	{
	    "name": "07",
	    "type": 0,
	    "O": 4
	},
	{
	    "name": "08",
	    "type": 0,
	    "O": 4
	},
	{
	    "name": "09",
	    "type": 0,
	    "O": 4
	},
	{
	    "name": "10",
	    "type": 1
	},
	{
	    "name": "11",
	    "type": 1
	},
	{
	    "name": "12",
	    "type": 1
	},
	{
	    "name": "13",
	    "type": 0,
	    "O": 4
	},
	{
	    "name": "14",
	    "type": 1
	}

]
*/
func (p *Payload) generatePayloadStr() string {
	out := ""
	// 00
	out += ol(p.NavigatorCheck, 1, false)
	//01
	out += ol(p.PhantomCheck, 1, false)
	//02
	out += ol(p.HistoryCheck, 1, false)
	//03
	out += ol(p.ReferrerCheck, 1, false)
	//04
	out += ol(p.ShockwaveFlashCheck, 1, false)
	//05
	out += ol(p.WGLCheck, 1, false)
	//06
	out += ol(p.SpoofedUACheck, 1, false)
	// 07
	out += ol(p.SeleniumCheck, 4, false)
	// 08
	out += ol(p.Idk, 4, false)
	// 09
	out += ol(p.SafariAutomationCheck, 4, false)
	// 10

	out += ol(len(p.Language), 1, false)
	out += p.Language

	// 11
	out += ol(len(p.UserAgent), 1, false)
	out += p.UserAgent

	// 12
	// golang is UTF8, JS is UTF16, this causes issues here
	utf16Encoded := utf16.Encode([]rune(p.WeirdStr))
	out += ol(len(utf16Encoded), 1, false)
	for i := 0; i < len(utf16Encoded); i++ {
		out += string(byte(utf16Encoded[i] & 0xFF))
	}
	// 13
	out += ol(p.State, 4, false)
	// 14
	out += ol(len(p.HTTPInterceptorsRunning), 1, false)
	out += p.HTTPInterceptorsRunning
	return out
}

/*
	OL: function (J, L, z) {
	        var _ = "";
	        J = J["toString"](16);
	        J = IL.O$(J);
	        for (var I, jj = J["length"]; jj > 0; jj -= 2) I = J["slice"](Math["max"](0, jj - 2), jj), _ += String["fromCharCode"](parseInt(I, 16));
	        L = L || _["length"];
	        _ += Array(1 + L - _["length"])["join"]("\0");
	        if (_["length"] !== L) throw Lo(), "";
	        z && (_ = oo.oJ(_));
	        return OL() ? _ : void 0;
	      }
*/
var (
	weirdRegex = regexp.MustCompile(`(^[\\da-f\\.]+)\\(e\\+(\\d+)\\)`)
)

func ol(J, L int, z bool) string {
	underscore := ""
	JStr := toStringHex(int64(J))
	//if len(JStr) == 1 {
	//	JStr = "0" + JStr
	//}
	JStr = odollarsign(JStr)
	I := ""
	jj := len(JStr)
	for ; jj > 0; jj -= 2 {
		//I = J["slice"](Math["max"](0, jj - 2), jj)
		//_ += String["fromCharCode"](parseInt(I, 16));
		tmp := 0
		if jj-2 > tmp {
			tmp = jj - 2
		}
		I = JStr[tmp:jj]
		underscore += string(parseInt(I, 16))
	}
	if L == 0 {
		L = len(underscore)
	}
	underscore += strings.Join(make([]string, 1+L-len(underscore)), "\000")
	if len(underscore) != L {
		panic("OH NOES")
	}
	//z && (_ = oo.oJ(_));
	if z {
		panic("HOW MANNN")
		//underscore = oJ(underscore())
	}
	return underscore
}

func odollarsign(J string) string {
	z := weirdRegex.MatchString(J)
	if !z {
		return J
	}
	panic("HOW DID WE GET HERE BROTHER D:")
}
