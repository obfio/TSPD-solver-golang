package TEA

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

func DecryptLoaderStr(str string) string {
	a := decryptLoaderStr(str, "01").(string)
	b := sl(a, "AB", true, true, true, -1, false).(*objOutput)
	out := oJ(b.LZ)
	return out
}

/*
	oJ: function (J) {
	        return JZ["map"](JZ.ZL(0, J["length"], 1), function (z) {
	          z = Number(J["charCodeAt"](z))["toString"](16);
	          return z["length"] == 1 ? "0" + z : z;
	        })["join"]("");
	      }
*/
func oJ(J string) string {
	out := []string{}
	for i := 0; i < len(J); i++ {
		toAdd := toStringHex(parseInt(int(J[i]), 10))
		if len(toStringHex(parseInt(int(J[i]), 10))) == 1 {
			toAdd = "0" + toAdd
		}
		out = append(out, toAdd)
	}
	return strings.Join(out, "")
}

/*
	function Ol(J, L, z, S, _, I, jj) {
	        if (typeof J !== "string") return false;
	        J = oo.jl(J);
	        L = oo.LO().SL(J, L, z, S, _, I, jj);
	        typeof L == "object" && (L["offset"] && (L["offset"] = L["offset"] * 2), L.O && (L.O *= 2));
	        return L;
	      }
*/
func decryptLoaderStr(str, scope string) interface{} {
	str = jl(str)
	L := sl(str, scope, false, false, false, -1, false)
	var oo *objOutput
	switch L.(type) {
	case objOutput:
		oo = L.(*objOutput)
		if oo.offset != 0 {
			oo.offset *= 2
		}
		if oo.O != 0 {
			oo.O *= 2
		}
	}
	return L
}

type objOutput struct {
	offset int
	O      int
	LZ     string
	zjJ    string
}

/*
	function SL(z, _, oj, Oj, _j, jJ, lJ) {
	              jJ = I(jJ);
	                _["length"] === 4 && _["substring"](0, 2) === "0x" && (_ = _["substring"](2));
	                if (_["length"] != 2) throw _o("bad scope_hex.length " + _["length"]), "";
	                var Sj = oo.jl(_);
	                if (z["length"] < 8) throw _o("Message too short for headers: " + z["length"] + " < 8"), "";
	                var JJ = oo.S_(z["slice"](0, 1)),
	                  OJ = z["slice"](1, 5),
	                  zJ = z["slice"](5, 6),
	                  ZJ = oo.S_(z["slice"](6, 8)),
	                  SJ = parseInt(JJ, 10) + parseInt(ZJ, 10);
	                if (Sj !== zJ) throw _o("scope doesn't match: " + oo.oJ(Sj) + " !== " + oo.oJ(zJ)), "";
	                if (JJ < 8) throw _o("hdr_len too short: " + JJ + " < 8"), "";
	                if (z["length"] < SJ) throw _o("message too short for payload: " + z["length"] + " < " + SJ), "";
	                if (ZJ < oo.I$) throw _o("message too short for signature: " + ZJ + " < " + oo.I$), "";
	                var Zj = parseInt(JJ, 10) + parseInt(oo.I$, 10),
	                  Ol = parseInt(ZJ, 10) - parseInt(oo.I$, 10),
	                  IJ = z["substr"](Zj, Ol);
	                if (Oj) {
	                  var lL = parseInt(Zj, 10) + parseInt(Ol, 10),
	                    iL = z["slice"](0, lL);
	                  return oj ? {
	                    LZ: iL,
	                    O: lL
	                  } : iL;
	                }
	                if (z["substr"](JJ, oo.I$) !== oo.IS(jJ, IJ + OJ + Sj)) throw _o("Message failed integrity checks during unseal"), "";
	                if (lJ) return oo.s2(jJ, IJ, lJ), Jl;
	                var jo = oo.J_(jJ, IJ, Jl);
	                _j || (L = OJ);
	                return oj ? {
	                  zjJ: jo,
	                  "offset": parseInt(Zj, 10) + parseInt(Ol, 10)
	                } : jo;
	            }
*/
func sl(str, scope string, oj, Oj, _j bool, jJ1 int, lJ bool) interface{} {
	// get enc/dec key
	jJ := getKey(jJ1)
	if len(scope) == 4 && scope[:2] == "0x" {
		scope = scope[2:4]
	}
	if len(scope) != 2 {
		panic("bad scope_hex.length " + fmt.Sprint(len(scope)))
	}
	Sj := jl(scope)
	if len(str) < 8 {
		panic("message too short for headers: " + fmt.Sprint(len(str)) + " < 8")
	}
	JJ := s_(str[:1])
	OJ := str[1:5]
	zJ := str[5:6]
	ZJ := s_(str[6:8])
	SJ := JJ + ZJ
	if Sj != zJ {
		panic("scope doesn't match: " + fmt.Sprint(Sj) + " !== " + fmt.Sprint(zJ))
	}
	if JJ < 8 {
		panic("hdr_len too short: " + fmt.Sprint(JJ) + " < 8")
	}
	if len(str) < SJ {
		panic("message too short for payload: " + fmt.Sprint(len(str)) + " < " + fmt.Sprint(SJ))
	}
	if ZJ < 8 {
		panic("message too short for signature: " + fmt.Sprint(ZJ) + " < 8")
	}
	Zj := JJ + 8
	Ol := ZJ - 8
	IJ := str[Zj : Ol+Zj]
	if Oj {
		lL := Zj + Ol
		iL := str[:lL]
		if oj {
			return &objOutput{
				LZ: iL,
				O:  int(lL),
			}
		}
		return iL
	}

	if str[JJ:JJ+8] != is(jJ, IJ+OJ+Sj) {
		panic("Message failed integrity checks during unseal")
	}
	// ignore for now?
	//if (lJ) return oo.s2(jJ, IJ, lJ), Jl;
	//	                var jo = oo.J_(jJ, IJ, Jl);
	//	                _j || (L = OJ);
	//	                return oj ? {
	//	                  zjJ: jo,
	//	                  "offset": parseInt(Zj, 10) + parseInt(Ol, 10)
	//	                } : jo;
	jo := j_(jJ, IJ, true)
	if _j {
		panic(OJ)
	}
	if oj {
		return &objOutput{
			zjJ:    jo,
			offset: Zj + Ol,
		}
	}
	return jo
}

/*
	J_: function (J, L, z) {
	      var _ = "\0\0\0\0\0\0\0\0",
	        I = "";
	      if (z) {
	        if (L["length"] % 8 != 0) throw _o("Decryption failure"), "";
	        I = oo.jS(J, L);
	        return oo.O_(I);
	      }
	      L = oo.L_(L, 8, "\xFF");
	      z = L["length"] / 8;
	      for (var jj = 0; jj < z; jj++) _ = oo.iz(J, oo.oL(_, L["substr"](jj * 8, 8)), false), I += _;
	      return I;
	    }
*/
func j_(J, L string, z bool) string {
	// L is the payload string
	// the length is correct I guess
	underscore := "\000\000\000\000\000\000\000\000"
	I := ""
	if z {
		if len(L)%8 != 0 {
			panic("Decryption failure")
		}
		I = jS(J, L, false, "EMPTY")
		return O_(I)
	}
	L = l_(L, 8, "\xFF")
	utf16Bytes := utf16.Encode([]rune(L))
	z1 := len(utf16Bytes) / 8
	for jj := 0; jj < z1; jj++ {
		x := oL(underscore, L[jj*8:(jj*8)+8])
		if []byte(x)[0] == 71 {
			fmt.Println([]byte(x))
			fmt.Println([]byte(underscore))
			//panic("A")
		}
		underscore = iz1(J, x, false)
		I += underscore
	}
	a := strings.Split(I, "")
	asd, _ := json.Marshal(a)
	os.WriteFile("idk1.json", asd, 0644)
	//tmp := []string{}
	//f, _ := os.ReadFile("./idk.json")
	//json.Unmarshal(f, &tmp)
	//for i, a := range strings.Split(I, "") {
	//	if []byte(a) != []byte(tmp[i]) {
	//		fmt.Println(i, a, tmp[i])
	//		panic("a")
	//	}
	//}
	test := utf16.Encode([]rune(I))
	fmt.Println(len(test))
	fmt.Println(len(I))
	panic("ASD")
	return I
}

/*
	O_: function (J) {
	      return J["slice"](0, J["length"] - J["charCodeAt"](J["length"] - 1) - 1);
	    }
*/
func O_(J string) string {
	return J[0 : len(J)-int(J[len(J)-1])-1]
}

/*
	jS: function (J, L, z, S) {
	      S = S || "\0\0\0\0\0\0\0\0";
	      var _,
	        I,
	        jj = "";
	      io = "";
	      for (var Jj = L.length / 8, oj = 0; oj < Jj; oj++) {
			_ = L.substr(8 * oj, 8)
	        I = oo.iz(J, _, 1)
	        jj += oo.oL(I, S)
	        S = _;
	      }
	      Io = "";
	      if (z) z(jj, S);else return jj;
	    }
*/
func jS(J, L string, z bool, S string) string {
	if S == "EMPTY" {
		S = "\000\000\000\000\000\000\000\000"
	}
	Jj := len(L) / 8
	oj := 0
	underscore := ""
	I := ""
	jj := ""
	for ; oj < Jj; oj++ {
		underscore = L[8*oj : (8*oj)+8]
		I = iz1(J, underscore, true)
		jj += oL(I, S)
		S = underscore
	}
	if z {
		panic("IDK WHAT TO DO HERE YET")
	}
	return jj
}

/*
	IS: function (J, L) {
	          var S = J["length"] <= 16 ? J : oo.Iz(J);
	        S["length"] < 16 && (S += oo.jz("\0", 16 - S["length"]));
	        var _ = oo.oL(S, oo.jz("\\", 16)),
	          z = oo.oL(S, oo.jz("6", 16));
	        return oo.Iz(_ + oo.Iz(z + L));
	      }
*/
func is(J, L string) string {
	S := J
	if !(len(J) <= 16) {
		S = iz(J)
	}
	if len(S) < 16 {
		S += jz1("\000", 16-len(S))
	}
	a_ := oL(S, jz1("\\", 16))
	z := oL(S, jz1("6", 16))
	return iz(a_ + iz(z+L))
}

/*
	jz: function (J, L) {
	        for (var S = "", _ = 0; _ < L; _++) S += J;
	        return S;
	      }
*/
func jz1(J string, L int) string {
	out := ""
	for i := 0; i < L; i++ {
		out += J
	}
	return out
}

/*
	Iz: function (J) {
	        var z = "poiuytre";
	        J = oo.L_(J, 8, "y");
	        for (var S = J["length"] / 8, _ = 0; _ < S; _++) {
				var I = J["substr"](_ * 8, 8)
	            I = I + oo.oL(I, "\xB7\xD9 \r=\xC6lI")
	            z = oo.oL(z, oo.iz(I, z, false));
			}
	        return z;
	      }
*/
func iz(J string) string {
	z := "poiuytre"
	J = l_(J, 8, "y")
	S := len(J) / 8
	for underscore := 0; underscore < S; underscore++ {
		I := J[underscore*8 : (underscore*8)+8]
		I = I + oL(I, "\xB7\xD9 \r=\xC6lI")
		z = oL(z, iz1(I, z, false))
	}
	return z
}

/*
	j2: function (J, L, z) {
	        io = "";
	        if (16 != J.length) throw _o("Bad key length (should be 16) " + J.length), "";
	        if (8 != L.length) throw _o("Bad block length (should be 8) " + L.length), "";
	        J = oo.o_(J);
	        J = [oo.zl(J[0]), oo.zl(J[1]), oo.zl(J[2]), oo.zl(J[3])];
	        var _ = oo.o_(L);
	        L = oo.zl(_[0]);
	        var _ = oo.zl(_[1]),
	          I = (z ? 42470972304 : 0) >>> 0,
	          jj,
	          Jj,
	          oj,
	          Oj,
	          _j;
	        try {
	          if (z) for (jj = 15; 0 <= jj; jj--) oj = oo.sJ(L << 4 ^ L >>> 5, L), Jj = oo.sJ(I, J[I >>> 11 & 3]), _ = oo.JZ(_, oj ^ Jj), I = oo.JZ(I, 2654435769), Oj = oo.sJ(_ << 4 ^ _ >>> 5, _), _j = oo.sJ(I, J[I & 3]), L = oo.JZ(L, Oj ^ _j);else for (jj = I = 0; 16 > jj; jj++) oj = oo.sJ(_ << 4 ^ _ >>> 5, _), Jj = oo.sJ(I, J[I & 3]), L = oo.sJ(L, oj ^ Jj), I = oo.sJ(I, 2654435769), Oj = oo.sJ(L << 4 ^ L >>> 5, L), _j = oo.sJ(I, J[I >>> 11 & 3]), _ = oo.sJ(_, Oj ^ _j);
	        } catch (jJ) {
	          throw jJ;
	        }
	        L = oo.zl(L);
	        _ = oo.zl(_);
	        z = oo.L$([L, _]);
	        Io = "";
	        return z;
	      }
*/
func iz1(J, L string, z bool) string {
	if 16 != len(J) {
		panic("Bad key length (should be 16) " + fmt.Sprint(len(J)))
	}
	if 8 != len(L) {
		panic("Bad block length (should be 8) " + fmt.Sprint(len(L)))
	}
	JArr := o_(J)
	jArrInt := []int{zl(JArr[0]), zl(JArr[1]), zl(JArr[2]), zl(JArr[3])}
	var a_ = o_(L)
	Lint := zl(a_[0])
	b_ := zl(a_[1])
	tmp := 0
	if z {
		tmp = 42470972304
	}
	I := trippleShift(tmp, 0)
	jj := 0
	Jj := 0
	oj := 0
	Oj := 0
	_j := 0
	if z {
		for jj = 15; 0 <= jj; jj-- {
			oj = sJ(Lint<<4^trippleShift(Lint, 5), Lint)
			Jj = sJ(I, jArrInt[trippleShift(I, 11)&3])
			b_ = jz(b_, oj^Jj)
			I = jz(I, 2654435769)
			Oj = sJ(b_<<4^trippleShift(b_, 5), b_)
			_j = sJ(I, jArrInt[I&3])
			Lint = jz(Lint, Oj^_j)
		}
	} else {
		jj = 0
		I = 0
		for ; 16 > jj; jj++ {
			oj = sJ(b_<<4^trippleShift(b_, 5), b_)
			Jj = sJ(I, jArrInt[I&3])
			Lint = sJ(Lint, oj^Jj)
			I = sJ(I, 2654435769)
			Oj = sJ(Lint<<4^trippleShift(Lint, 5), Lint)
			_j = sJ(I, jArrInt[trippleShift(I, 11)&3])
			b_ = sJ(b_, Oj^_j)

		}
	}

	Lint = zl(Lint)
	b_ = zl(b_)
	return capitalldollarsign([]int{Lint, b_})
}

/*
	L$: function (J) {
	        return oo["map"](oo.ZL(0, J["length"], 1), function (L) {
	          return oo.l$(J[L], 4);
	        })["join"]("");
	      }
*/
func capitalldollarsign(J []int) string {
	//fmt.Println(J)
	out := []string{}
	for i := 0; i < len(J); i++ {
		out = append(out, ldollarsign(J[i], 4))
	}
	return strings.Join(out, "")
}

/*
	l$: function (J, L) {
	        if (J < 0) throw _o("Called Uint2Str with negative int " + J), "";
	        typeof L == "undefined" && (L = 4);
	        return oo["map"](oo.S2(L - 1, -1, -1), function (L) {
	          return String["fromCharCode"](oo.I2(J >> 8 * L));
	        })["join"]("");
	      }
*/
func ldollarsign(J int, L interface{}) string {
	if J < 0 {
		panic("Called Uint2Str with negative int " + fmt.Sprint(J))
	}
	if L == nil {
		L = 4
	}
	out := []byte{}
	for _, a := range s2(L.(int)-1, -1, -1) {
		out = append(out, byte(i2(rightShift(J, 8*a))))
	}
	return string(out)
}

/*
	I2: function (J) {
	        return 1 + Math["random"]() ? J & 255 : void 0;
	      }
*/
func i2(J int) int {
	return J & 255
}

/*
S2: function (J, L, z) {
        if (0 <= z) throw _o("step must be negative"), "";
        for (var _ = []; J > L; J += z) _.push(J);
        return _;
      }
*/

func s2(J, L, z int) []int {
	if 0 <= z {
		panic("step must be negative")
	}
	out := []int{}
	for ; J > L; J += z {
		out = append(out, J)
	}
	return out
}

/*
	JZ: function (J, L) {
	        var z = (J >>> 0) - L & 4294967295;
	        return z >>> 0;
	      }
*/
func jz(J, L int) int {
	z := trippleShift(J, 0) - L&4294967295
	return trippleShift(z, 0)
}

/*
	sJ: function (J, L) {
	        var z = (J >>> 0) + (L >>> 0) & 4294967295;
	        return z >>> 0;
	      }
*/
func sJ(J, L int) int {
	z := trippleShift(J, 0) + trippleShift(L, 0)&4294967295
	return trippleShift(z, 0)
}

/*
	zl: function (J) {
	        io = "";
	        J = (J & 255) << 24 | (J & 65280) << 8 | J >> 8 & 65280 | J >> 24 & 255;
	        "";
	        Io = "";
	        return J >>> 0;
	      }
*/
func zl(zz interface{}) int {
	//fmt.Println(zz)
	//panic("ASD")
	J := -1
	switch zz.(type) {
	case int:
		J = zz.(int)
		break
	case string:
		z := []byte(zz.(string))
		if len(z) != 1 {
			panic("IDK bro")
		}
		J = int(z[0])
	}

	num := (J&255)<<24 | (J&65280)<<8 | J>>8&65280 | J>>24&255
	return trippleShift(num, 0)
}

/*
	o_: function (J) {
	        for (var z = [], S = 0; S < J["length"]; S += 4) z["push"](oo.J$(J["substr"](S, 4)));
	        return z;
	      }
*/
func o_(J string) []int {
	z := []int{}
	for S := 0; S < len(J); S += 4 {
		z = append(z, capitalJdollarsign(J[S:S+4]))
	}
	return z
}

/*
	J$: function (J) {
	      if (4 < J.length) throw _o("Cannot convert string of more than 4 bytes"), "";
	      for (var L = 0, z = 0; z < J.length; z++) L = (L << 8) + J.charCodeAt(z);
	      return L >>> 0;
	    }
*/
func capitalJdollarsign(J string) int {
	if 4 < len(J) {
		panic("cannot convert string of more than 4 bytes")
	}
	L := 0
	z := 0
	for ; z < len(J); z++ {
		L = (L << 8) + int(J[z])
	}
	return trippleShift(L, 0)
}

/*
	oL: function (J, L) {
	        if (J.length != L.length) throw _o("xorBytes:: Length don't match -- " + oo.oJ(J) + " -- " + oo.oJ(L) + " -- " + J.length + " -- " + L.length + " -- "), "";
	        for (var S = "", _ = 0; _ < J.length; _++) S += String.fromCharCode(J.charCodeAt(_) ^ L.charCodeAt(_));
	        return S;
	      }
*/
func oL(J, L string) string {
	if len(J) != len(L) {
		panic("xorBytes:: Length don't match -- ")
	}
	S := []byte{}
	for i := 0; i < len(J); i++ {
		S = append(S, byte(J[i])^byte(L[i]))
	}
	return string(S)
}

/*
	L_: function (J, L, z) {
	        for (var _ = L - J["length"] % L - 1, I = "", jj = 0; jj < _; jj++) I += z;
	        return J + I + String["fromCharCode"](_);
	      }
*/
func l_(J string, L int, z string) string {
	underscore := L - len(J)%L - 1
	I := ""
	for jj := 0; jj < underscore; jj++ {
		I += z
	}
	return J + I + fromCharCode(underscore)
}

/*
	S_: function (J) {
	        for (var z = "", S = 0; S < J["length"]; ++S) z = ("0" + J["charCodeAt"](S)["toString"](16))["slice"](-2) + z;
	        return parseInt(z, 16);
	      }
*/
func s_(str string) int {
	z := ""
	for S := 0; S < len(str); {
		hexStr := fmt.Sprintf("%x", []byte(str)[S])
		if len(hexStr) > 2 {
			hexStr = hexStr[len(hexStr)-2:]
		} else {
			hexStr = "0" + hexStr
		}
		z = hexStr + z
		S++
	}
	return int(parseInt(z, 16))
}

/*
	I = function (L) {
	              var z, S;
	              L = L || Zo._s;
	              if (!_) {
	                try {
	                  z = Number["constructor"]
	                  delete Number["constructor"]
	                  S = Jl;
	                } catch (I) {}
	                _ = ["\x9C\xF6\x0F\x11\xB6\x0E\xBF|;\xB0u\xA4!/\xA2Q", "", "\x17\x84S\xA4H\xF6\x92\xC8\x9F\x94\x10\xA16E\xFA\xE2"];
	                S && (Number["constructor"] = z);
	              }
	              L = _[L];
	              L["length"] !== 16 && (L = L["slice"](0, 16));
	              return L;
	            }
*/
var keys = []string{"\x9C\xF6\x0F\x11\xB6\x0E\xBF|;\xB0u\xA4!/\xA2Q", "", "\x17\x84S\xA4H\xF6\x92\xC8\x9F\x94\x10\xA16E\xFA\xE2"}

func getKey(L int) string {
	num := 0
	if L != -1 {
		num = L
	}
	key := keys[num]
	if len(key) != 16 {
		key = key[:16]
	}
	return key
}

/*
	function (J) {
	        return oo["map"](oo.ZL(0, J["length"], 2), function (z) {
	          return String["fromCharCode"](parseInt(J["substr"](z, 2), 16));
	        })["join"]("");
	      }
*/
func jl(str string) string {
	out := []byte{}
	// split into chunks of 2
	for i := 0; i < len(str); i += 2 {
		s := str[i : i+2]
		val, err := strconv.ParseInt(s, 16, 0)
		if err != nil {
			panic(err)
		}
		out = append(out, byte(val))
	}
	return string(out)
}
