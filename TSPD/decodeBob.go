package TSPD

type a struct {
	value interface{}
	lL    int
}

func DecodeBob(bobStr string) ([]interface{}, error) {
	out := []interface{}{}
	/*
			for (var Jj = 0, oj = [], Oj = {
			          "value": "",
			          lL: 0
			        }; Oj.lL < J["length"];) switch (Oj = S(J, Oj.lL), Oj["value"]) {
			        case 1:
			          Oj = _(J, Oj.lL);
			          oj[Jj++] = Oj["value"];
			          break;
			        case 2:
			          Oj = I(J, Oj.lL);
			          oj[Jj++] = Oj["value"];
			          break;
			        case 3:
			          Oj = jj(J, Oj.lL)
		              oj[Jj++] = Oj["value"];
			      }
			      return oj;
	*/
	Oj := &a{}
	for Oj.lL < len(bobStr) {
		Oj = s(bobStr, Oj.lL)
		switch Oj.value.(int64) {
		case 1:
			Oj = underscore(bobStr, Oj.lL)
			out = append(out, Oj.value.(bool))
			break
		case 2:
			Oj = I(bobStr, Oj.lL)
			out = append(out, Oj.value.(int64))
			break
		case 3:
			Oj = jj(bobStr, Oj.lL)
			out = append(out, Oj.value.(string))
			break
		}
	}
	return out, nil
}

/*
	function jj(J, S) {
	      var _ = parseInt(J["substring"](S, S + 8), 16);
	      S += 8;
	      var I = J["substring"](S, S + _);
	      S += _;
	      L && (I = decodeURIComponent(I));
	      return {
	        "value": I,
	        lL: S
	      };
	    }
*/
func jj(bobStr string, L int) *a {
	temp := int(parseInt(bobStr[L:L+8], 16))
	L += 8
	I := bobStr[L : L+temp]
	L += temp
	return &a{
		value: I,
		lL:    L,
	}
}

/*
function I(J, L) {
      var S = parseInt(J["substring"](L, L + 8), 16);
      L += 8;
      return {
        "value": S,
        lL: L
      };
    }
*/

func I(bobStr string, L int) *a {
	S := parseInt(bobStr[L:L+8], 16)
	L += 8
	return &a{
		value: S,
		lL:    L,
	}
}

/*
	function _(J, L) {
	      var S = parseInt(J["substring"](L, L + 1)) ? Jl : false;
	      L += 1;
	      return {
	        "value": S,
	        lL: L
	      };
	    }
*/
func underscore(bobStr string, L int) *a {
	S := parseInt(bobStr[L:L+1], 10)
	S1 := true
	if S == 0 {
		S1 = false
	}
	L += 1
	return &a{
		value: S1,
		lL:    L,
	}
}

/*
function S(J, L) {
      var S = parseInt(J["substring"](L, L + 1));
      L += 1;
      return {
        "value": S,
        lL: L
      };
    }
*/

func s(bobStr string, L int) *a {
	S := parseInt(bobStr[L:L+1], 10)
	L += 1
	return &a{
		value: S,
		lL:    L,
	}
}
