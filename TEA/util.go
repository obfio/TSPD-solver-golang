package TEA

import (
	"fmt"
	"strconv"
	"strings"
)

// CharCodeAt https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/charCodeAt
func charCodeAt(str string, n int) int {
	if len(str) == 0 || len(str) < n {
		return 0
	}
	return int([]rune(str)[n])
}

func charAt(str string, n int) string {
	return strings.Split(str, "")[n]
}

func charAtRange(str string, n, n1 int) string {
	return strings.Join(strings.Split(str, "")[n:n1], "")
}

// FromCharCode https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/FromCharCode
func fromCharCode(c int) string {
	return string(rune(c))
}

func toString(v interface{}) string {
	switch c := v.(type) {
	case int:
		return strconv.Itoa(c)
	case uint:
		return strconv.FormatUint(uint64(c), 10)
	case int32:
		return strconv.Itoa(int(c))
	case uint32:
		return strconv.FormatUint(uint64(c), 10)
	case int64:
		return strconv.Itoa(int(c))
	case uint64:
		return strconv.FormatUint(uint64(c), 10)
	case float32:
		return fmt.Sprintf("%f", c)
	case float64:
		return strconv.FormatFloat(c, 'f', -1, 64)
	case string:
		return c
	default:
		return fmt.Sprintf("%s", c)
	}
}

func toStringHex(v int64) string {
	return strconv.FormatInt(v, 16)
}

func toInt(v interface{}) int {
	switch c := v.(type) {
	case int:
		return int(c)
	case int32:
		return int(c)
	case int64:
		return int(c)
	case float32:
		return int(c)
	case float64:
		return int(c)
	case string:
		r, _ := strconv.Atoi(c)
		return r
	default:
		return 0
	}
}

func parseInt(v, c interface{}) int64 {
	switch v.(type) {
	case int:
		return int64(v.(int))
	case string:
		solved, _ := strconv.ParseInt(v.(string), toInt(c), 64)
		return solved
	default:
		panic("lmao")
	}

}

func doubleInt(v int) string {
	if v < 0 || v > 9 {
		return fmt.Sprint(v)
	}
	return "0" + fmt.Sprint(v)
}

func trippleShift(num, t int) int {
	overflow := int32(num)
	return int(uint32(overflow) >> t)
}

func rotateLeft(num, t int) int {
	overflow := int32(num)
	return int(overflow<<t) | int(uint32(num)>>(32-t))
}

func rightShift(num, t int) int {
	overflow := int32(num)
	return int(overflow >> t)
}
