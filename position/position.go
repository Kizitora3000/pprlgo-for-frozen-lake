package position

import "fmt"

type Position struct {
	X int // X座標
	Y int // Y座標
}

// String() メソッドを定義して Position の表示形式を変更
func (p Position) String() string {
	return fmt.Sprintf("{X: %d, Y: %d}", p.X, p.Y)
}
