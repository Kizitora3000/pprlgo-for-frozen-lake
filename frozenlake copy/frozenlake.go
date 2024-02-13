package frozenlake

import "pprlgoFrozenLake/position"

type FrozenLake struct {
	Width    int               // 湖の幅
	Height   int               // 湖の高さ
	LakeMap  [][]string        // 湖の状態 ("o": 地面, "x": 穴)
	StartPos position.Position // スタート地点
	GoalPos  position.Position // ゴール地点
}

var (
	FrozenLake3x3 = FrozenLake{
		Width:  3,
		Height: 3,
		LakeMap: [][]string{
			{"o", "x", "x"},
			{"o", "o", "o"},
			{"x", "x", "o"},
		},
		StartPos: position.Position{
			X: 0,
			Y: 0,
		},
		GoalPos: position.Position{
			X: 2, // Width - 1
			Y: 2, // Height - 1
		},
	}

	FrozenLake4x4 = FrozenLake{
		Width:  4,
		Height: 4,
		LakeMap: [][]string{
			{"o", "o", "x", "x"},
			{"o", "x", "o", "x"},
			{"o", "o", "o", "o"},
			{"o", "x", "x", "o"},
		},
		StartPos: position.Position{
			X: 0,
			Y: 0,
		},
		GoalPos: position.Position{
			X: 3, // Width - 1
			Y: 3, // Height - 1
		},
	}

	FrozenLake5x5 = FrozenLake{
		Width:  5,
		Height: 5,
		LakeMap: [][]string{
			{"o", "o", "x", "x", "o"},
			{"o", "o", "o", "x", "x"},
			{"x", "x", "o", "o", "o"},
			{"x", "o", "o", "o", "x"},
			{"o", "o", "x", "o", "o"},
		},
		StartPos: position.Position{
			X: 0,
			Y: 0,
		},
		GoalPos: position.Position{
			X: 4, // Width - 1
			Y: 4, // Height - 1
		},
	}

	FrozenLake6x6 = FrozenLake{
		Width:  6,
		Height: 6,
		LakeMap: [][]string{
			{"o", "o", "x", "x", "o", "o"},
			{"o", "o", "o", "x", "x", "o"},
			{"x", "x", "o", "o", "o", "o"},
			{"o", "o", "o", "x", "x", "o"},
			{"o", "x", "x", "x", "o", "o"},
			{"o", "x", "o", "o", "o", "o"},
		},
		StartPos: position.Position{
			X: 0,
			Y: 0,
		},
		GoalPos: position.Position{
			X: 5, // Width - 1
			Y: 5, // Height - 1
		},
	}
)
