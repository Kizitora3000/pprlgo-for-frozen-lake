package agent

import (
	"fmt"
	"math/rand"
	"pprlgoFrozenLake/doublenc"
	"pprlgoFrozenLake/environment"
	"pprlgoFrozenLake/party"
	"pprlgoFrozenLake/position"
	"pprlgoFrozenLake/pprl"
	"pprlgoFrozenLake/utils"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Agent struct {
	actionNum  int
	stateNum   int
	lakeHeight int
	lakeWidth  int
	InitValQ   float64
	Epsilon    float64
	Alpha      float64
	Gamma      float64
	Qtable     [][]float64 // Qテーブルの状態は1次元とする (状態をposition.Positionにすると暗号化時に処理できない)
}

const (
	INITIAL_VAL_Q = 0
	EPSILON       = 0.1
	ALPHA         = 0.1
	GAMMA         = 0.9
)

func NewAgent(env *environment.Environment) *Agent {
	actionNum := len(env.ActionSpace)
	stateNum := env.Height() * env.Width()
	lakeHeight := env.Height()
	lakeWidth := env.Width()

	// Qtable[stateNum][actionNum]の二次元配列を作成してInitValQで初期化
	Qtable := make([][]float64, stateNum)
	for i := range Qtable {
		Qtable[i] = make([]float64, actionNum)
		for j := range Qtable[i] {
			Qtable[i][j] = INITIAL_VAL_Q
		}
	}

	return &Agent{
		actionNum:  actionNum,
		stateNum:   stateNum,
		lakeHeight: lakeHeight,
		lakeWidth:  lakeWidth,
		InitValQ:   INITIAL_VAL_Q,
		Epsilon:    EPSILON,
		Alpha:      ALPHA,
		Gamma:      GAMMA,
		Qtable:     Qtable,
	}
}

func (a *Agent) QtableReset(env *environment.Environment) {
	// Qtable[stateNum][actionNum]の二次元配列を作成してInitValQで初期化
	for i := range a.Qtable {
		a.Qtable[i] = make([]float64, a.actionNum)
		for j := range a.Qtable[i] {
			a.Qtable[i][j] = INITIAL_VAL_Q
		}
	}
}

func (e *Agent) Learn(state position.Position, act int, rwd int, next_state position.Position, keyTools party.BfvKeyTools, encryptedQtable []*rlwe.Ciphertext) {
	state_1D := e.convert2DTo1D(state)
	next_state_1D := e.convert2DTo1D(next_state)

	target := float64(0)
	target = float64(rwd) + e.Gamma*e.maxValue(e.Qtable[next_state_1D]) // rwdは整数値なので実数値にキャストする

	e.Qtable[state_1D][act] = (1-e.Alpha)*e.Qtable[state_1D][act] + e.Alpha*target

	v_t := make([]uint64, e.stateNum)
	w_t := make([]uint64, e.actionNum)
	v_t[state_1D] = 1
	w_t[act] = 1

	Qnew := e.Qtable[state_1D][act]
	Qnew_int := int64(Qnew * utils.Q_int_coeff)
	Q_new_uint64 := utils.MapInteger(int64(Qnew_int))
	pprl.SecureQtableUpdatingWithBFV(keyTools.Params, keyTools.Encoder, keyTools.Encryptor, keyTools.Decryptor, keyTools.Evaluator, keyTools.PublicKey, keyTools.PrivateKey, v_t, w_t, Q_new_uint64, e.stateNum, e.actionNum, encryptedQtable)
}

func (e *Agent) maxValue(slice []float64) float64 {
	maxValue := slice[0]
	for _, v := range slice {
		if v > maxValue {
			maxValue = v
		}
	}
	return maxValue
}

// Qテーブルの状態(1次元)に格納するため，二次元座標を一次元インデックスに変換
func (e *Agent) convert2DTo1D(state position.Position) int {
	return state.Y*e.lakeWidth + state.X
}

// ランダムに行動を選択
func (a *Agent) ChooseRandomAction() int {
	return rand.Intn(a.actionNum) // 0からactionNum-1までの範囲でランダムに整数を返す
}

// εグリーディー方策
func (a *Agent) EpsilonGreedyAction(state position.Position) int {
	state_1D := a.convert2DTo1D(state)

	// εより小さいランダムな値を生成してランダムに行動を選択
	if rand.Float64() < a.Epsilon {
		return a.ChooseRandomAction()
	}

	// 最大のQ値を持つ行動を選択
	maxAction := 0
	maxQValue := a.Qtable[state_1D][0]
	for action, qValue := range a.Qtable[state_1D] {
		if qValue > maxQValue {
			maxAction = action
			maxQValue = qValue
		}
	}

	return maxAction
}

// εグリーディー方策(クラウド上のQテーブルから選択)
func (a *Agent) SecureEpsilonGreedyAction(state position.Position, keyTools party.BfvKeyTools, encryptedQtable []*rlwe.Ciphertext) int {
	// εより小さいランダムな値を生成してランダムに行動を選択
	if rand.Float64() < a.Epsilon {
		return a.ChooseRandomAction()
	}

	state_1D := a.convert2DTo1D(state)
	v_t := make([]float64, a.stateNum)
	v_t[state_1D] = 1

	// 最大のQ値を持つ行動を選択
	// actions_Q_in_state := pprl.SecureActionSelection(v_t, a.stateNum, a.actionNum, testContext, encryptedQtable, user_list)
	actions_Q_in_state := pprl.SecureActionSelectionWithBFV(keyTools.Params, keyTools.Encoder, keyTools.Encryptor, keyTools.Decryptor, keyTools.Evaluator, keyTools.PublicKey, keyTools.PrivateKey, v_t, a.stateNum, a.actionNum, encryptedQtable)
	actions_Q_in_state_msg := doublenc.BFVdec(keyTools.Params, keyTools.Encoder, keyTools.Decryptor, actions_Q_in_state)

	actions_Q_in_state_float64 := make([]float64, a.actionNum)

	// [0, 2N] -> [-N, N] +  係数の除去
	for idx := 0; idx < a.actionNum; idx++ {
		Q_new_int64 := utils.UnmapInteger(actions_Q_in_state_msg[idx])
		actions_Q_in_state_float64[idx] = float64(Q_new_int64) / utils.Q_int_coeff
	}

	maxAction := 0
	maxQValue := actions_Q_in_state_float64[0]

	for idx := 0; idx < a.actionNum; idx++ {
		qValue := actions_Q_in_state_float64[idx]
		if qValue > maxQValue {
			maxAction = idx
			maxQValue = qValue
		}
	}

	return maxAction
}

// 貪欲方策
func (a *Agent) GreedyAction(state position.Position) int {
	state_1D := a.convert2DTo1D(state)

	// 最大のQ値を持つ行動を選択
	maxAction := 0
	maxQValue := a.Qtable[state_1D][0]
	for action, qValue := range a.Qtable[state_1D] {
		if qValue > maxQValue {
			maxAction = action
			maxQValue = qValue
		}
	}

	return maxAction
}

func (a *Agent) ShowQTable() {
	// 行動インデックスに対応する方向の文字列
	actionSymbols := map[int]string{
		0: "↑",
		1: "↓",
		2: "←",
		3: "→",
	}

	fmt.Println("Qtable:")

	for stateIndex, actions := range a.Qtable {
		// 状態を二次元座標に変換して表示
		stateY := stateIndex / a.lakeWidth
		stateX := stateIndex % a.lakeWidth
		fmt.Printf("State [Y: %d, X: %d]: ", stateY, stateX)

		for actionIndex, qValue := range actions {
			// actionIndex を方向の文字列に変換して表示
			actionSymbol := actionSymbols[actionIndex]
			fmt.Printf("%s: %.2f ", actionSymbol, qValue)
		}
		fmt.Println()
	}
}

func (a *Agent) ShowOptimalPath(env *environment.Environment) {
	currentState := env.Reset() // 環境をリセットしてスタート位置を取得
	fmt.Println("Optimal Path: ")

	// 行動インデックスに対応する方向の文字列
	actionSymbols := map[int]string{
		0: "↑",
		1: "↓",
		2: "←",
		3: "→",
	}

	for {
		action := a.GreedyAction(currentState)

		// 最適な行動に基づいて次の状態を決定
		nextState := env.NextState(currentState, action)

		// 経路を出力
		if currentState == env.StartPos {
			fmt.Println("START")
		}
		fmt.Printf("state: %s,  action: %s\n", currentState, actionSymbols[action])
		currentState = nextState

		if currentState == env.GoalPos {
			fmt.Println("GOAL")
			break // ゴールに到達したらループを終了
		}
	}
}

func (e *Agent) GetActionNum() int {
	return e.actionNum
}

func (e *Agent) GetStateNum() int {
	return e.stateNum
}
