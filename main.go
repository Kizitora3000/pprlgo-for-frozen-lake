package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	mrand "math/rand" // crypto/randとの名前衝突を避けるためmath/randにエイリアスmrandを適用
	"os"
	"pprlgoFrozenLake/agent"
	"pprlgoFrozenLake/doublenc"
	"pprlgoFrozenLake/environment"
	"pprlgoFrozenLake/frozenlake"
	"pprlgoFrozenLake/party"
	"pprlgoFrozenLake/utils"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	EPISODES   = 200
	MAX_USERS  = 2             // MAX_USERS = cloud + agents
	MAX_AGENTS = MAX_USERS - 1 // agents = MAX_USERS - cloud
	MAX_TRIALS = 4
)

func main() {
	// agent.ChooseRandomAction()やagent.EpsilonGreedyAction()で使用する乱数値を固定
	// 補足：rand.Seedはグローバルな乱数生成器のため、意図せず他のプログラムの乱数生成も固定してしまう可能性がある
	// 　　　rand.New(rand.NewSource(0))はローカルな乱数生成器のため、プログラムごとに乱数生成を固定でき、他のプログラムに影響を与えない
	// 　　　しかし、今回はプログラム全体で乱数を固定したいので、rand.Seedを使用する
	mrand.Seed(0)

	// コマンドライン引数でマップのサイズを指定
	map_size := flag.String("s", "", "Size of the Frozen Lake map (options: 4x4, 5x5, 6x6)")
	flag.Parse()

	// `s`オプションが指定されているかチェック。指定されていなければ終了
	if *map_size == "" {
		fmt.Println("Error: The -s option is required.")
		os.Exit(1)
	}

	var lake frozenlake.FrozenLake
	switch *map_size {
	case "3x3":
		lake = frozenlake.FrozenLake3x3
	case "4x4":
		lake = frozenlake.FrozenLake4x4
	case "5x5":
		lake = frozenlake.FrozenLake5x5
	case "6x6":
		lake = frozenlake.FrozenLake6x6
	default:
		fmt.Println("Invalid map size. Please choose from 4x4, 5x5, or 6x6.")
		os.Exit(1)
	}

	environments := make([]*environment.Environment, MAX_AGENTS)
	agents := make([]*agent.Agent, MAX_AGENTS)

	for i := 0; i < MAX_AGENTS; i++ {
		environments[i] = environment.NewEnvironment(lake)
		agents[i] = agent.NewAgent(environments[i])
	}
	Agt := agents[0]
	Env := environments[0]

	// --- set up for Result
	success_rate_filename := fmt.Sprintf("PPRL_success_rate_%dx%d.csv", Env.Height(), Env.Width())
	file, err := os.Create(success_rate_filename)
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Episode", "Success Rate"}) // 表頭を記入

	eval_rate_filename := fmt.Sprintf("PPRL_eval_greedy_success_rate_%dx%d.csv", Env.Height(), Env.Width())
	// ファイルが存在する場合は削除 (eval_success_rateはeval関数が呼ばれるたびに追記していく形式なので、プログラム開始時は削除する)
	if _, err := os.Stat(eval_rate_filename); err == nil {
		if err := os.Remove(eval_rate_filename); err != nil {
			panic(err)
		}
	}

	// --- set up for bfv
	params, err := bfv.NewParametersFromLiteral(utils.FAST_BUT_NOT_128_SECURITY) // bfv.PN15QP880 // utils.FAST_BUT_NOT_128_SECURITY
	if err != nil {
		panic(err)
	}

	// キージェネレータ、エンコーダ、暗号化器、評価器、復号器の生成
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder := bfv.NewEncoder(params)
	encryptor := bfv.NewEncryptor(params, pk)
	decryptor := bfv.NewDecryptor(params, sk)
	rlk := kgen.GenRelinearizationKey(sk, 1)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	bfvKeyTools := party.BfvKeyTools{
		Params:     params,
		Encryptor:  encryptor,
		Decryptor:  decryptor,
		Encoder:    encoder,
		Evaluator:  evaluator,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// ---PPRL ---
	var success_rate_per_episode = make([][]float64, MAX_TRIALS)
	for trial := 0; trial < MAX_TRIALS; trial++ {
		goal_count := 0.0
		all_agt_eps := 0 // 各エージェントの試行回数の総計

		for agent_idx := 0; agent_idx < MAX_AGENTS; agent_idx++ {
			agents[agent_idx].QtableReset(environments[agent_idx])
		}

		// 試行ごとにクラウドのQ値を初期化
		// 各エージェントの状態数・行動数は同一のため、いずれのagentsを用いて初期化しても問題ない。今回は代表としてagents[0]を使用する
		encryptedQtable := make([]*rlwe.Ciphertext, Agt.GetStateNum())
		for i := 0; i < Agt.GetStateNum(); i++ {
			plaintext := make([]uint64, Agt.GetActionNum())
			for i := range plaintext {
				plaintext[i] = 0 // Agt.InitValQ
			}

			ciphertext := doublenc.BFVenc(params, encoder, encryptor, plaintext)
			encryptedQtable[i] = ciphertext
		}

		for episode := 0; episode <= EPISODES; episode++ {
			// 学習の進捗率を表示
			progress := float64(episode) / float64(EPISODES) * 100
			fmt.Printf("\rTraining Progress (Trial - %d/%d): %.1f%% (%d/%d)", trial, MAX_TRIALS, progress, episode, EPISODES)

			for agent_idx := 0; agent_idx < MAX_AGENTS; agent_idx++ {
				env := environments[agent_idx]
				agt := agents[agent_idx]

				state := env.Reset()
				for {
					action := agt.SecureEpsilonGreedyAction(state, bfvKeyTools, encryptedQtable)

					next_state, reward, done := env.Step(action)
					agt.Learn(state, action, reward, next_state, bfvKeyTools, encryptedQtable)

					if done {
						if next_state == env.GoalPos {
							goal_count++
						}
						all_agt_eps++

						break
					}
					state = next_state
				}

				// 成功率を算出してcsvに出力
				goal_rate := goal_count / float64(all_agt_eps)
				writer.Write([]string{fmt.Sprintf("%d", int(episode)), fmt.Sprintf("%.2f", goal_rate)})

				/*
					if episode%4 == 0 {
						evaluateGreedyActionAtEpisodes(episode, env, agt)
					}
				*/
				success_rate_per_episode[trial] = append(success_rate_per_episode[trial], goal_rate)
			}
		}
	}

	// 成功率の平均値を計算
	average_success_rates := make([]float64, EPISODES+1)
	fmt.Println(len(success_rate_per_episode))
	for _, goal_rates := range success_rate_per_episode {
		for episode, goal_rate := range goal_rates {
			average_success_rates[episode] += goal_rate / float64(MAX_TRIALS)
		}
	}

	// 平均成功率をCSVに書き出す
	average_successl_rate_filename := fmt.Sprintf("PPRL_average_success_rate_%dx%d.csv", environments[0].Height(), environments[0].Width())
	average_file, err := os.Create(average_successl_rate_filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	average_writer := csv.NewWriter(average_file)
	defer average_writer.Flush()

	// ヘッダーを書き込む
	average_writer.Write([]string{"Episode", "Average Success Rate"})

	// データを書き込む
	for episode, average_success_rate := range average_success_rates {
		average_writer.Write([]string{fmt.Sprintf("%d", episode), fmt.Sprintf("%.2f", average_success_rate)})
	}

	fmt.Println()

	// その他デバッグ情報の表示
	agents[0].ShowQTable()
	// agents[0].ShowOptimalPath(environments[0])
	// ShowDecryptedQTable(agents[0], encryptedQtable, bfvKeyTools.Params, bfvKeyTools.Encoder, bfvKeyTools.Decryptor)
	// fmt.Println(calcMSE(agents[0], encryptedQtable, bfvKeyTools.Params, bfvKeyTools.Encoder, bfvKeyTools.Decryptor))
}

func calcMSE(agt *agent.Agent, encryptedQtable []*rlwe.Ciphertext, params bfv.Parameters, encoder bfv.Encoder, decryptor rlwe.Decryptor) float64 {
	// 復号されたQテーブルを格納するための変数
	decryptedQtable := make([][]float64, agt.GetStateNum())

	// 復号されたQテーブルの初期化
	for i := range decryptedQtable {
		decryptedQtable[i] = make([]float64, agt.GetActionNum())
	}

	// encryptedQtableの復号
	for i, encryptedValue := range encryptedQtable {
		decryptedMessage := doublenc.BFVdec(params, encoder, decryptor, encryptedValue)
		for j := 0; j < agt.GetActionNum(); j++ {
			// decryptedQtable[i][j] = float64(decryptedMessage[j])
			Q_new_int64 := utils.UnmapInteger(decryptedMessage[j])
			decryptedQtable[i][j] = float64(Q_new_int64) / utils.Q_int_coeff
		}
	}

	// MSEの計算
	var mse float64
	for i := range agt.Qtable {
		for j := range agt.Qtable[i] {
			diff := agt.Qtable[i][j] - float64(decryptedQtable[i][j])
			mse += diff * diff
		}
	}
	mse /= float64(agt.GetStateNum() * agt.GetActionNum())

	return mse
}

func ShowDecryptedQTable(agt *agent.Agent, encryptedQtable []*rlwe.Ciphertext, params bfv.Parameters, encoder bfv.Encoder, decryptor rlwe.Decryptor) {
	// 暗号化されたQテーブルの各要素を復号して表示
	fmt.Println("Decrypted Qtable:")
	for i, encryptedValue := range encryptedQtable {
		// ここで復号プロセスを実行
		decryptedValue := doublenc.BFVdec(params, encoder, decryptor, encryptedValue)
		decryptedValue_float64 := make([]float64, 4)

		// [0, 2N] -> [-N, N] +  係数の除去
		for j := 0; j < 4; j++ {
			Q_new_int64 := utils.UnmapInteger(decryptedValue[j])
			decryptedValue_float64[j] = float64(Q_new_int64) / utils.Q_int_coeff
		}
		// 復号された値を表示
		height := int(math.Sqrt(float64(agt.GetStateNum())))
		x := i % height
		y := i / height
		fmt.Printf("State [Y: %d, X: %d]: %f\n", y, x, decryptedValue_float64)
	}
}

func evaluateGreedyActionAtEpisodes(now_episode int, env *environment.Environment, agt *agent.Agent) {
	// ファイルを追記モードで開く（ファイルが存在しない場合は新しく作成）
	eval_rate_filename := fmt.Sprintf("PPRL_eval_greedy_success_rate_%dx%d.csv", env.Height(), env.Width())
	file, err := os.OpenFile(eval_rate_filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// ファイルが空（新規作成されたばかり）の場合、ヘッダーを書き込む
	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	if fileInfo.Size() == 0 {
		writer.Write([]string{"Episode", "Success Rate"}) // 表頭を記入
	}

	goal_count := 0 // エピソードでのゴール到達回数をカウント
	trials := 100   // 評価のために各エピソードを何回実行するか

	for i := 0; i < trials; i++ {
		state := env.Reset()
		cnt := 0
		for {
			action := agt.GreedyAction(state) // 学習済みのQテーブルを使用して最適な行動を選択
			next_state, _, done := env.Step(action)

			if done {
				if next_state == env.GoalPos {
					goal_count++
				}
				break
			}

			if cnt > 100 {
				break
			}

			state = next_state
			cnt++
		}
	}

	goalRate := float64(goal_count) / float64(trials) * 100.0
	// fmt.Printf("Greedy Action Goal Rate: %.2f%%\n", goalRate)

	writer.Write([]string{fmt.Sprintf("%d", int(now_episode)), fmt.Sprintf("%.2f", goalRate)})
}
