package handler

import (
	auth "cloudtech-forum/util"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	// リクエストボディで受け取る項目を定義
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	// リクエストボディの情報を読み取る
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "リクエストの形式が不正です", http.StatusBadRequest)
		return
	}

	// CognitoのクライアントIDとシークレットを環境変数から取得
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")

	// サインアップ処理を実行
	result, err := auth.Signup(clientID, clientSecret, req.Email, req.Password)
	if err != nil {
		log.Println("Signupエラー:", err)
		http.Error(w, "サインアップに失敗しました", http.StatusInternalServerError)
		return
	}

	// ユーザー作成に成功した場合は201 Createdを返す
	w.WriteHeader(http.StatusCreated)

	// 成功メッセージを返す
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ユーザー登録が完了しました",
		"userSub": *result.UserSub, // Cognitoが返すユーザーIDを含める（任意）
	})
}
