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

// ConfirmSignupハンドラ関数
func ConfirmSignupHandler(w http.ResponseWriter, r *http.Request) {
	// リクエストボディの構造体を定義（メールアドレスと確認コードを受け取る）
	var req struct {
		Email            string `json:"email"`
		ConfirmationCode string `json:"confirmation_code"`
	}

	// JSONデコード処理（失敗した場合は400エラーを返す）
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "リクエストの形式が不正です", http.StatusBadRequest)
		return
	}

	// 環境変数からCognitoのクライアントIDとシークレットを取得
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")

	// 確認コードをCognitoに送信してサインアップを確定
	_, err := auth.ConfirmCode(clientID, clientSecret, req.Email, req.ConfirmationCode)
	if err != nil {
		http.Error(w, "確認コードの検証に失敗しました", http.StatusBadRequest)
		return
	}

	// 成功時のレスポンスをJSON形式で返す
	response := map[string]string{
		"message": "サインアップの確認が完了しました",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
