package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// SECRET_HASH を計算する関数
func calculateSecretHash(clientSecret, username, clientID string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Cognitoに新規ユーザーを登録する関数
func Signup(
	clientID string,
	clientSecret string,
	email string,
	password string,
) (*cognitoidentityprovider.SignUpOutput, error) {

	// AWSセッションを作成
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-1"),
	}))
	svc := cognitoidentityprovider.New(sess)

	// クライアントシークレットを用いてSecretHashを計算
	secretHash := calculateSecretHash(clientSecret, email, clientID)

	// サインアップ用のリクエストを作成
	input := &cognitoidentityprovider.SignUpInput{
		ClientId:   aws.String(clientID),
		Username:   aws.String(email),
		Password:   aws.String(password),
		SecretHash: aws.String(secretHash),
		UserAttributes: []*cognitoidentityprovider.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(email),
			},
		},
	}

	// Cognitoにサインアップリクエストを送信
	result, err := svc.SignUp(input)
	if err != nil {
		return nil, err
	}

	// 結果を返却
	return result, nil
}

// メールに送信された確認コードを使って、Cognitoでユーザーを有効化する関数
func ConfirmCode(
	clientID string,
	clientSecret string,
	email string,
	confirmationCode string,
) (*cognitoidentityprovider.ConfirmSignUpOutput, error) {
	// AWSセッションを初期化（リージョンは東京）
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-1"),
	}))

	// Cognitoクライアントを作成
	svc := cognitoidentityprovider.New(sess)

	// シークレットハッシュを計算
	secretHash := calculateSecretHash(clientSecret, email, clientID)

	// 確認コードとユーザー情報を設定
	input := &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         aws.String(clientID),
		Username:         aws.String(email),
		ConfirmationCode: aws.String(confirmationCode),
		SecretHash:       aws.String(secretHash),
	}

	// サインアップ確認を実行
	result, err := svc.ConfirmSignUp(input)
	if err != nil {
		return nil, err
	}

	// 結果を返す
	return result, nil
}

// Cognitoでユーザーのログインを行い、アクセストークンを取得する関数
func Login(clientID string, clientSecret string, email string, password string) (*cognitoidentityprovider.AuthenticationResultType, error) {
	// AWSセッションを初期化（リージョンは東京）
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-1"),
	}))

	// Cognitoクライアントを作成
	svc := cognitoidentityprovider.New(sess)

	// シークレットハッシュを計算
	secretHash := calculateSecretHash(clientSecret, email, clientID)

	// ログイン情報を設定
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		ClientId: aws.String(clientID),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(email),
			"PASSWORD":    aws.String(password),
			"SECRET_HASH": aws.String(secretHash),
		},
	}

	// Cognitoで認証を実行
	resp, err := svc.InitiateAuth(input)
	if err != nil {
		return nil, err
	}

	// 結果を返す
	return resp.AuthenticationResult, nil
}
