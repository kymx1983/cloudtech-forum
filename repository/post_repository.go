package repository

import (
	"cloudtech-forum/model"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

// 投稿の新規登録
func CreatePost(content string, createdUserID int) (int, error) {
	// SQLを定義
	query := "INSERT INTO posts (content, user_id) VALUES (?, ?)"

	// INSERTのSQLを実行
	result, err := db.Exec(query, content, createdUserID)
	if err != nil {
		// エラーログの出力
		log.Printf("投稿の新規登録に失敗しました: %v", err)
		return 0, fmt.Errorf("投稿の新規登録に失敗しました: %w", err)
	}

	// 新規登録されたレコードのIDを取得
	id, err := result.LastInsertId()
	if err != nil {
		// エラーログの出力
		log.Printf("新規登録IDの取得に失敗しました: %v", err)
		return 0, fmt.Errorf("新規登録IDの取得に失敗しました: %w", err)
	}

	// IDを返却
	return int(id), nil
}

// 投稿の一覧検索
func SearchPostAll() ([]model.Post, error) {
	// SQLを定義
	query := "SELECT id, content, user_id, created_at, updated_at FROM posts"

	// SELECTのSQLを実行
	rows, err := db.Query(query)
	if err != nil {
		// エラーログの出力
		log.Printf("投稿の一覧検索に失敗しました: %v", err)
		return nil, fmt.Errorf("投稿の一覧検索に失敗しました: %w", err)
	}

	// rowsをclose
	defer rows.Close()

	// 一覧データを格納するスライスを定義
	var posts []model.Post

	// 一覧データを読み取りスライスに登録
	for rows.Next() {
		var post model.Post
		err := rows.Scan(&post.ID, &post.Content, &post.UserID, &post.CreatedAt, &post.UpdatedAt)
		if err != nil {
			// エラーログの出力
			log.Printf("投稿データの読み取りに失敗しました: %v", err)
			return nil, fmt.Errorf("投稿データの読み取りに失敗しました: %w", err)
		}
		posts = append(posts, post)
	}

	// 投稿データの一覧を返却
	return posts, nil
}

// 投稿の詳細検索
func SearchPost(id int) (model.Post, error) {
	// 検索結果を格納する構造体を定義
	var post model.Post

	// SQLを定義
	query := "SELECT id, content, user_id, created_at, updated_at FROM posts WHERE id = ?"

	// SELECTのSQLを実行
	row := db.QueryRow(query, id)

	// 読み込んだデータを、postの各フィールドに格納
	err := row.Scan(&post.ID, &post.Content, &post.UserID, &post.CreatedAt, &post.UpdatedAt)
	if err != nil {
		// エラーログの出力
		log.Printf("投稿の詳細検索に失敗しました: %v", err)
		return post, fmt.Errorf("投稿の詳細検索に失敗しました: %w", err)
	}

	// 読み込んだ投稿データを返却
	return post, nil
}

// 投稿の更新
func UpdatePost(id int, content string, createdUserID int) (int64, error) {
	// SQLを定義
	query := "UPDATE posts SET content = ?, user_id = ? WHERE id = ?"

	// UPDATEのSQLを実行
	result, err := db.Exec(query, content, createdUserID, id)
	if err != nil {
		// エラーログの出力
		log.Printf("投稿の更新に失敗しました: %v", err)
		return 0, fmt.Errorf("投稿の更新に失敗しました: %w", err)
	}

	// 影響を受けた行数を取得
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// エラーログの出力
		log.Printf("影響を受けた行数の取得に失敗しました: %v", err)
		return 0, fmt.Errorf("影響を受けた行数の取得に失敗しました: %w", err)
	}

	// 影響を受けた行数を返す
	return rowsAffected, nil
}

// 投稿の削除
func DeletePost(id int) (int64, error) {
	// SQLを定義
	query := "DELETE FROM posts WHERE id = ?"

	// DELETEのSQLを実行
	result, err := db.Exec(query, id)
	if err != nil {
		// エラーログの出力
		log.Printf("投稿の削除に失敗しました: %v", err)
		return 0, fmt.Errorf("投稿の削除に失敗しました: %w", err)
	}

	// 影響を受けた行数を取得
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// エラーログの出力
		log.Printf("影響を受けた行数の取得に失敗しました: %v", err)
		return 0, fmt.Errorf("影響を受けた行数の取得に失敗しました: %w", err)
	}

	// 影響を受けた行数を返す
	return rowsAffected, nil
}
