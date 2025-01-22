package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db       *sql.DB
	idLock   = &sync.Mutex{}
	upgrader = websocket.Upgrader{}
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Room struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"user_id"`       
	RoomID       int64  `json:"room_id"`       
	RoomName     string `json:"room_name"`     
	RoomPassword string `json:"room_password"` 
}

type RoomUser struct {
	RoomID int    `json:"room_id"`
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type Document struct {
	RoomID  int    `json:"room_id"`
	UserID  int    `json:"user_id"`
	Version string `json:"version"`
	Content string `json:"content"`
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

func initDB() {
	var err error
	connStr := "host=localhost user=admin password=123 dbname=test port=5432 sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка при подключении к базе данных:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Ошибка пинга:", err)
	}

	// clearAllTables()

	initUsersTable()
	initRoomsTable()
	initRoomUsersTable()
	initDocumentVersionsTable()
}

func initUsersTable() {
	query := `
    CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
				email VARCHAR(255) NOT NULL,
				password VARCHAR(255) NOT NULL
    );
    `

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Ошибка при создании таблицы users:", err)
	} else {
		log.Println("Таблица users успешно создана или уже существует.")
	}
}


func initRoomsTable() {
	query := `
    CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        room_id SERIAL UNIQUE NOT NULL,
        room_name VARCHAR(255) NOT NULL,
        room_password VARCHAR(255),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    `

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Ошибка при создании таблицы rooms:", err)
	} else {
		log.Println("Таблица rooms успешно создана или уже существует.")
	}
}

func initRoomUsersTable() {
	query := `
    CREATE TABLE IF NOT EXISTS room_users (
        room_id INT NOT NULL,
        user_id INT NOT NULL,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(50),
        FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        PRIMARY KEY (room_id, user_id)
    );
    `

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Ошибка при создании таблицы room_users:", err)
	} else {
		log.Println("Таблица room_users успешно создана или уже существует.")
	}
}

func initDocumentVersionsTable() {
	query := `
    CREATE TABLE IF NOT EXISTS document_versions (
        room_id INT NOT NULL,
        version VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (room_id, version),
        FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
    );
    `

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Ошибка при создании таблицы document_versions:", err)
	} else {
		log.Println("Таблица document_versions успешно создана или уже существует.")
	}
}

func clearAllTables() {
	rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
	if err != nil {
		log.Fatal("Ошибка при получения списка таблиц:", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			log.Fatal("Ошибка при сканировании имени таблицы:", err)
		}
		tables = append(tables, tableName)
	}

	if len(tables) > 0 {
		truncateQuery := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE;"
		_, err = db.Exec(truncateQuery)
		if err != nil {
			log.Fatal("Ошибка при чистке таблиц:", err)
		} else {
			log.Println("Все таблицы успешно очищены и счетчики сброшены.")
		}
	} else {
		log.Println("Нет таблиц для очистки.")
	}
}

func userExists(email string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&exists)
	if err != nil {
		log.Println("Ошибка при проверке существования пользователя:", err)
		return false
	}
	return exists
}

func createUser(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
			return 
	}

	if r.Method != http.MethodPost {
			http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
			return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Ошибка декодирования: "+err.Error(), http.StatusBadRequest)
			return
	}

	log.Printf("Received user data: %+v", user) 

	if user.Email == "" || user.Password == "" {
			http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
			return
	}

	if userExists(user.Email) {
			http.Error(w, "Пользователь с таким email уже существует", http.StatusConflict)
			return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
			http.Error(w, "Ошибка при хэшировании пароля: "+err.Error(), http.StatusInternalServerError)
			return
	}
	user.Password = string(hash)

	idLock.Lock()
	defer idLock.Unlock()

	err = db.QueryRow("INSERT INTO users(email, password) VALUES($1, $2) RETURNING id",
			user.Email, user.Password).Scan(&user.ID)
	if err != nil {
			http.Error(w, "Ошибка при создании пользователя: "+err.Error(), http.StatusInternalServerError)
			return
	}

	response := map[string]string{"message": "Пользователь успешно зарегистрирован", "redirect": "/account"}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Ошибка декодирования: "+err.Error(), http.StatusBadRequest)
		return
	}

	if user.Email == "" || user.Password == "" {
		http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
		return
	}

	var storedUser User
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", user.Email).Scan(
		&storedUser.ID, &storedUser.Email, &storedUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Ошибка при получении данных: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"message": "Успешный вход в систему",
		"userId":  storedUser.ID,
		"email":   storedUser.Email,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func createRoom(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
			return 
	}

	if r.Method != http.MethodPost {
			http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
			return
	}

	var room Room
	if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
			http.Error(w, "Ошибка декодирования: "+err.Error(), http.StatusBadRequest)
			return
	}

	if room.UserID == 0 || room.RoomName == "" {
			http.Error(w, "ID пользователя и название комнаты не могут быть пустыми", http.StatusBadRequest)
			return
	}

	if room.RoomPassword != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(room.RoomPassword), bcrypt.DefaultCost)
			if err != nil {
					http.Error(w, "Ошибка при хэшировании пароля: "+err.Error(), http.StatusInternalServerError)
					return
			}
			room.RoomPassword = string(hash)
	}

	var userEmail string
	err := db.QueryRow("SELECT email FROM users WHERE id = $1", room.UserID).Scan(&userEmail)
	if err != nil {
			http.Error(w, "Ошибка при получения Email пользователя: "+err.Error(), http.StatusInternalServerError)
			return
	}

	err = db.QueryRow(
			"INSERT INTO rooms(user_id, room_name, room_password) VALUES($1, $2, $3) RETURNING id",
			room.UserID, room.RoomName, room.RoomPassword,
	).Scan(&room.ID)

	if err != nil {
			http.Error(w, "Ошибка при создании комнаты: "+err.Error(), http.StatusInternalServerError)
			return
	}

	_, err = db.Exec(
			"INSERT INTO room_users(room_id, user_id, email, role) VALUES($1, $2, $3, $4)",
			room.ID, room.UserID, userEmail, "owner", 
	)

	if err != nil {
			http.Error(w, "Ошибка при добавлении пользователя в комнату: "+err.Error(), http.StatusInternalServerError)
			return
	}

	response := map[string]interface{}{
			"message":  "Комната успешно создана",
			"roomId":   room.ID,
			"roomName": room.RoomName,
			"userId":   room.UserID,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func joinRoom(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
			return 
	}

	if r.Method != http.MethodPost {
			http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
			return
	}

	var room struct {
			RoomName     string `json:"room_name"`
			RoomPassword string `json:"room_password"`
			UserID       int    `json:"user_id"`
			UserEmail    string `json:"user_email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
			http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
			return
	}

	if room.RoomName == "" || room.RoomPassword == "" {
			http.Error(w, "Название комнаты и пароль не могут быть пустыми", http.StatusBadRequest)
			return
	}

	var storedRoom struct {
			ID           int
			RoomPassword string
	}

	err := db.QueryRow("SELECT id, room_password FROM rooms WHERE room_name = $1", room.RoomName).Scan(&storedRoom.ID, &storedRoom.RoomPassword)

	if err != nil {
			if err == sql.ErrNoRows {
					http.Error(w, "Комната не найдена", http.StatusUnauthorized)
					return
			}
			http.Error(w, "Ошибка при получении данных: "+err.Error(), http.StatusInternalServerError)
			return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedRoom.RoomPassword), []byte(room.RoomPassword))
	if err != nil {
			http.Error(w, "Неверный пароль", http.StatusUnauthorized)
			return
	}

	var userInRoomID int
	err = db.QueryRow("SELECT user_id FROM room_users WHERE room_id = $1 AND user_id = $2", storedRoom.ID, room.UserID).Scan(&userInRoomID)

	if err == sql.ErrNoRows {
			_, err = db.Exec("INSERT INTO room_users(room_id, user_id, email, role) VALUES($1, $2, $3, $4)", storedRoom.ID, room.UserID, room.UserEmail, "reader")
			if err != nil {
					http.Error(w, "Ошибка при добавлении пользователя в комнату: "+err.Error(), http.StatusInternalServerError)
					return
			}
	} else if err != nil {
			http.Error(w, "Ошибка при проверке существования пользователя: "+err.Error(), http.StatusInternalServerError)
			return
	}

	response := map[string]interface{}{
			"message":  "Успешное присоединение к комнате",
			"roomId":   storedRoom.ID,
			"roomName": room.RoomName,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getRoomUsers(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return 
	}

	roomIdStr := r.URL.Query().Get("roomId")
	if roomIdStr == "" {
		http.Error(w, "Отсутствует ID комнаты", http.StatusBadRequest)
		return
	}

	roomId, err := strconv.Atoi(roomIdStr)
	if err != nil {
		http.Error(w, "Ошибка изменения ID комнаты: "+err.Error(), http.StatusBadRequest)
		return
	}

	rows, err := db.Query(`
        SELECT user_id, email, role 
        FROM room_users 
        WHERE room_id = $1`, roomId)

	if err != nil {
		http.Error(w, "Ошибка получения данных о пользователях: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []RoomUser
	for rows.Next() {
		var user RoomUser
		if err := rows.Scan(&user.UserID, &user.Email, &user.Role); err != nil {
			http.Error(w, "Ошибка сканирования данных: "+err.Error(), http.StatusInternalServerError)
			return
		}
		user.RoomID = roomId
		users = append(users, user)
	}

	log.Println("Пользователи в комнате:", users)

	response := map[string]interface{}{
		"users": users,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func updateUserRole(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return 
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		UserID int    `json:"user_id"`
		Role   string `json:"role"`
		RoomID int    `json:"room_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Обновление роли пользователя ID %d на %s в комнате ID %d\n", data.UserID, data.Role, data.RoomID)

	_, err := db.Exec(`
        UPDATE room_users 
        SET role = $1 
        WHERE user_id = $2 AND room_id = $3`, data.Role, data.UserID, data.RoomID)

	if err != nil {
		http.Error(w, "Ошибка обновления роли пользователя: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func saveDocument(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	var doc Document

	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		http.Error(w, "Ошибка декодирования: "+err.Error(), http.StatusBadRequest)
		return
	}

	var lastVersion string
	err := db.QueryRow("SELECT version FROM document_versions WHERE room_id = $1 ORDER BY created_at DESC LIMIT 1", doc.RoomID).Scan(&lastVersion)

	var newVersion string
	userIDStr := fmt.Sprintf("%d", doc.UserID)

	var lastVersionNum int

	if err == sql.ErrNoRows {
		newVersion = fmt.Sprintf("%s.1", userIDStr)
		lastVersionNum = 1
	} else if err != nil {
		http.Error(w, "Ошибка получения последней версии документа: "+err.Error(), http.StatusInternalServerError)
		return
	} else {
		parts := strings.Split(lastVersion, ".")
		
		if len(parts) == 2 {
			lastVersionNum, _ = strconv.Atoi(parts[1])
			newVersion = fmt.Sprintf("%s.%d", userIDStr, lastVersionNum+1)
		} else {
			newVersion = fmt.Sprintf("%s.1", userIDStr)
			lastVersionNum = 1
		}
	}

	_, err = db.Exec(`
        INSERT INTO document_versions (room_id, version, content)
        VALUES ($1, $2, $3)`, doc.RoomID, newVersion, doc.Content)

	if err != nil {
		http.Error(w, "Ошибка сохранения документа: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func getDocumentVersions(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return 
	}

	roomIdStr := r.URL.Query().Get("roomId")
	roomId, err := strconv.Atoi(roomIdStr)
	if err != nil || roomId <= 0 {
		http.Error(w, "Некорректный ID комнаты", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT version FROM document_versions WHERE room_id = $1 ORDER BY created_at DESC", roomId)
	if err != nil {
		http.Error(w, "Ошибка получения версий документа: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			http.Error(w, "Ошибка сканирования данных: "+err.Error(), http.StatusInternalServerError)
			return
		}
		versions = append(versions, version)
	}

	response := map[string][]string{"versions": versions}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getDocumentByVersion(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		return 
	}

	roomIdStr := r.URL.Query().Get("roomId")
	version := r.URL.Query().Get("version")

	roomId, err := strconv.Atoi(roomIdStr)
	if err != nil || roomId <= 0 || version == "" {
		http.Error(w, "Некорректный ID комнаты или версия документа", http.StatusBadRequest)
		return
	}

	var content string
	err = db.QueryRow("SELECT content FROM document_versions WHERE room_id = $1 AND version = $2", roomId, version).Scan(&content)

	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Ошибка получения текста документа: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"content": content}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func serveAccount(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "account.html")
}

func handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	
	if err != nil {
		log.Println("Ошибка при установке соединения:", err)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Println("Ошибка при закрытии соединения:", err)
		}
	}()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка чтения сообщения:", err)
			break
		}

		log.Printf("Получено сообщение: %s\n", msg)

		if err := conn.WriteMessage(messageType, msg); err != nil {
			log.Println("Ошибка отправки сообщения:", err)
			break 
		}
	}
}

func main() {
	initDB()
	defer db.Close()

	clientDir := "../Client"
	http.Handle("/", http.FileServer(http.Dir(clientDir)))
	http.HandleFunc("/register", createUser)
	http.HandleFunc("/login", loginUser)
	http.HandleFunc("/ws", handleConnection)
	http.HandleFunc("/account", serveAccount)
	http.HandleFunc("/createRoom", createRoom)
	http.HandleFunc("/joinRoom", joinRoom)
	http.HandleFunc("/getRoomUsers", getRoomUsers)
	http.HandleFunc("/updateUserRole", updateUserRole)
	http.HandleFunc("/saveDocument", saveDocument)
	http.HandleFunc("/getDocumentVersions", getDocumentVersions)
	http.HandleFunc("/getDocumentByVersion", getDocumentByVersion)

	log.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe(":8080", nil)) 
}
