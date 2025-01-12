package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db           *sql.DB
	idLock       = &sync.Mutex{}
	upgrader     = websocket.Upgrader{}
)

// User структура для хранения данных пользователя
type User struct {
    ID       int    `json:"id"` 
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Room struct {
    ID          int64  `json:"id"`
    UserID      int64  `json:"user_id"`      // ID пользователя, создавшего комнату
    RoomID      int64  `json:"room_id"`      // Уникальный идентификатор комнаты
    RoomName    string `json:"room_name"`     // Название комнаты
    RoomPassword string `json:"room_password"` // Пароль для входа (если требуется)
}



func initDB() {
	var err error
	connStr := "host=localhost user=admin password=123 dbname=test port=5432 sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Ошибка пинга базы данных:", err)
	}

    // clearAllTables()
    initRoomsTable()
    initRoomUsersTable()
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
        log.Fatal("Ошибка при создании таблицы комнат:", err)
    } else {
        log.Println("Таблица комнат успешно создана или уже существует.")
    }
}

func initRoomUsersTable() {
    // Запрос для добавления нового столбца email в таблицу room_users
    query := `
    ALTER TABLE room_users 
    ADD COLUMN IF NOT EXISTS email VARCHAR(255) NOT NULL;
    `

    _, err := db.Exec(query)
    if err != nil {
        log.Fatal("Ошибка при обновлении таблицы room_users:", err)
    } else {
        log.Println("Таблица room_users успешно обновлена или уже существует.")
    }
}

func clearAllTables() {
    // Получаем список всех таблиц
    rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
    if err != nil {
        log.Fatal("Ошибка получения списка таблиц:", err)
    }
    defer rows.Close()

    var tables []string
    for rows.Next() {
        var tableName string
        if err := rows.Scan(&tableName); err != nil {
            log.Fatal("Ошибка сканирования имени таблицы:", err)
        }
        tables = append(tables, tableName)
    }

    // Формируем запрос TRUNCATE для всех таблиц с сбросом идентификаторов
    if len(tables) > 0 {
        truncateQuery := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE;"
        _, err = db.Exec(truncateQuery)
        if err != nil {
            log.Fatal("Ошибка очистки таблиц:", err)
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
		log.Println("Ошибка проверки существования пользователя:", err)
		return false
	}
	return exists
}

func setCORSHeaders(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
    w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
}

func createUser(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

    if r.Method == http.MethodOptions {
        return // Просто возвращаем ответ с установкой заголовков
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
        return
    }

    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
        return
    }

    log.Printf("Received user data: %+v", user) // Логируем входящие данные

    if user.Email == "" || user.Password == "" {
        http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
        return
    }

    // Хэшируем пароль
    hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Ошибка хэширования пароля: "+err.Error(), http.StatusInternalServerError)
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
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
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
        http.Error(w, "Ошибка получения данных: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Сравниваем хэш пароля
    err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
    if err != nil {
        http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
        return
    }

    // Формируем ответ
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
        return // Обработка preflight-запроса
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
        return
    }

    var room Room
    if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Проверка обязательных полей
    if room.UserID == 0 || room.RoomName == "" {
        http.Error(w, "ID пользователя и название комнаты не могут быть пустыми", http.StatusBadRequest)
        return
    }

    // Получаем email пользователя из таблицы users
    var userEmail string
    err := db.QueryRow("SELECT email FROM users WHERE id = $1", room.UserID).Scan(&userEmail)
    if err != nil {
        http.Error(w, "Ошибка получения email пользователя: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Вставка данных в таблицу rooms
    err = db.QueryRow(
        "INSERT INTO rooms(user_id, room_name, room_password) VALUES($1, $2, $3) RETURNING id",
        room.UserID, room.RoomName, room.RoomPassword,
    ).Scan(&room.ID)

    if err != nil {
        http.Error(w, "Ошибка при создании комнаты: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Добавление записи в таблицу room_users с ролью "owner" и email пользователя
    _, err = db.Exec(
        "INSERT INTO room_users(room_id, user_id, email, role) VALUES($1, $2, $3, $4)",
        room.ID, room.UserID, userEmail, "owner", // Роль на английском языке
    )
    
    if err != nil {
        http.Error(w, "Ошибка при добавлении пользователя в комнату: "+err.Error(), http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "message":   "Комната успешно создана",
        "roomId":    room.ID,
        "roomName":  room.RoomName,
        "userId":    room.UserID,
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(response)
}



func joinRoom(w http.ResponseWriter, r *http.Request) {
    setCORSHeaders(w)

    if r.Method == http.MethodOptions {
        return // Обработка preflight-запроса
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
        return
    }

    var room struct {
        RoomName     string `json:"room_name"`
        RoomPassword string `json:"room_password"`
        UserID       int    `json:"user_id"` // Получаем ID пользователя из запроса
    }

    if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
        return
    }

    if room.RoomName == "" || room.RoomPassword == "" {
        http.Error(w, "Название комнаты и пароль не могут быть пустыми", http.StatusBadRequest)
        return
    }

    // Проверка существования комнаты
    var storedRoom struct {
        ID   int
        Name string
    }
    
    err := db.QueryRow("SELECT id FROM rooms WHERE room_name = $1 AND room_password = $2", room.RoomName, room.RoomPassword).Scan(&storedRoom.ID)
    
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Комната не найдена или неверный пароль", http.StatusUnauthorized)
            return
        }
        http.Error(w, "Ошибка получения данных: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Проверка на существование записи в таблице room_users
    var userInRoomID int
    err = db.QueryRow("SELECT user_id FROM room_users WHERE room_id = $1 AND user_id = $2", storedRoom.ID, room.UserID).Scan(&userInRoomID)

    if err == sql.ErrNoRows {
        // Если записи нет, добавляем нового пользователя в комнату с ролью "reader"
        _, err = db.Exec("INSERT INTO room_users(room_id, user_id, role) VALUES($1, $2, $3)", storedRoom.ID, room.UserID, "reader")
        if err != nil {
            http.Error(w, "Ошибка при добавлении пользователя в комнату: "+err.Error(), http.StatusInternalServerError)
            return
        }
    } else if err != nil {
        // Если произошла другая ошибка
        http.Error(w, "Ошибка проверки существования пользователя: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Формируем ответ с ID и названием комнаты
    response := map[string]interface{}{
        "message":   "Успешное присоединение к комнате",
        "roomId":    storedRoom.ID,
        "roomName":  storedRoom.Name,
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
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
            break // Выход из цикла при ошибке
        }

        log.Printf("Получено сообщение: %s\n", msg)

        // Эхо-ответ (если нужно)
        if err := conn.WriteMessage(messageType, msg); err != nil {
            log.Println("Ошибка отправки сообщения:", err)
            break // Выход из цикла при ошибке
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

	

	log.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe(":8080", nil)) // Запуск HTTP-сервера
}

func serveAccount(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "account.html") 
}