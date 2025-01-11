package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
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

	createUsersTable()
}

func createUsersTable() {
    query := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    );
    `
    
    _, err := db.Exec(query)
    if err != nil {
        log.Fatal("Ошибка при создании таблицы пользователей:", err)
    } else {
        log.Println("Таблица пользователей успешно создана или уже существует.")
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
        return // Обработка preflight-запроса
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

    log.Printf("Received login data: %+v", user)

    if user.Email == "" || user.Password == "" {
        http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
        return
    }

    // Получаем ID и хэш пароля из базы данных
    var storedHash string
    err := db.QueryRow("SELECT id, password FROM users WHERE email = $1", user.Email).Scan(&user.ID, &storedHash)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
            return
        }
        http.Error(w, "Ошибка получения данных: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Сравниваем хэш пароля
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
    if err != nil {
        http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
}


func handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при установке соединения:", err)
		return
	}
	defer conn.Close()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка:", err)
			break
		}

		log.Printf("Получено сообщение: %s\n", msg)

		err = conn.WriteMessage(messageType, msg) // Эхо-ответ (если нужно)
		if err != nil {
			log.Println("Ошибка:", err)
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
	

	log.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe(":8080", nil)) // Запуск HTTP-сервера
}

func serveAccount(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "D:/projects/webDocuments/Client/account.html") 
}