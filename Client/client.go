package main

import (
    "log"
    "os/exec"
    "time"

    "github.com/gorilla/websocket"
)

func main() {
    // Открываем HTML-страницу регистрации в браузере
    err := exec.Command("cmd", "/c", "start", "index.html").Start() // Для Windows
    if err != nil {
        log.Fatal("Ошибка открытия браузера:", err)
    }

    // Укажите адрес вашего WebSocket-сервера
    url := "ws://localhost:8080/ws"

    // Подключаемся к WebSocket-серверу
    conn, _, err := websocket.DefaultDialer.Dial(url, nil)
    if err != nil {
        log.Fatal("Ошибка подключения:", err)
    }
    defer conn.Close()

    log.Println("Подключение к WebSocket-серверу установлено")

    // Запускаем горутину для обработки входящих сообщений
    go func() {
        for {
            _, msg, err := conn.ReadMessage()
            if err != nil {
                log.Println("Ошибка чтения сообщения:", err)
                return
            }
            log.Printf("Получено сообщение: %s\n", msg)
        }
    }()

    // Бесконечный цикл для поддержания работы клиента
    for {
        time.Sleep(1 * time.Second) // Задержка для предотвращения перегрузки процессора
        
    }
}
