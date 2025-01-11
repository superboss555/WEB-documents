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

	// Бесконечный цикл для поддержания работы клиента
	for {
		time.Sleep(1 * time.Second) 
	}
}



