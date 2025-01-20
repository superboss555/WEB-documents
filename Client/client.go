package main

import (
	"log"
	"os/exec"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	err := exec.Command("cmd", "/c", "start", "index.html").Start() // Windows
	// err := exec.Command("open", "index.html").Start() // macOS
	if err != nil {
		log.Fatal("Ошибка при открытия браузера:", err)
	}

	url := "ws://localhost:8080/ws"

	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Fatal("Ошибка при подключении:", err)
	}
	
	defer conn.Close()

	log.Println("Подключение к WebSocket-серверу установлено")

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Println("Ошибка при чтения сообщения:", err)
				return
			}
			log.Printf("Получено сообщение: %s\n", msg)
		}
	}()

	for {
		time.Sleep(1 * time.Second) 

	}
}
