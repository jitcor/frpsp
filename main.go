package main

//ref:https://github.com/fatedier/frp/blob/v0.38.0/doc/server_plugin.md
import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FrpspRequest struct {
	Content struct {
		User struct {
			User  string `json:"user"`
			Metas struct {
			} `json:"metas"`
			RunId string `json:"run_id"`
		} `json:"user"`
		ProxyName  string `json:"proxy_name"`
		ProxyType  string `json:"proxy_type"`
		RemoteAddr string `json:"remote_addr"`
	} `json:"content"`
}

func FrpspHandler(res http.ResponseWriter, req *http.Request) {
	bin, err := io.ReadAll(req.Body)
	defer func() {
		if err != nil {
			log.Println("error:", err.Error())
			http.Error(res, `{"reject": true,"reject_reason": "internal error"}`, 200)
			return
		}
	}()

	frpspReq := new(FrpspRequest)
	err = json.Unmarshal(bin, frpspReq)
	if err != nil {
		return
	}
	if db == nil {
		err = fmt.Errorf("db is nil")
		return
	}
	remoteAddr := strings.Split(frpspReq.Content.RemoteAddr, ":")[0]
	rows, e := db.Query("SELECT host,timestamp,isBlacked FROM ip WHERE timestamp >= ? and host = ?", time.Now().Unix()-10*60, remoteAddr)
	if e != nil {
		err = e
		return
	}
	defer rows.Close()
	var host string
	var timestamp int
	var isBlocked bool
	var count int
	for rows.Next() {
		err = rows.Scan(&host, &timestamp, &isBlocked)
		if err != nil {
			return
		}
		if isBlocked {
			http.Error(res, `{"reject": true,"reject_reason": "invalid user"}`, 200)
			return
		}
		count++
	}
	wg.Lock()
	defer wg.Unlock()
	insertData := `
		INSERT INTO ip (host, timestamp,isBlacked) VALUES (?, ?,?);
	`
	_, err = db.Exec(insertData, remoteAddr, time.Now().Unix(), count > 4)
	if err != nil {
		return
	}
	http.Error(res, `{"reject": false,"unchange": true}`, 200)
}

var db *sql.DB
var wg sync.RWMutex

func main() {
	if db == nil {
		var err error
		db, err = sql.Open("sqlite3", "./ipcheck.db")
		if err != nil {
			log.Fatalln(err)
			return
		}
		defer db.Close()

		createTable := `
		CREATE TABLE IF NOT EXISTS ip (
                                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                                           host TEXT NOT NULL,
                                           timestamp INT,
                                           isBlacked BOOLEAN
);
	`
		_, err = db.Exec(createTable)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/frpsp", FrpspHandler)
	log.Println("Listening on:http://127.0.0.1:50234")
	if err := http.ListenAndServe(":50234", mux); err != nil {
		log.Fatalln("error:", err)
		return
	}
}
