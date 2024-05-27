package main

//ref:https://github.com/fatedier/frp/blob/v0.38.0/doc/server_plugin.md
import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net/http"
	"os"
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
type IpInfo struct {
	Ip       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
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
	if whiteList != nil {
		for _, item := range whiteList {
			if item == remoteAddr {
				http.Error(res, `{"reject": false,"unchange": true}`, 200)
				return
			}
		}
	}
	loc, err := getIpCountry(remoteAddr)
	if err != nil {
		log.Println("getIpLoc error: ", err.Error())
	} else if loc != "CN" {
		http.Error(res, `{"reject": true,"reject_reason": "invalid user(no CN)"}`, 200)
		return
	}
	var isBlocked bool
	var count int

	count, err = checkIp(remoteAddr, 10*time.Minute)
	if err != nil {
		return
	}
	if count < 4 {
		count, err = checkIp(remoteAddr, 24*time.Hour)
		if err != nil {
			return
		}
		if count < 20 {
			count, err = checkIp(remoteAddr, 7*24*time.Hour)
			if err != nil {
				return
			}
			isBlocked = count > 60
		} else {
			isBlocked = true
		}
	} else {
		isBlocked = true
	}
	if isBlocked {
		http.Error(res, `{"reject": true,"reject_reason": "invalid user"}`, 200)
		return
	}
	wg.Lock()
	defer wg.Unlock()
	insertData := `
		INSERT INTO ip (host, timestamp,isBlacked) VALUES (?, ?,?);
	`
	_, err = db.Exec(insertData, remoteAddr, time.Now().Unix(), isBlocked)
	if err != nil {
		return
	}
	http.Error(res, `{"reject": false,"unchange": true}`, 200)
}
func getIpCountry(remoteAddr string) (country string, err error) {
	var host string
	var rows *sql.Rows
	var resp *http.Response
	var body []byte
	rows, err = db.Query("SELECT host,country FROM country WHERE host = ?", remoteAddr)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&host, &country)
		if err != nil {
			return
		}
		if country != "" {
			return
		}
	}
	resp, err = http.Get(fmt.Sprintf("https://ipinfo.io/%s/json?token=1564640ae4bce5", remoteAddr))
	if err != nil {
		return
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	ipInfo := new(IpInfo)
	err = json.Unmarshal(body, ipInfo)
	if err != nil {
		return
	}
	if ipInfo.Country == "" {
		return "", errors.New("country is nil")
	}
	wg.Lock()
	defer wg.Unlock()
	insertData := `
		INSERT INTO country (host, country) VALUES (?,?);
	`
	_, err = db.Exec(insertData, remoteAddr, ipInfo.Country)
	if err != nil {
		return
	}
	return ipInfo.Country, nil
}
func checkIp(remoteAddr string, interval time.Duration) (count int, err error) {
	var host string
	var timestamp int

	rows, e := db.Query("SELECT host,timestamp FROM ip WHERE timestamp >= ? and host = ?", time.Now().Add(-interval).Unix(), remoteAddr)
	if e != nil {
		err = e
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&host, &timestamp)
		if err != nil {
			return
		}
		count++
	}
	return
}

var db *sql.DB
var wg sync.RWMutex
var whiteList []string

func main() {
	if db == nil {
		var err error
		db, err = sql.Open("sqlite3", "./ipcheck.db")
		if err != nil {
			log.Fatalln(err)
			return
		}
		defer db.Close()
		if len(os.Args) == 2 {
			whiteList = append(whiteList, strings.Split(os.Args[1], ",")...)
		}

		createTable := `
		CREATE TABLE IF NOT EXISTS ip (
                                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                                           host TEXT NOT NULL,
                                           timestamp INT,
                                           isBlacked BOOLEAN
);
		CREATE TABLE IF NOT EXISTS country (
                                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                                           host TEXT NOT NULL,
                                           country TEXT
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
