package main

import (
	"bufio"
	"fmt"
	"os"
)

// TODO (layered-model): implement per the lesson description.

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" { continue }
		fmt.Println("TODO")
	}
}
