#whirlpool.go
a [whirlpool hashing](https://en.wikipedia.org/wiki/Whirlpool_(cryptography\)) library for go

## setup

`go get github.com/jzelinskie/whirlpool` in a terminal

or simply
`import "github.com/jzelinskie/whirlpool"` in your code


## example

    package main

    import (
      "fmt"
      "github.com/jzelinskie/whirlpool"
    )
    
    func main() {
      w := whirlpool.New()
      text := []byte("This is an example.")
      w.Write(text)
      fmt.Println(w.Sum(nil))
    }

## branches

* master - stable, works like the hash libs in the corelib
* trace - same code as master, but prints midstate values to stdout

## license

Modified BSD License
