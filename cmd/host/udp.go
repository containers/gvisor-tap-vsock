package main

import "net"

func pipe(conn1 net.Conn, conn2 net.Conn) {
	defer func() {
		_ = conn1.Close()
		_ = conn2.Close()
	}()
	chan1 := chanFromConn(conn1)
	chan2 := chanFromConn(conn2)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			}
			_, _ = conn2.Write(b1)
		case b2 := <-chan2:
			if b2 == nil {
				return
			}
			_, _ = conn1.Write(b2)
		}
	}
}

func chanFromConn(conn net.Conn) chan []byte {
	c := make(chan []byte)

	go func() {
		b := make([]byte, 1024)

		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()

	return c
}
