package forward

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

const (
	udpBufferSize = 65535
	udpTimeout    = 60 * time.Second
)

// UDP buffer 池，减少高流量下的内存分配和 GC 压力
var udpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, udpBufferSize) },
}

type udpSession struct {
	remoteConn *net.UDPConn
	lastActive int64 // Unix timestamp，用 atomic 或 sync.Map 的天然并发安全
}

func (e *Engine) startUDP(ctx context.Context, rule *Rule) error {
	addr, err := net.ResolveUDPAddr("udp", rule.Config.ListenAddr)
	if err != nil {
		return err
	}

	destAddr, err := net.ResolveUDPAddr("udp", rule.Config.RemoteAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	rule.UDPConn = conn

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[UDP Panic] Rule %s: %v", rule.Config.ID, r)
			}
		}()

		var sessions sync.Map // map[string]*udpSession

		// Cleanup routine
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[UDP Cleanup Panic] %v", r)
				}
			}()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now().Unix()
					sessions.Range(func(key, value interface{}) bool {
						sess := value.(*udpSession)
						if now-sess.lastActive > int64(udpTimeout.Seconds()) {
							sess.remoteConn.Close()
							sessions.Delete(key)
						}
						return true
					})
				}
			}
		}()

		for {
			buf := udpBufPool.Get().([]byte)
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				udpBufPool.Put(buf)
				return
			}

			// 复制数据到独立 slice，释放 pool buffer
			data := make([]byte, n)
			copy(data, buf[:n])
			udpBufPool.Put(buf)

			// 异步处理，避免 Limiter.Wait 阻塞读取循环
			go func(data []byte, clientAddr *net.UDPAddr) {
				// Apply Limiter (Upload)
				if !rule.Limiter.Allow(len(data)) {
					return // Drop packet if quota exceeded
				}
				rule.Limiter.Wait(ctx, len(data)) // Delay

				val, exists := sessions.Load(clientAddr.String())
				var session *udpSession
				if exists {
					session = val.(*udpSession)
				} else {
					// Create new session (dial remote)
					rConn, err := net.DialUDP("udp", nil, destAddr)
					if err != nil {
						log.Printf("UDP Dial error: %v", err)
						return
					}
					session = &udpSession{
						remoteConn: rConn,
						lastActive: time.Now().Unix(),
					}
					sessions.Store(clientAddr.String(), session)

					// Start reading from remote and writing back to client
					go func(sess *udpSession, cAddr *net.UDPAddr) {
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[UDP Session Panic] %v", r)
							}
						}()
						respBuf := udpBufPool.Get().([]byte)
						defer udpBufPool.Put(respBuf)
						for {
							rn, _, err := sess.remoteConn.ReadFromUDP(respBuf)
							if err != nil {
								return
							}

							sess.lastActive = time.Now().Unix()

							// Apply Limiter (Download)
							if !rule.Limiter.Allow(rn) {
								continue
							}
							rule.Limiter.Wait(ctx, rn)

							conn.WriteToUDP(respBuf[:rn], cAddr)
						}
					}(session, clientAddr)
				}
				session.lastActive = time.Now().Unix()

				// Write to remote
				session.remoteConn.Write(data)
			}(data, clientAddr)
		}
	}()

	return nil
}
