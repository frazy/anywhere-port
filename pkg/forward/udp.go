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

type udpSession struct {
	remoteConn *net.UDPConn
	lastActive time.Time
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

		buffer := make([]byte, udpBufferSize)
		sessions := make(map[string]*udpSession)
		var mu sync.Mutex

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
					mu.Lock()
					now := time.Now()
					for k, v := range sessions {
						if now.Sub(v.lastActive) > udpTimeout {
							v.remoteConn.Close()
							delete(sessions, k)
						}
					}
					mu.Unlock()
				}
			}
		}()

		for {
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				// Closed
				return
			}

			// Apply Limiter (Upload)
			if !rule.Limiter.Allow(n) {
				continue // Drop packet if quota exceeded
			}
			rule.Limiter.Wait(ctx, n) // Delay

			mu.Lock()
			session, exists := sessions[clientAddr.String()]
			if !exists {
				// Create new session (dial remote)
				rConn, err := net.DialUDP("udp", nil, destAddr)
				if err != nil {
					log.Printf("UDP Dial error: %v", err)
					mu.Unlock()
					continue
				}
				session = &udpSession{
					remoteConn: rConn,
					lastActive: time.Now(),
				}
				sessions[clientAddr.String()] = session

				// Start reading from remote and allow writing back to client
				go func(sess *udpSession, cAddr *net.UDPAddr) {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[UDP Session Panic] %v", r)
						}
					}()
					respBuffer := make([]byte, udpBufferSize)
					for {
						rn, _, err := sess.remoteConn.ReadFromUDP(respBuffer)
						if err != nil {
							return
						}

						sess.lastActive = time.Now()

						// Apply Limiter (Download)
						if !rule.Limiter.Allow(rn) {
							continue
						}
						rule.Limiter.Wait(ctx, rn)

						conn.WriteToUDP(respBuffer[:rn], cAddr)
					}
				}(session, clientAddr)
			}
			session.lastActive = time.Now()
			mu.Unlock()

			// Write to remote
			session.remoteConn.Write(buffer[:n])
		}
	}()

	return nil
}
