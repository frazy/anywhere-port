package forward

import (
	"context"
	"io"
	"log"
	"net"
	"time"

	"anywhere-port/pkg/limit"
)

func (e *Engine) startTCP(ctx context.Context, rule *Rule) error {
	l, err := net.Listen("tcp", rule.Config.ListenAddr)
	if err != nil {
		return err
	}
	rule.Listener = l

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				// Check if closed
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("Accept error: %v", err)
					time.Sleep(100 * time.Millisecond) // Avoid tight loop
					continue
				}
			}

			go e.handleTCP(ctx, conn, rule)
		}
	}()

	return nil
}

func (e *Engine) handleTCP(ctx context.Context, src net.Conn, rule *Rule) {
	defer src.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TCP Panic] Rule %s: %v", rule.Config.ID, r)
		}
	}()

	if !rule.Limiter.Allow(0) { // Check quota before connecting
		return
	}

	dst, err := net.DialTimeout("tcp", rule.Config.RemoteAddr, 5*time.Second)
	if err != nil {
		log.Printf("Dial error to %s: %v", rule.Config.RemoteAddr, err)
		return
	}
	defer dst.Close()

	errChan := make(chan error, 2)

	// Optimization: If no limits are set, use raw connections for zero-copy (splice/sendfile)
	if rule.Config.SpeedLimit <= 0 && rule.Config.TotalQuota <= 0 {
		go func() {
			io.Copy(dst, src)
			errChan <- nil
		}()
		go func() {
			io.Copy(src, dst)
			errChan <- nil
		}()
	} else {
		// Wrap connections with limiter
		srcLimited := &RateLimitedConn{Conn: src, Limiter: rule.Limiter, Ctx: ctx}
		dstLimited := &RateLimitedConn{Conn: dst, Limiter: rule.Limiter, Ctx: ctx}

		go func() {
			_, err := io.Copy(dst, srcLimited) // Upload
			errChan <- err
		}()

		go func() {
			_, err := io.Copy(src, dstLimited) // Download
			errChan <- err
		}()
	}

	select {
	case <-ctx.Done():
	case <-errChan:
	}
}

// RateLimitedConn wraps net.Conn to intercept Reads (and optionally Writes)
type RateLimitedConn struct {
	net.Conn
	Limiter *limit.Limiter
	Ctx     context.Context
}

func (c *RateLimitedConn) Read(b []byte) (n int, err error) {
	// Check quota first
	if !c.Limiter.Allow(1) { // Check if we have *any* quota left
		return 0, io.EOF
	}

	// Read first, then wait? Or Wait then Read?
	// If we read first, we "spent" the bandwidth already on the wire.
	// But we can't control the wire receive unless we stop reading.
	// So we Read (pull from kernel buffer), then Wait (delay app processing), simulating slow link.

	n, err = c.Conn.Read(b)
	if n > 0 {
		if !c.Limiter.Allow(n) {
			return n, io.EOF // Quota exceeded during read
		}
		if err := c.Limiter.Wait(c.Ctx, n); err != nil {
			return n, err
		}
	}
	return n, err
}
