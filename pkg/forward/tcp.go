package forward

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"anywhere-port/pkg/limit"
)

// 默认连接超时，可在 RuleConfig 中覆盖
const defaultDialTimeout = 10 * time.Second

// TCP 转发用的 buffer 池，减少高并发时的 GC 压力
var tcpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 64*1024) },
}

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

	timeout := defaultDialTimeout
	if rule.Config.DialTimeout > 0 {
		timeout = time.Duration(rule.Config.DialTimeout) * time.Second
	}

	dst, err := net.DialTimeout("tcp", rule.Config.RemoteAddr, timeout)
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
		// Wrap connections with limiter, use pooled buffers
		srcLimited := &RateLimitedConn{Conn: src, Limiter: rule.Limiter, Ctx: ctx}
		dstLimited := &RateLimitedConn{Conn: dst, Limiter: rule.Limiter, Ctx: ctx}

		go func() {
			buf := tcpBufPool.Get().([]byte)
			defer tcpBufPool.Put(buf)
			_, err := io.CopyBuffer(dst, srcLimited, buf) // Upload
			errChan <- err
		}()

		go func() {
			buf := tcpBufPool.Get().([]byte)
			defer tcpBufPool.Put(buf)
			_, err := io.CopyBuffer(src, dstLimited, buf) // Download
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
