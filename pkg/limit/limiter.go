package limit

import (
	"context"
	"io"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Limiter 定义了限速和配额限制的行为
type Limiter struct {
	rateLimiter *rate.Limiter
	quota       int64 // 总允许流量 (bytes)
	used        int64 // 已使用流量 (bytes)
}

// NewLimiter 创建一个新的限制器
func NewLimiter(speedLimit int64, quota int64) *Limiter {
	l := &Limiter{
		quota: quota,
	}
	if speedLimit > 0 {
		l.rateLimiter = rate.NewLimiter(rate.Limit(speedLimit), int(speedLimit))
	}
	return l
}

func (l *Limiter) SetUsed(u int64) {
	atomic.StoreInt64(&l.used, u)
}

// Allow 检查是否允许通过 n 字节的数据（CAS 保证不会超额计量）
func (l *Limiter) Allow(n int) bool {
	if l.quota <= 0 {
		return true
	}
	for {
		old := atomic.LoadInt64(&l.used)
		newVal := old + int64(n)
		if newVal > l.quota {
			return false
		}
		if atomic.CompareAndSwapInt64(&l.used, old, newVal) {
			return true
		}
	}
}

// Wait 等待令牌桶许可
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l.rateLimiter == nil {
		return nil
	}
	return l.rateLimiter.WaitN(ctx, n)
}

// Stats 返回当前统计信息
func (l *Limiter) Stats() (used int64, quota int64) {
	return atomic.LoadInt64(&l.used), l.quota
}

// UpdateConfig 动态更新限制配置
func (l *Limiter) UpdateConfig(speedLimit int64, quota int64) {
	atomic.StoreInt64(&l.quota, quota)
	if speedLimit > 0 {
		if l.rateLimiter == nil {
			l.rateLimiter = rate.NewLimiter(rate.Limit(speedLimit), int(speedLimit))
		} else {
			l.rateLimiter.SetLimit(rate.Limit(speedLimit))
			l.rateLimiter.SetBurst(int(speedLimit))
		}
	} else {
		l.rateLimiter = nil
	}
}

// RateLimitedReader 包装 io.Reader 实现限速
type RateLimitedReader struct {
	R       io.Reader
	Limiter *Limiter
	Ctx     context.Context
}

func (r *RateLimitedReader) Read(p []byte) (n int, err error) {
	n, err = r.R.Read(p)
	if n > 0 {
		if !r.Limiter.Allow(n) {
			return n, io.EOF
		}
		if err := r.Limiter.Wait(r.Ctx, n); err != nil {
			return n, err
		}
	}
	return n, err
}

// RateLimitedWriter 包装 io.Writer 实现限速
type RateLimitedWriter struct {
	W       io.Writer
	Limiter *Limiter
	Ctx     context.Context
}

func (w *RateLimitedWriter) Write(p []byte) (n int, err error) {
	if !w.Limiter.Allow(len(p)) {
		return 0, io.EOF
	}
	if err := w.Limiter.Wait(w.Ctx, len(p)); err != nil {
		return 0, err
	}
	return w.W.Write(p)
}
