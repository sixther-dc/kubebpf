package red

import (
	"fmt"
	"main/metric"
	"time"
)

type RED struct {
	PodName       string
	NodeName      string
	NameSpace     string
	ServiceName   string
	RequestCount  int
	ErrCount      int
	DurationCount int
	QPS           float32
	ErrRate       float32
	Duration      float32
}

func (r *RED) String() string {
	return fmt.Sprintf("%s %s %s %s %d %f %d %f %d %f %s\n",
		r.PodName, r.NameSpace, r.NodeName, r.ServiceName, r.RequestCount,
		r.QPS, r.ErrCount, r.ErrRate, r.DurationCount, r.Duration,
		time.Now().Format("2006-01-02 15:04:05"),
	)
}

func (r *RED) CovertMetric() metric.Metric {
	var m metric.Metric
	m.Measurement = "red"
	m.AddTags("podname", r.PodName)
	m.AddTags("nodename", r.NodeName)
	m.AddTags("namespace", r.NameSpace)
	m.AddTags("servicename", r.ServiceName)
	m.AddField("qps", r.QPS)
	m.AddField("errrate", r.ErrRate)
	m.AddField("duration", r.Duration)
	return m
}
