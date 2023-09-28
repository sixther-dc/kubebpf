package influxdb

import (
	"context"
	"log"
	"main/metric"
	"sync"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	influxdb2api "github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
)

type Influxdb struct {
	Client   influxdb2.Client
	WriteApi influxdb2api.WriteAPIBlocking
	Points   []*write.Point
	mu       sync.Mutex
}

func NewInfluxdb(host string, org string, bucket string, token string) *Influxdb {
	var client influxdb2.Client
	var writeAPI influxdb2api.WriteAPIBlocking
	client = influxdb2.NewClient(host, token)
	writeAPI = client.WriteAPIBlocking(org, bucket)
	return &Influxdb{
		Client:   client,
		WriteApi: writeAPI,
	}
}

func (i *Influxdb) Write(m metric.Metric) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var p *write.Point
	p = influxdb2.NewPointWithMeasurement(m.Measurement)
	for k, v := range m.Tags {
		p = p.AddTag(k, v)
	}
	for k, v := range m.Fields {
		p = p.AddField(k, v)
	}
	i.Points = append(i.Points, p)
}

// 提交数据涉及清空buffer, 所以需要在提交的时候加锁, 提交结束后释放锁, 防止数据被误清除
func (i *Influxdb) Run() *Influxdb {
	calTicker := time.NewTicker(3 * time.Second)
	go func() {
		for range calTicker.C {
			i.mu.Lock()
			i.Commit()
			i.mu.Unlock()
		}
	}()
	return i
}

func (i *Influxdb) Commit() {
	log.Printf("begin to commit data [%d]\n", len(i.Points))
	if err := i.WriteApi.WritePoint(context.Background(), i.Points...); err != nil {
		log.Printf("write influxdb error: %+v\n", err)
		panic(err)
	}
	i.ClearPoints()
}

func (i *Influxdb) ClearPoints() {
	i.Points = i.Points[:0]
}
