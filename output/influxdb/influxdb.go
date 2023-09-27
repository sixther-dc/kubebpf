package influxdb

import (
	"main/metric"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	influxdb2api "github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
)

type Influxdb struct {
	Client   influxdb2.Client
	WriteApi influxdb2api.WriteAPI
}

func NewInfluxdb(host string, org string, bucket string, token string) *Influxdb {
	var client influxdb2.Client
	var writeAPI influxdb2api.WriteAPI
	client = influxdb2.NewClient(host, token)
	writeAPI = client.WriteAPI(org, bucket)
	return &Influxdb{
		Client:   client,
		WriteApi: writeAPI,
	}
}

func (i *Influxdb) Write(m metric.Metric) {

	var p *write.Point

	p = influxdb2.NewPointWithMeasurement(m.Measurement)
	for k, v := range m.Tags {
		p = p.AddTag(k, v)
	}
	for k, v := range m.Fields {
		p = p.AddField(k, v)
	}

	// p := influxdb2.NewPointWithMeasurement("traffic").
	// 	AddTag("type", strconv.Itoa(int(m.Type))).
	// 	AddTag("flow", strconv.Itoa(m.Flow)).
	// 	AddTag("dstip", m.DstIP).
	// 	AddTag("dstport", strconv.Itoa(int(m.DstPort))).
	// 	AddTag("srcip", m.SrcIP).
	// 	AddTag("srcport", strconv.Itoa(int(m.SrcPort))).
	// 	AddTag("method", m.Method).
	// 	AddTag("protocol", m.Protocol).
	// 	AddTag("url", m.URL).
	// 	AddTag("ifindex", strconv.Itoa(m.IfIndex)).
	// 	AddTag("podname", m.PodName).
	// 	AddTag("nodename", m.NodeName).
	// 	AddTag("namespace", m.NameSpace).
	// 	AddTag("code", m.Code).
	// 	AddTag("servicename", m.ServiceName).
	// 	AddField("duration", m.Duration).
	// 	SetTime(time.Now())
	// Flush writes
	i.WriteApi.WritePoint(p)
	i.WriteApi.Flush()
}
