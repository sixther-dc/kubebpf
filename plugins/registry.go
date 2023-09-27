package plugins

import "main/metric"

type Plugin interface {
	Gather(chan metric.Metric)
}

var Plugins = map[string]Plugin{}

func Add(name string, plugin Plugin) {
	Plugins[name] = plugin
}
