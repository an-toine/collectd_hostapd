# collectd_hostapd
A python plugin for collectd to monitor Hostapd activity.

This plugin is using the Netlink API with the nl80211 driver to collect basic metrics from the Kernel about a wireless interface acting as an Access Point with Hostapd.

Currently, the following metrics are collected :

 * Number of clients connected
 * RX packets
 * TX packets
 * RX bytes
 * TX bytes
 * TX failed
 * Signal attenuation

It is possible to collect metrics from only a few clients by using the `client` key in the configuration with the MAC address of clients of interest.

Note : even though this plugin was written with Hostapd in mind, it should be possible to use it on any Linux station connected to an access point.

## Installation

### Requirements

This plugin heavily depends on the [libnl](https://github.com/Robpol86/libnl) module to query a netlink socket. You can install it with :

```
pip install libnl
```

The Collectd python plugin should also be enabled.

### Plugin setup

Copy the python script to the plugin directory, for example `/usr/lib/collectd/`.

In the configuration, add the block contained in file `collectd_hostapd.conf` :

```
<Plugin python>
	LogTraces false
	Interactive false
	ModulePath "/usr/lib/collectd/"
	Import "collectd_hostapd"
	<Module collectd_hostapd>
		interface wlan0
		client "xx:xx:xx:xx:xx:xx"
		client "yy:yy:yy:yy:yy:yy"
    </Module>
</Plugin>
```

This configuration would monitor the `wlan0` wireless interface, and collect detailed metrics for clients identified by the MAC addresses `xx:xx:xx:xx:xx:xx`and `yy:yy:yy:yy:yy:yy`.

## Metrics name

The following metric names are used :

 * stations-count
 * rx-bytes-[MAC address]
 * tx-bytes-[MAC address]
 * rx-packets-[MAC address]
 * tx-packets-[MAC address]
 * tx-failure-[MAC address]
 * signal-[MAC address]