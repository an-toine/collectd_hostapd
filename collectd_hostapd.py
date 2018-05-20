#!/bin/python

import collectd
import socket
import fcntl
import struct
import time

import libnl.handlers
from libnl.attr import nla_put_u32, nla_parse, nla_parse_nested, nla_get_string, nla_get_u32, nla_get_u8, nla_put_nested
from libnl.socket_ import nl_socket_alloc, nl_socket_free
from libnl.linux_private.genetlink import genlmsghdr
from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.genl.genl import genl_connect, genlmsg_put, genlmsg_attrdata, genlmsg_attrlen
from libnl.msg import nlmsg_alloc, nlmsg_data, nlmsg_hdr
from libnl.linux_private.netlink import NLM_F_DUMP
from libnl.nl80211 import nl80211
from libnl.nl import nl_recvmsgs, nl_send_auto
from libnl.attr import nla_policy, NLA_U64, NLA_U32, NLA_U8, NLA_U16, NLA_NESTED

INTERFACE = ""
INTERFACEINDEX = 0
CLIENTS = []
VALUES = collectd.Values()
DRIVER_ID = None
SOCKET = None

# Class used to represent a station and its various attributes
class Station:
    def __init__(self, mac_addr=None, rx_packets=None, rx_bytes=None, tx_packets=None, tx_bytes=None, signal=None, tx_failed=None):
        self._mac_addr = mac_addr
        self._rx_packets = rx_packets
        self._rx_bytes = rx_bytes
        self._tx_packets = tx_packets
        self._tx_bytes = tx_bytes
        self._signal = signal
        self._tx_failed = tx_failed
    
    @property
    def mac_addr(self):
        return self._mac_addr
    
    @mac_addr.setter
    def mac_addr(self, value):
        self._mac_addr = value

    @property
    def rx_packets(self):
        return self._rx_packets
    
    @rx_packets.setter
    def rx_packets(self, value):
        self._rx_packets = value
    
    @property
    def rx_bytes(self):
        return self._rx_bytes
    
    @rx_bytes.setter
    def rx_bytes(self, value):
        self._rx_bytes = value

    @property
    def tx_packets(self):
        return self._tx_packets
    
    @tx_packets.setter
    def tx_packets(self, value):
        self._tx_packets = value

    @property
    def tx_bytes(self):
        return self._tx_bytes
    
    @tx_bytes.setter
    def tx_bytes(self, value):
        self._tx_bytes = value
    
    @property
    def signal(self):
        return self._signal
    
    @signal.setter
    def signal(self, value):
        self._signal = value
    
    @property
    def tx_failed(self):
        return self._tx_failed

    @tx_failed.setter
    def tx_failed(self, value):
        self._tx_failed = value

# Method called for each message received
def getStationInfo_callback(msg, results):
    # Dictionnary later populated with response message sub-attributes
    sinfo = dict()
    # Get the header of the message
    gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
    tb = dict((i, None) for i in range(nl80211.NL80211_ATTR_MAX + 1))
    # Define the data structure of the netlink attributes we will receive
    stats_policy = dict((i, None) for i in range(nl80211.NL80211_STA_INFO_MAX + 1))
    stats_policy.update({
        nl80211.NL80211_STA_INFO_INACTIVE_TIME: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_RX_BYTES: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_TX_BYTES: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_RX_PACKETS: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_TX_PACKETS: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_SIGNAL: nla_policy(type_=NLA_U8),
        nl80211.NL80211_STA_INFO_SIGNAL_AVG: nla_policy(type_=NLA_U8),
        nl80211.NL80211_STA_INFO_T_OFFSET: nla_policy(type_=NLA_U64),
        nl80211.NL80211_STA_INFO_TX_BITRATE: nla_policy(type_=NLA_NESTED),
        nl80211.NL80211_STA_INFO_RX_BITRATE: nla_policy(type_=NLA_NESTED),
        nl80211.NL80211_STA_INFO_LLID: nla_policy(type_=NLA_U16),
        nl80211.NL80211_STA_INFO_PLID: nla_policy(type_=NLA_U16),
        nl80211.NL80211_STA_INFO_PLINK_STATE: nla_policy(type_=NLA_U8),
        nl80211.NL80211_STA_INFO_TX_RETRIES: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_TX_FAILED: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_LOCAL_PM: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_PEER_PM: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_NONPEER_PM: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_CHAIN_SIGNAL: nla_policy(type_=NLA_NESTED),
        nl80211.NL80211_STA_INFO_RX_BYTES64: nla_policy(type_=NLA_U64),
        nl80211.NL80211_STA_INFO_TX_BYTES64: nla_policy(type_=NLA_U64),
        nl80211.NL80211_STA_INFO_BEACON_LOSS: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_CONNECTED_TIME: nla_policy(type_=NLA_U32),
        nl80211.NL80211_STA_INFO_BSS_PARAM: nla_policy(type_=NLA_NESTED),
    })
    # If any value in the stats_policy is empty, pad it with a default NLA_U8 type to avoid
    # any issue during validation
    for key in stats_policy:
        if stats_policy[key] is None:
            stats_policy[key] = nla_policy(type_=NLA_U8)
    # Parse the stream of attributes received into indexed chunks of data
    nla_parse(tb, nl80211.NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
    # If we haven't received Station info data, don't go further and skip this message
    if tb[nl80211.NL80211_ATTR_STA_INFO] is None:
        return libnl.handlers.NL_SKIP
    # Finally, feed the attributes of the message into the chunk defined before
    nla_parse_nested(sinfo, nl80211.NL80211_STA_INFO_MAX, tb[nl80211.NL80211_ATTR_STA_INFO], stats_policy)
    # Create the Station object
    station = Station()
    # Finally, if an attribute of interest is present, save it in the object
    if tb[nl80211.NL80211_ATTR_MAC]:
        # Convert the station MAC address to something human readable
        raw_mac = nla_get_string(tb[nl80211.NL80211_ATTR_MAC])
        station.mac_addr = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",raw_mac)
    if sinfo[nl80211.NL80211_STA_INFO_RX_BYTES]:
        station.rx_bytes = nla_get_u32(sinfo[nl80211.NL80211_STA_INFO_RX_BYTES])
    if sinfo[nl80211.NL80211_STA_INFO_TX_BYTES]:
        station.tx_bytes = nla_get_u32(sinfo[nl80211.NL80211_STA_INFO_TX_BYTES])
    if sinfo[nl80211.NL80211_STA_INFO_RX_PACKETS]:
        station.rx_packets = nla_get_u32(sinfo[nl80211.NL80211_STA_INFO_RX_PACKETS])
    if sinfo[nl80211.NL80211_STA_INFO_TX_PACKETS]:
        station.tx_packets = nla_get_u32(sinfo[nl80211.NL80211_STA_INFO_TX_PACKETS])
    if sinfo[nl80211.NL80211_STA_INFO_TX_FAILED]:
        station.tx_failed = nla_get_u32(sinfo[nl80211.NL80211_STA_INFO_TX_FAILED])
    if sinfo[nl80211.NL80211_STA_INFO_SIGNAL]:
        # Signal level is saved as an 8-bit byte, so we convert it to a signed integer
        raw_signal = nla_get_u8(sinfo[nl80211.NL80211_STA_INFO_SIGNAL])
        if raw_signal > 127:
            station.signal = raw_signal - 256
        else:
            station.signal = raw_signal
    # Append the station to the list of station and iterate to the next result
    results.append(station)
    return libnl.handlers.NL_SKIP

# Callback called when no more messages can be read from the socket
def finish_callback(msg, results):
    # If no station was stored, add value -1 at the end of the result list
    # so that we can determine that the results were processed but that no
    # station was found.
    if len(results) == 0:
        results.append(-1)
    return libnl.handlers.NL_SKIP

# Plugin initialized
def init():
    collectd.info("hostapd plugin : loaded")

# Parse and configure plugin
def config_function(config):
    # Global variables storing conf and shared ressources
    global INTERFACE
    global CLIENTS
    global INTERFACEINDEX
    global VALUES
    global DRIVER_ID
    global SOCKET
    for node in config.children:
        key = node.key.lower()
        value = node.values[0]
        # Save Wi-Fi interface name
        if key == 'interface':
            INTERFACE = value
            collectd.info("Collecting stats for interface %s" % value)
        # Save a client MAC address
        elif key == 'client':
            CLIENTS.append(value)
        else:
            collectd.info("Unknown configuration key %s" % key)
    # No clients configured ? Store everything
    if len(CLIENTS) == 0:
        collectd.info("Collecting detailed stats for all clients")
    else:
        str_clients = ""
        for client in CLIENTS:
            str_clients = str_clients + " " +client
        collectd.info("Collecting stats for clients%s" % str_clients)

    # No Wi-FI interface configured
    if INTERFACE == "":
        collectd.error("No interface set in configuration")
        exit(1)
    else:
        # Get the interface index from the interface name
        pack = struct.pack('16sI', 'wlan0', 0)
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = struct.unpack('16sI', fcntl.ioctl(sk.fileno(), 0x8933, pack))
            INTERFACEINDEX = int(info[1])
        except IOError:
            collectd.error("Unknown network interface !")
            exit(1)
    # Create the netlink socket and resolve the driver id of extension nl80211
    SOCKET = nl_socket_alloc()
    genl_connect(SOCKET)
    DRIVER_ID = genl_ctrl_resolve(SOCKET,b'nl80211')

# Actually send the data
def send_station_stats(station):
    VALUES.type_instance='rx-bytes-'+station.mac_addr
    VALUES.dispatch(values=[station.rx_bytes])
    VALUES.type_instance='tx-bytes-'+station.mac_addr
    VALUES.dispatch(values=[station.tx_bytes])
    VALUES.type_instance='rx-packets-'+station.mac_addr
    VALUES.dispatch(values=[station.rx_packets])
    VALUES.type_instance='tx-packets-'+station.mac_addr
    VALUES.dispatch(values=[station.tx_packets])
    VALUES.type_instance='tx-failure-'+station.mac_addr
    VALUES.dispatch(values=[station.tx_failed])
    VALUES.type_instance='signal-'+station.mac_addr
    VALUES.dispatch(values=[station.signal])

# Collectd is closing, close the netlink socket
def terminate_function():
    collectd.info("Terminating Hostapd plugin")
    nl_socket_free(SOCKET)
    del(SOCKET)

# Collect and send data every n seconds
def read_function():
    # Initialize the message sent by netlink socket
    msg = nlmsg_alloc()
    # Use command CMD_GET_STATION to retreive the connected stations attributes
    # With Hostapd, the connected stations are the clients
    # See https://git.kernel.org/pub/scm/linux/kernel/git/linville/wireless.git/tree/include/uapi/linux/nl80211.h?id=HEAD#n222
    genlmsg_put(msg, 0, 0, DRIVER_ID, 0, NLM_F_DUMP, nl80211.NL80211_CMD_GET_STATION, 0)
    # Set the network interface of the device we are working with
    # See https://git.kernel.org/pub/scm/linux/kernel/git/linville/wireless.git/tree/include/uapi/linux/nl80211.h?id=HEAD#n1032
    nla_put_u32(msg, nl80211.NL80211_ATTR_IFINDEX, INTERFACEINDEX)
    # Finalize and transmit message
    nl_send_auto(SOCKET, msg)
    # This list will contain the results of the kernel
    results = []
    # Bind the callbacks methods for events NL_CB_VALID and NL_CB_FINISH
    cb = libnl.handlers.nl_cb_alloc(libnl.handlers.NL_CB_DEFAULT)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_VALID , libnl.handlers.NL_CB_CUSTOM, getStationInfo_callback, results)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_FINISH, libnl.handlers.NL_CB_CUSTOM, finish_callback, results)
    # Receive messages from Kernel
    nl_recvmsgs(SOCKET, cb)
    while len(results) == 0:
        continue
    # Configure the collectd data sending object
    VALUES.plugin="hostapd"
    VALUES.type='gauge'
    VALUES.type_instance='stations-count'
    # If no clients are connected, just send 0 to the metrics storage backend,
    # otherwise, send the count and the attributes of clients
    if results[-1] == -1:
        VALUES.dispatch(values=[0])
    else:
        VALUES.dispatch(values=[len(results)])
        # Browse the stations returned by the kernel
        for station in results:
            # If we shouldn't send data for every clients, we check the MAC address
            if len(CLIENTS)>0:
                if station.mac_addr in CLIENTS:
                    send_station_stats(station)
            # If not, just send the data
            else:
                send_station_stats(station)

    # Clean a few values to avoid memory leak
    del(msg)
    del(cb)
    del(results)

# Register various functions called during the various stages of the daemon
collectd.register_init(init)
collectd.register_config(config_function)
collectd.register_read(read_function)
collectd.register_shutdown(terminate_function)