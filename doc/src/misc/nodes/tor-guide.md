# Set-up a Tor-enabled node

_To connect to Tor, we use [Arti](https://gitlab.torproject.org/tpo/core/arti). 
Arti is an experimental project with incomplete security features. See Arti's 
[roadmap](https://gitlab.torproject.org/tpo/core/arti#roadmap) for more 
information._

<u><b>Note</b></u>: This page is a general guide for `tor` nodes in the DarkFi 
ecosystem and is applicable to other apps such as `taud` and `darkfid`. We use 
`darkirc` as our main example throughout this guide. Commands such as `./darkirc`
and configuration filenames need to be adjusted if using different apps.
If you're using another app, the network configurations remain the same except 
for the seed nodes you connect to.

## Generating configuration files

After compiling, you can start the application so it can spawn its configuration 
file. We use `darkirc` as the application example going forward.

```shell
% ./darkirc
```

`darkirc` creates a configuration file `darkirc_config.toml` by default in 
`~/.config/darkfi/`. You will review and edit this configuration file for your 
preferred network settings. 

## Configure network settings

Modify the network settings located in the `~/.config/darkfi` directory. This 
configuration allows your node to send and receive traffic only via Tor.

<u><b>Note</b></u>: As you modify the file, if you notice some settings are missing, 
simply add them. Some settings may be commented-out by default. In the example 
configurations below, you will find the a placeholder `youraddress.onion` which 
indicates you should replace them with your onion address.

### Outbound node settings

These outbound node settings for your `tor` node configuration is only for
connecting to the network. You will not advertise an external address.

```toml
## connection settings
outbound_connect_timeout = 60
channel_handshake_timeout = 55
channel_heartbeat_interval = 90
outbound_peer_discovery_cooloff_time = 60

## Whitelisted transports for outbound connections
allowed_transports = ["tor", "tor+tls"]

## Seed nodes to connect to 
seeds = [
    "tor://czzulj66rr5kq3uhidzn7fh4qvt3vaxaoldukuxnl5vipayuj7obo7id.onion:5263",
    "tor://vgbfkcu5hcnlnwd2lz26nfoa6g6quciyxwbftm6ivvrx74yvv5jnaoid.onion:5273",
]

## Outbound connection slots
outbound_connections = 8

## Enable transport mixing
transport_mixing = false
```

### Inbound node settings

With these settings your node becomes a Tor inbound node. The `inbound` 
settings are optional, but enabling them will increase the strength and 
reliability of the network. Using Tor, we can host anonymous nodes as Tor hidden 
services. To do this, we need to set up our Tor daemon and create a hidden service.
The following instructions should work on any Linux system.

First, you must install [Tor](https://www.torproject.org/). It can usually be 
installed with your package manager. For example on an `apt` based system we can run:

```
% apt install tor
```

This will install Tor. Now in `/etc/tor/torrc` we can set up the hidden
service. For hosting an anonymous `darkirc` node, set up the following
lines in the file:

```
HiddenServiceDir /var/lib/tor/darkfi_darkirc
HiddenServicePort 25551 127.0.0.1:25551
```

Then restart Tor:

```
% /etc/init.d/tor restart
```

Find the hostname of your hidden service from the directory:

```
% cat /var/lib/tor/darkfi_darkirc/hostname
```

Note your `.onion` address and the ports you used while setting up the
hidden service, and add the following settings to your configuration file:

```toml
## Addresses we want to advertise to peers
external_addrs = ["tor://youraddress.onion:25551"]

## P2P accept addresses
inbound = ["tcp://127.0.0.1:25551"]

## Inbound connection slots
inbound_connections = 64
```

## Connect and test your node

Run `./darkirc`. Welcome to the dark forest.

You can test if your node is configured properly on the network. Use 
[Dnet](../../learn/dchat/network-tools/using-dnet.md) and the 
[ping-tool](../network-troubleshooting.md#ping-tool) to test your node 
connections. You can view if your node is making inbound and outbound connections.

## Troubleshooting

Refer to [Network troubleshooting](../network-troubleshooting.md)
for further troubleshooting resources.