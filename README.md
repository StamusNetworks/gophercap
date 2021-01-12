# GopherCap

> Accurate, modular, scalable PCAP manipulation tool written in Go.

GoperCap uses [gopacket](https://github.com/google/gopacket) and [cobra](https://github.com/spf13/cobra) to build a CLI tool for PCAP manipulation. First implemented feature being the ability to concurrently replay offline PCAP files on live network interface. While preserving timestamps between each packet.

It can also calculate metadata for PCAP files and extract files from compressed tarballs (with no intermediate storage requirements).

# Background

Stamus Networks develops [Scirius Security Platform](https://www.stamus-networks.com/scirius-platform) and open-source [Scirius CE](https://github.com/StamusNetworks/scirius), network security platforms. We specialize in  network detection and response solutions which include signature ruleset management, network threat hunting, advanced threat intelligence and data analytics. All leveraging the  Suricata network IDS/IPS/NSM engine.

Historically, we have used [tcpreplay](https://tcpreplay.appneta.com/) with predetermined PPS options. When setting up replay for a particular bigger-than-average PCAP set, we initially tried the typical bash rocket approach. Just read PCAP metadata using capinfos, extract average packet rate and then replay the file at that extracted average rate. Not ideal for developing algorithmic threat detection, but the result should be close enough, right?

```bash
avg_pps=$(capinfos ${pcap} | grep 'Average packet rate' | awk '{print $4}' | tr -d ',')
tcpreplay-edit --pps=$avg_pps --mtu-trunc -i $iface ${pcap}
```

After four days, our replay had only gone through about 10-15% of all PCAP files. Given that entire dataset only spans for three days, we were understandably puzzled. Sure, we were aware that replaying with average rate would flatten out all bursts, but that still seemed too much. But we quickly figured out what happened.

That set was written using [Moloch](https://github.com/aol/moloch) full packet capture. Like Suricata, it reconstructs sessions from the ground up. All the way to the application layer. And like Suricata, it’s multi-threaded. Flow reconstruction 101 - all packets in a flow need to pass through the same worker. No information exchange happens between workers due to the extreme throughput they need to handle, and each worker can write those packets out to a separate PCAP file. But not all flows are created equal. Some workers will see more traffic volume than others, even if the flow balancer is able to distribute roughly the same number of sessions to each thread. One thread would therefore receive a large HTTP file download while another gets a lot of small DNS queries. The first PCAP file will simply rotate faster.

In other words, our script relied on having sequential PCAP files. But the dataset was not sequential at all. Rather, it consisted of N sequential PCAP subsets, where N corresponds to the number of workers configured in Moloch. All in one folder and without worker ID configured as part of the PCAP naming scheme. Not knowing how many workers were used. And we needed to reconstruct it as well as we could, as the dataset was full of sweet simulated attacks, perfect for exercising the algorithmic threat detection we are developing. To put it bluntly, it sucked to be us.

But... 

We can check when a PCAP file begins and ends by simply parsing the first and last packet. [Gopacket](https://github.com/google/gopacket) is pretty cool. It works well, we have have good experience using it. Even better, golang is actually built from ground up for concurrency, and spinning up IO readers that produce to single IO writer via thread-safe channel is a breeze. So, why not just sleep each reader for a duration calculated between global dataset and PCAP start timestamps. We can easily calculate diffs between each packet with `time.Sub()`, and sleep before pushing to writer. [Gopacket even had an example on that (albeit too basic to outright solve our problem)](https://github.com/google/gopacket/blob/master/examples/pcaplay/main.go). And finally, we could implement this feature as subcommand to bigger binary and build our own swiss army knife for all kinds of funky PCAP operations.

Two working days later, we had a prototype replay tool. And after a month of bugfixes and usage in lab we decided to give it to community.

You can read more in [this Stamus Networks blog post](https://www.stamus-networks.com/blog/gophercap), detailing the design more thoroughly.

# Getting started

## Binary packages

Version tagged binaries for GopherCap can be found under **releases** section in github. We currently provide Ubuntu 20.04 and Debian Buster CI builds. Note that very little is different between the builds. We simply separated them to ensure that libpcap version is locked in per platform. Following bash commands can be used to pull latest version download url.

### Ubuntu

```
GOPHER_URL=$(curl --silent "https://api.github.com/repos/StamusNetworks/gophercap/releases/latest" | jq -r '.assets[] | select(.name|startswith("gopherCap-ubuntu-2004-")) | .browser_download_url')
wget $GOPHER_URL
```

### Debian

```
GOPHER_URL=$(curl --silent "https://api.github.com/repos/StamusNetworks/gophercap/releases/latest" | jq -r '.assets[] | select(.name|startswith("gopherCap-debian-buster-")) | .browser_download_url')
wget $GOPHER_URL
```

## Community packages

### Arch linux

Arch User Repository (AUR) package was contributed by a community member. It is not maintained by Stamus Networks. It can be installed with AUR helper like `yay`.

```
yay -Sy gophercap
```

Or by invoking `makepkg`.

```
git clone https://aur.archlinux.org/gophercap.git
cd gophercap
makepkg -si
```

## Build

Building GopherCap is quite easy, assuming some familiarity with Go build system. Currently it only has one Cgo dependency - libpcap. GoperCap needs libpcap to write packets into network interface. Development headers must be present for installing and regular library must be installed for execution.

Ubuntu and Debian: 

```
apt-get update && apt-get install -y libpcap-dev libpcap0.8
```

Arch Linux:

```
pacman -Sy libpcap
```

Then proceed as normal for building a go binary. Get project dependencies.

```
go get -u ./
```

And build the binary.

```
go build -o ./gopherCap ./
```

Or install it to `$GOPATH`.

```
go install
which gopherCap
```

Binary can then be executed directly.

```
gopherCap --help
```

## Basic usage

Each subcommand has embedded usage examples. Refer to those for up to date and more extensive information.

```
gopherCap map --help
```
```
gopherCap replay --help
```
```
gopherCap tarExtract --help
```

Replay functionality requires PCAP files to be mapped first. This will collect metadata, such as first and last timestamp, total number of packets, PPS, etc. Most importantly, timestamp information is needed to calculate global dataset start and delay before reading each PCAP.

```
gopherCap map \
	--dir-src /mnt/pcap \
	--file-suffix "pcap" \
	--dump-json /mnt/pcap/meta.json
```

Note that current implementation needs to iterate over entire PCAP file, for all files in dataset. Thus, mapping can take long. But it only needs to be done once. Afterwards, the `replay` subcommand will simply load the JSON metadata. This needs to be considered when moving or remounting PCAP storage.

```
gopherCap replay \
	--out-interface veth0 \
	--dump-json /mnt/pcap/meta.json
```

### Configuring virtual NIC for testing

Virtual ethernet interface pair can be created with following command. Packets replayed to one interface can be read from another.

```
sudo ip link add veth0 type veth peer name veth1
```

After creation, make sure to activate them.

```
sudo ip link set veth0 up
sudo ip link set veth1 up
```

Use tcpdump to validate replay.

```
sudo tcpdump -i veth1 -n
```

Replay command might crash with following error:

```
FATA[0005] send: Message too long
```

This means packet was bigger than interface MTU. Maximum packet size can be found in metadata JSON. But 9000 is usually a safe MTU size, corresponding to common jumbo packet feature in many network switches.

```
sudo ip link set dev veth0 mtu 9000
sudo ip link set dev veth1 mtu 9000
```

## Docker

Alternatively, you can also build and run gophercap as a docker container.

```
docker build -t stamus/gophercap .
```

Subcommands can then be executed through the image.

```
docker run -ti --rm stamus/gophercap --help
```

You will want to mount PCAP directory as volume.

```
docker run -ti --rm -v /mnt/pcap:/pcaps stamus/gophercap map \
  --dir-src /pcaps \
  --dump-json /pcaps/meta.json
```

For replay, you need to use *host network* rather than default docker bridge. Also, make sure that mapped PCAP paths correspond to in-container mount point, rather than host folder.

```
docker run -ti --rm --network host -v /mnt/pcap:/pcaps stamus/gophercap replay \
  --dump-json /pcaps/meta.json \
  --out-interface veth0
```

## YAML config

All CLI flags can be defined as configuration dictionary in YAML file. See [example configuration](/config/gophercap.yml) for layout. We also provide a subcommand for generating a clean template with default values. However, note that `--config` global flag needs to be used.

```
gopherCap --config <YAML file> <subcommand>
```

Configuration dictionary is organized by subcommand. With options used by multiple subcommands under `global` section. For example, location of mapping JSON file must be synced between `map` and `replay` commands, and thus both use the same config option. However, your mileage might vary with other parameters. You might want to map all PCAP files, but only replay a subset. In that case, you need two configuration files, or you need to override `global.file.regexp` via CLI flag.

# Subcommands

GoperCap uses *cobra* and *viper* libraries to implement a single binary with many subcommands. Similar to many other tools built in Go. Here's overview of currently supported features.

## Map

PCAP metadata mapper. Collects timestamp information needed by replay command, along with other useful information. Such as largest packet size, total packet size, packet count, PPS, etc. Can take a lot of time to complete on bigger datasets, as it needs to iterate over all PCAP files. Thus reason for making this a separate subcommand, rather than wasting time before each replay sequence. PCAPs are processed concurrently on workers. So, the time needed depends on system IO throughput and CPU performance.

```
Usage:
  gopherCap map [flags]

Flags:
      --dir-src string       Source folder for recursive pcap search.
      --file-suffix string   Suffix suffix used for file discovery. (default "pcap")
      --file-workers int     Number of concurrent workers for scanning pcap files. Value less than 1 will map all pcap files concurrently. (default 4)
  -h, --help                 help for map

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "/tmp/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

## Replay

Replay PCAP files to network interface while preserving time difference between packets. Requires files to be mapped beforehand, as the command relies entirely on metadata dump and no file discovery or mapping is performed.

PCAP replay can be sped up or slowed down using timescaling parameters. BPF filter can be applied to written packets.

```
Usage:
  gopherCap replay [flags]

Flags:
  -h, --help                           help for replay
      --loop-count int                 Number of iterations over pcap set. Will run infinitely if 0 or negative value is given. (default 1)
      --loop-infinite                  Loop over pcap files infinitely. Will override --loop-count
      --out-bpf string                 BPF filter to exclude some packets.
      --out-interface string           Network interface to replay to. (default "eth0")
      --time-from string               Start replay from this time.
      --time-modifier float            Modifier for speeding up or slowing down the replay by a factor of X. (default 1)
      --time-scale-duration duration   Duration for time scaling. (default 1h0m0s)
      --time-scale-enabled             Enable time scaling. When enabled, will automatically calculate replay.time.modifier value to replay pcap in specified time window. Overrides replay.time.modifier value. Actual replay is not guaranteed to complete in defined time, As overhead from sleep calculations causes a natural drift.
      --time-to string                 End replay from this time.
      --wait-disable                   Disable initial wait before each PCAP file read. Useful when PCAPs are part of same logical set but not from same capture period.

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "/tmp/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

## Tar extract

While attempting to use gopherCap in offline dev environment, we ran into a little problem. PCAPs were in 1 terabyte gzipped tarball that took 4 terabytes fully uncompressed. More than what was available on hand at the time. And only 1 terabyte subset (300GB compressed) was actually relevant for replay.

This subcommand was written to extract selection of files from tarballs, optionally directly to gzipped file handles. No temporary storage or advanced filesystem level compression needed.

```
Usage:
  gopherCap tarExtract [flags]

Flags:
      --dryrun              Only list files in tarball for regex validation, do not extract.
  -h, --help                help for tarExtract
      --in-tarball string   Input gzipped tarball.
      --out-dir string      Output directory for pcap files.
      --out-gzip            Compress extracted files with gzip.

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "/tmp/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

## Example config

GopherCap uses viper library to build a configuration dictionary. In other words, all CLI flags can be defined in YAML config file. CLI arguments would simply override the config file settings.

```
gopherCap --config ./config.yml exampleConfig
```

## Version

Prints GopherCap version tag. For integrating with CI builds and automated deploy systems, to check if local binary needs to be updated. Default value is `development`.

```
gopherCap version
```

Custom version can be embedded with following build command.

```
export VERSION=<val>
go build -ldflags="-X 'gopherCap/cmd.Version=$VERSION'" -o ./gopherCap ./
```

# Contributing

For all contributions please use a Pull Request on Github or open an issue.
