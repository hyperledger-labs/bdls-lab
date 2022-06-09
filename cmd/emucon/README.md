# Consensus Emulator

## Install

```
$ git clone https://github.com/yonggewang/bdls
$ cd bdls/cmd/emucon
$ go build .
$ ./emucon
NAME:
   BDLS consensus protocol emulator - Generate quorum then emulate participants
 
USAGE:
   emucon [global options] command [command options] [arguments...]

COMMANDS:
   genkeys  generate quorum to participant in consensus
   run      start a consensus agent
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```



## GENERATE CONSENSUS GROUP KEYS

```
$ ./emucon genkeys --count 4

$ ./emucon genkeys --help                                                                   
NAME:
   emucon genkeys - generate quorum to participant in consensus

USAGE:
   emucon genkeys [command options] [arguments...]

OPTIONS:
   --count value   number of participant in quorum (default: 4)
   --config value  output quorum file (default: "./quorum.json")
   --help, -h      show help (default: false)

```



## NODES EMULATION

```
$ ./emucon run --help
NAME:
   emucon run - start a consensus agent

USAGE:
   emucon run [command options] [arguments...]

OPTIONS:
   --listen value  the client's listening port (default: ":4680")
   --id value      the node id, will use the n-th private key in quorum.json (default: 0)
   --config value  the shared quorum config file (default: "./quorum.json")
   --peers value   all peers's ip:port list to connect, as a json array (default: "./peers.json")
   --help, -h      show help (default: false)
```



Create a file named peers.json, like below, which contains 4 different nodes listening on different ports at localhost.

```
$ cat peers.json
["localhost:4680", "localhost:4681","localhost:4682", "localhost:4683"]
```

You can start minimum 4 nodes in 4 different terminal like below:

```
$./emucon run --id 0 --listen ":4680"
$./emucon run --id 1 --listen ":4681"
$./emucon run --id 2 --listen ":4682"
$./emucon run --id 3 --listen ":4683"
```

A succesfully running  node will output something like:

```
$ ./emucon run --id 2 --listen ":4682"
2020/04/10 18:19:15 identity: 2
2020/04/10 18:19:15 listening on: :4682
2020/04/10 18:19:15 connected to peer: 127.0.0.1:4682
2020/04/10 18:19:15 connected to peer: 127.0.0.1:4680
2020/04/10 18:19:15 peer connected from: 127.0.0.1:49204
2020/04/10 18:19:15 connected to peer: 127.0.0.1:4681
2020/04/10 18:19:15 peer connected from: 127.0.0.1:49212
2020/04/10 18:19:15 peer connected from: 127.0.0.1:49216
2020/04/10 18:19:17 <decide> at height:1 round:1 hash:d2d583085a489287a889238229879a7bc3aef2251c39c052d165883687e06db8
2020/04/10 18:19:18 <decide> at height:2 round:1 hash:c430bc8bb8b749717a3d90dd6ee29271694e8ad49f16e0e61b96de145f89d892
2020/04/10 18:19:20 <decide> at height:3 round:1 hash:e21370a2f82d4b0b5a885c5a6f669890d5df9a8caffbce664e519184b1a25c64
```

