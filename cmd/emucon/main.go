package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/yonggewang/bdls"
	"github.com/yonggewang/bdls/agent-tcp"
	"github.com/yonggewang/bdls/crypto/blake2b"
	"github.com/urfave/cli/v2"
)

// A quorum set for consenus
type Quorum struct {
	Keys []*big.Int `json:"keys"` // pem formatted keys
}

func main() {
	app := &cli.App{
		Name:                 "BDLS consensus protocol emulator",
		Usage:                "Generate quorum then emulate participants",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "genkeys",
				Usage: "generate quorum to participant in consensus",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "count",
						Value: 4,
						Usage: "number of participant in quorum",
					},
					&cli.StringFlag{
						Name:  "config",
						Value: "./quorum.json",
						Usage: "output quorum file",
					},
				},
				Action: func(c *cli.Context) error {
					count := c.Int("count")
					quorum := &Quorum{}
					// generate private keys
					for i := 0; i < count; i++ {
						privateKey, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
						if err != nil {
							return err
						}

						quorum.Keys = append(quorum.Keys, privateKey.D)
					}

					file, err := os.Create(c.String("config"))
					if err != nil {
						return err
					}
					enc := json.NewEncoder(file)
					enc.SetIndent("", "\t")
					err = enc.Encode(quorum)
					if err != nil {
						return err
					}
					file.Close()

					log.Println("generate", c.Int("count"), "keys")
					return nil
				},
			},
			{
				Name:  "run",
				Usage: "start a consensus agent",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "listen",
						Value: ":4680",
						Usage: "the client's listening port",
					},
					&cli.IntFlag{
						Name:  "id",
						Value: 0,
						Usage: "the node id, will use the n-th private key in quorum.json",
					},
					&cli.StringFlag{
						Name:  "config",
						Value: "./quorum.json",
						Usage: "the shared quorum config file",
					},
					&cli.StringFlag{
						Name:  "peers",
						Value: "./peers.json",
						Usage: "all peers's ip:port list to connect, as a json array",
					},
				},
				Action: func(c *cli.Context) error {
					// open quorum config
					file, err := os.Open(c.String("config"))
					if err != nil {
						return err
					}
					defer file.Close()

					quorum := new(Quorum)
					err = json.NewDecoder(file).Decode(quorum)
					if err != nil {
						return err
					}

					id := c.Int("id")
					if id >= len(quorum.Keys) {
						return errors.New(fmt.Sprint("cannot locate private key for id:", id))
					}
					log.Println("identity:", id)

					// create configuration
					config := new(bdls.Config)
					config.Epoch = time.Now()
					config.CurrentHeight = 0
					config.StateCompare = func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) }
					config.StateValidate = func(bdls.State) bool { return true }

					for k := range quorum.Keys {
						priv := new(ecdsa.PrivateKey)
						priv.PublicKey.Curve = bdls.S256Curve
						priv.D = quorum.Keys[k]
						priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(priv.D.Bytes())
						// myself
						if id == k {
							config.PrivateKey = priv
						}

						// set validator sequence
						config.Participants = append(config.Participants, bdls.DefaultPubKeyToIdentity(&priv.PublicKey))
					}

					if err := startConsensus(c, config); err != nil {
						return err
					}
					return nil
				},
			},
		},

		Action: func(c *cli.Context) error {
			cli.ShowAppHelp(c)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

// consensus for one round with full procedure
func startConsensus(c *cli.Context, config *bdls.Config) error {
	// create consensus
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		return err
	}
	consensus.SetLatency(200 * time.Millisecond)

	// load endpoints
	file, err := os.Open(c.String("peers"))
	if err != nil {
		return err
	}
	defer file.Close()

	var peers []string
	err = json.NewDecoder(file).Decode(&peers)
	if err != nil {
		return err
	}

	// start listener
	tcpaddr, err := net.ResolveTCPAddr("tcp", c.String("listen"))
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("listening on:", c.String("listen"))

	// initiate tcp agent
	tagent := agent.NewTCPAgent(consensus, config.PrivateKey)
	if err != nil {
		return err
	}

	// start updater
	tagent.Update()

	// passive connection from peers
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			log.Println("peer connected from:", conn.RemoteAddr())
			// peer endpoint created
			p := agent.NewTCPPeer(conn, tagent)
			tagent.AddPeer(p)
			// prove my identity to this peer
			p.InitiatePublicKeyAuthentication()
		}
	}()

	// active connections to peers
	for k := range peers {
		go func(raddr string) {
			for {
				conn, err := net.Dial("tcp", raddr)
				if err == nil {
					log.Println("connected to peer:", conn.RemoteAddr())
					// peer endpoint created
					p := agent.NewTCPPeer(conn, tagent)
					tagent.AddPeer(p)
					// prove my identity to this peer
					p.InitiatePublicKeyAuthentication()
					return
				}
				<-time.After(time.Second)
			}
		}(peers[k])
	}

	lastHeight := uint64(0)

NEXTHEIGHT:
	for {
		data := make([]byte, 1024)
		io.ReadFull(rand.Reader, data)
		tagent.Propose(data)

		for {
			newHeight, newRound, newState := tagent.GetLatestState()
			if newHeight > lastHeight {
				h := blake2b.Sum256(newState)
				log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
				lastHeight = newHeight
				continue NEXTHEIGHT
			}
			// wait
			<-time.After(20 * time.Millisecond)
		}
	}
}
