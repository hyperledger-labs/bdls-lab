package bdls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	fmt "fmt"
	"io"
	"log"
	math "math"
	mrand "math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/yonggewang/bdls/crypto/blake2b"
	"github.com/davecgh/go-spew/spew"
	proto "github.com/gogo/protobuf/proto"
	"github.com/olekukonko/tablewriter"
	"github.com/stretchr/testify/assert"
)

// init will listen for 6060 while debugging
func init() {
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
}

// (testing augumented function) SetLeader sets a fixed leader for consensus
func (c *Consensus) SetLeader(key *ecdsa.PublicKey) {
	coord := DefaultPubKeyToIdentity(key)
	c.fixedLeader = &coord
}

// (testing augumented function) AddParticipant add a new participant in the quorum
func (c *Consensus) AddParticipant(key *ecdsa.PublicKey) {
	coord := DefaultPubKeyToIdentity(key)
	for k := range c.participants {
		if c.participants[k] == coord {
			return
		}
	}
	c.participants = append(c.participants, coord)
}

// createConsensus creates a valid consensus object with given height & round and random state
// the c.particpants[0] will always be the consensus's publickey
func createConsensus(t *testing.T, height uint64, round uint64, quorum []*ecdsa.PublicKey) *Consensus {
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// mock data
	initialData := make([]byte, 1024)
	_, err = io.ReadFull(rand.Reader, initialData)
	assert.Nil(t, err)

	// mock config
	config := new(Config)
	config.Epoch = time.Now()
	config.CurrentHeight = height
	config.PrivateKey = privateKey
	config.StateCompare = func(a State, b State) int { return bytes.Compare(a, b) }

	config.StateValidate = func(a State) bool { return true }

	// add all input keys as the quorum
	config.Participants = []Identity{DefaultPubKeyToIdentity(&privateKey.PublicKey)}
	// and myself
	for _, pubkey := range quorum {
		config.Participants = append(config.Participants, DefaultPubKeyToIdentity(pubkey))
	}

	consensus := new(Consensus)
	consensus.init(config)
	consensus.switchRound(round)

	return consensus
}

// TestProposeMultipleRoundChanges for OOM attack
func TestProposeMultipleRoundChanges(t *testing.T) {
	t.Log("a participant propose multiple <roundchange> in different rounds")
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	consensus := createConsensus(t, 1, 0, []*ecdsa.PublicKey{&privateKey.PublicKey})
	state := make([]byte, 1024)
	_, err = io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, signedRc, privateKey := createRoundChangeMessageState(t, 2, 0, state)
	consensus.AddParticipant(&privateKey.PublicKey)

	highest := uint64(0)
	for i := 0; i < 10000; i++ {
		round := uint64(mrand.Int())
		if round > highest {
			highest = round
		}
		// change round and re-sign
		m.Round = round
		signedRc.Sign(m, privateKey)

		bts, err := proto.Marshal(signedRc)
		assert.Nil(t, err)
		_ = consensus.ReceiveMessage(bts, time.Now())
	}

	// count messages
	count := 0
	var lastOne messageTuple
	for elem := consensus.rounds.Front(); elem != nil; elem = elem.Next() {
		round := elem.Value.(*consensusRound)
		count += len(round.roundChanges)
		if elem.Next() == nil {
			assert.Equal(t, 1, len(round.roundChanges))
			lastOne = round.roundChanges[0]
		}
	}

	assert.Equal(t, 1, count)
	assert.Equal(t, highest, lastOne.Message.Round)
}

func TestMultipleCommits(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	consensus := createConsensus(t, 0, 0, []*ecdsa.PublicKey{&privateKey.PublicKey})
	state := make([]byte, 1024)
	_, signed, _ := createCommitMessageSigner(t, 1, 0, state, privateKey)

	// hack to set current round status
	// add 20 random participants to prevent from height decide
	for i := 0; i < 20; i++ {
		privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
		assert.Nil(t, err)
		consensus.AddParticipant(&privateKey.PublicKey)
	}
	consensus.currentRound.Stage = stageCommit
	consensus.currentRound.LockedState = state
	consensus.currentRound.LockedStateHash = consensus.stateHash(state)

	bts, err := proto.Marshal(signed)
	assert.Nil(t, err)

	// and add all messages
	for i := 0; i < 10000; i++ {
		err = consensus.ReceiveMessage(bts, time.Now())
		assert.Nil(t, err)
	}

	// count messages
	count := 0
	for elem := consensus.rounds.Front(); elem != nil; elem = elem.Next() {
		round := elem.Value.(*consensusRound)
		count += len(round.commits)
		if elem.Next() == nil {
			assert.Equal(t, 1, len(round.commits))
		}
	}
	assert.Equal(t, 1, count)
}

func TestMaximalLocked(t *testing.T) {
	consensus := createConsensus(t, 0, 0, nil)

	for i := 0; i < 1000; i++ {
		m, _, _, _ := createLockMessage(t, 20, 1, 0, 1, 0)
		consensus.locks = append(consensus.locks, messageTuple{Message: m})
	}

	maximal := consensus.maximalLocked()
	for k := range consensus.locks {
		assert.True(t, consensus.stateCompare(maximal, consensus.locks[k].Message.State) >= 0)
	}
}

func TestRoundSequentiality(t *testing.T) {
	t.Log("test getRound() with random number, and round list is sequential")
	consensus := createConsensus(t, 0, 0, nil)
	var round uint64
	for i := 0; i < 10000; i++ {
		_ = binary.Read(rand.Reader, binary.LittleEndian, &round)
		consensus.getRound(round, false)
	}

	// sequentiality check
	var last = consensus.rounds.Front()
	for elem := last.Next(); elem != nil; elem = elem.Next() {
		assert.LessOrEqual(t, last.Value.(*consensusRound).RoundNumber, elem.Value.(*consensusRound).RoundNumber)
		last = elem
	}
}

func TestLockMessageRoundSwitch(t *testing.T) {
	t.Log("test switching to higher rounds using <lock> message and replace locks")
	_, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 10, 1, 10)
	consensus := createConsensus(t, 0, 1, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	//  round switch to 10
	consensus.AddParticipant(&privateKey.PublicKey)

	bts, err := proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Nil(t, err)
	// assert length of locks to 1
	assert.Equal(t, 1, len(consensus.locks))

	// round switch to 11 with new B', resetting particpants
	consensus.participants = nil
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 11, 1, 11)
	consensus.AddParticipant(&privateKey.PublicKey)
	consensus.SetLeader(&privateKey.PublicKey)

	for k := range proofKeys {
		consensus.AddParticipant(proofKeys[k])
	}

	bts, err = proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Nil(t, err)
	// assert length of locks to 2
	assert.Equal(t, 2, len(consensus.locks))

	// round switch to 12 with old B', resetting particpants
	consensus.participants = nil
	_, sp, privateKey, proofKeys = createLockMessageState(t, 20, m.State, 1, 12, 1, 12)
	consensus.AddParticipant(&privateKey.PublicKey)
	consensus.SetLeader(&privateKey.PublicKey)

	for k := range proofKeys {
		consensus.AddParticipant(proofKeys[k])
	}

	bts, err = proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Nil(t, err)
	// assert length of locks to 2
	assert.Equal(t, 2, len(consensus.locks))
}

func TestLockReleaseMessageRoundSwitch(t *testing.T) {
	t.Log("test switching to higher rounds using <lock-release> message and replace locks")
	_, sp, privateKey, proofKeys := createLockReleaseMessage(t, 20, 1, 10, 1, 10)
	consensus := createConsensus(t, 0, 1, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)
	consensus.currentRound.Stage = stageLockRelease

	//  round switch to 10
	consensus.AddParticipant(&privateKey.PublicKey)

	bts, err := proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Nil(t, err)

	// round switch to 11,  resetting particpants
	consensus.participants = nil
	_, sp, privateKey, proofKeys = createLockReleaseMessage(t, 20, 1, 11, 1, 11)
	consensus.AddParticipant(&privateKey.PublicKey)
	consensus.SetLeader(&privateKey.PublicKey)

	for k := range proofKeys {
		consensus.AddParticipant(proofKeys[k])
	}

	bts, err = proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Nil(t, err)

	// assert length of locks to 1
	assert.Equal(t, 1, len(consensus.locks))
}

func TestStageChangeLeader(t *testing.T) {
	testStageChange(t, true)
}

func TestStageChangeNonLeader(t *testing.T) {
	testStageChange(t, false)
}

func testStageChange(t *testing.T, leader bool) {
	t.Log("test lockTimeout stage changing")
	quorum := 20
	consensus := createConsensus(t, 0, 0, nil)
	if leader {
		consensus.SetLeader(&consensus.privateKey.PublicKey)
	}

	// create messages & add participant first
	var sps []*SignedProto
	for i := 0; i < quorum; i++ {
		randstate := make([]byte, 1024)
		_, err := io.ReadFull(rand.Reader, randstate)
		assert.Nil(t, err)
		_, signed, priv := createRoundChangeMessageState(t, 1, 1, randstate)
		consensus.AddParticipant(&priv.PublicKey)
		sps = append(sps, signed)
	}

	// receive quorum <roundchange> messages
	for i := 0; i < quorum; i++ {
		bts, err := proto.Marshal(sps[i])
		assert.Nil(t, err)
		err = consensus.ReceiveMessage(bts, time.Now())
		assert.Nil(t, err)
	}

	// should be in lockStage
	assert.Equal(t, stageLock, consensus.currentRound.Stage)
	assert.True(t, !consensus.lockTimeout.IsZero())

	// force expire and update
	_ = consensus.Update(time.Now().Add(time.Hour))

	if leader {
		// leader should have switched to stageLockRelease for random content
		assert.Equal(t, stageLockRelease, consensus.currentRound.Stage)
	} else {
		// while non-leader should have switched to stageCommit via timeout
		assert.Equal(t, stageCommit, consensus.currentRound.Stage)
	}

	if !leader {
		// force expire again ,should've switch to lock-release for non-leader
		consensus.Update(time.Now().Add(2 * time.Hour))
		assert.Equal(t, stageLockRelease, consensus.currentRound.Stage)
	}

	// force expire again ,should've switch to roundchanging
	_ = consensus.Update(time.Now().Add(3 * time.Hour))
	assert.Equal(t, stageRoundChanging, consensus.currentRound.Stage)

}

func TestCommitTimeout(t *testing.T) {
	t.Log("test commitTimeout stage changing")
	consensus := createConsensus(t, 0, 0, nil)
	consensus.currentRound.Stage = stageCommit

	// add some locked roundchanges
	for i := 0; i < 20; i++ {
		randstate := make([]byte, 1024)
		_, err := io.ReadFull(rand.Reader, randstate)
		assert.Nil(t, err)
		// monotonically increase rounds
		m, signed, _ := createRoundChangeMessageState(t, 1, uint64(i), randstate)
		consensus.locks = append(consensus.locks, messageTuple{Message: m, Signed: signed})
	}

	consensus.commitTimeout = time.Now()
	// force expire and update
	consensus.Update(time.Now().Add(time.Hour))
	// should change to stageLockRelease
	assert.Equal(t, stageLockRelease, consensus.currentRound.Stage)
	assert.Equal(t, 1, len(consensus.locks))
}

///////////////////////////////////////////////////////////////////////////////
//
// consensus functional tests via IPC
//
///////////////////////////////////////////////////////////////////////////////
type testParam struct {
	numPeers        int
	numParticipants int
	stopHeight      int
	latency         time.Duration
	expectedLatency time.Duration
}

func TestConsensusTableFormat(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
	}
	beginTest(t, params)
}

func TestConsensusFull20Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        20,
			numParticipants: 20,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}
	beginTest(t, params)
}

func TestConsensusFull30Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        30,
			numParticipants: 30,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        30,
			numParticipants: 30,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        30,
			numParticipants: 30,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        30,
			numParticipants: 30,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        30,
			numParticipants: 30,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusFull50Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusFull80Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        80,
			numParticipants: 80,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        80,
			numParticipants: 80,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        80,
			numParticipants: 80,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        80,
			numParticipants: 80,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        80,
			numParticipants: 80,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}
func TestConsensusOnlyFull100Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
	}
	beginTest(t, params)
}

func TestConsensusFull100Participants(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        100,
			numParticipants: 100,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial20Participants(t *testing.T) {
	n := 2*(20-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 20,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 20,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 20,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 20,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 20,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial30Participants(t *testing.T) {
	n := 2*(30-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 30,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 30,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 30,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 30,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 30,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial50Participants(t *testing.T) {
	n := 2*(50-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial80Participants(t *testing.T) {
	n := 2*(80-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 80,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 80,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 80,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 80,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 80,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial100Participants(t *testing.T) {
	n := 2*(100-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 100,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 100,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 200 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 100,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 300 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 100,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 100,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 1000 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusFull50LatencyHigherThanExpected(t *testing.T) {
	var params = []testParam{
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 50 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 150 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 250 * time.Millisecond,
		},
		{
			numPeers:        50,
			numParticipants: 50,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func TestConsensusPartial50LatencyHigherThanExpected(t *testing.T) {
	n := 2*(50-1)/3 + 1
	var params = []testParam{
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         100 * time.Millisecond,
			expectedLatency: 50 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         200 * time.Millisecond,
			expectedLatency: 100 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         300 * time.Millisecond,
			expectedLatency: 150 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         500 * time.Millisecond,
			expectedLatency: 250 * time.Millisecond,
		},
		{
			numPeers:        n,
			numParticipants: 50,
			stopHeight:      5,
			latency:         1000 * time.Millisecond,
			expectedLatency: 500 * time.Millisecond,
		},
	}

	beginTest(t, params)
}

func beginTest(t *testing.T, params []testParam) {
	var table = tablewriter.NewWriter(os.Stderr)
	table.SetHeader([]string{"DECIDE.AVG", "DECIDE.ROUNDS", "PEER.NUM", "PJ.NUM", "NET.MSGS", "NET.BYTES", "MSG.AVGSIZE", "NET.MSGRATE", "PEER.RATE", "DELAY.MIN", "DELAY.MAX", "DELAY.AVG", "DELAY.EXP"})
	table.SetAutoFormatHeaders(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for i := 0; i < len(params); i++ {
		t.Logf("-=-=- TESTING CASE: [%v/%v] -=-=-", i+1, len(params))
		v := testConsensus(t, &params[i])
		table.Append(v)
	}
	table.Render()
}

func testConsensus(t *testing.T, param *testParam) []string {
	t.Logf("PARAMETERS: %+v", spew.Sprintf("%+v", param))
	// initial data
	initialState := make([]byte, 1024)
	io.ReadFull(rand.Reader, initialState)
	h := blake2b.Sum256(initialState)
	t.Logf("%v genesis state for height: 0, hash:%v", time.Now().Format("15:04:05"), hex.EncodeToString(h[:]))

	var participants []*ecdsa.PrivateKey
	var coords []Identity
	for i := 0; i < param.numParticipants; i++ {
		privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		participants = append(participants, privateKey)
		coords = append(coords, DefaultPubKeyToIdentity(&privateKey.PublicKey))
	}

	// begin proposing
	var totalConfirms int64
	var totalDuration int64
	var totalMessages int64
	var totalBytes int64

	var minLatency = int64(math.MaxInt64)
	var maxLatency = int64(0)
	var allLatency = int64(0)
	var rounds []string
	start := time.Now()

	// consensus for one height
	consensusOneHeight := func(currentHeight uint64, currentState []byte) {
		// randomize participants, fisher yates shuffle
		n := uint32(len(participants))
		for i := n - 1; i > 0; i-- {
			var j uint32
			binary.Read(rand.Reader, binary.LittleEndian, &j)
			j = j % (i + 1)
			participants[i], participants[j] = participants[j], participants[i]
		}

		var peers []*IPCPeer
		// same epoch
		epoch := time.Now()
		// create numPeer peers
		for i := 0; i < param.numPeers; i++ {
			// initiate config
			config := new(Config)
			config.Epoch = epoch
			config.CurrentHeight = currentHeight
			config.PrivateKey = participants[i] // randomized participants
			config.Participants = coords        // keep all coords

			// should replace with real function
			config.StateCompare = func(a State, b State) int { return bytes.Compare(a, b) }
			config.StateValidate = func(a State) bool { return true }

			// consensus
			consensus, err := NewConsensus(config)
			assert.Nil(t, err)
			consensus.SetLatency(param.expectedLatency)

			peers = append(peers, NewIPCPeer(consensus, param.latency))
		}

		// establish full connected mesh
		numConns := 0
		for i := 0; i < len(peers); i++ {
			for j := 0; j < len(peers); j++ {
				if i != j {
					ok := peers[i].c.Join(peers[j])
					assert.True(t, ok)
					numConns++
				}
			}
		}

		// after all connections have established, start updater,
		// this must be done after connection establishement
		// to prevent from missing <decide> messages
		for i := 0; i < len(peers); i++ {
			peers[i].Update()
		}

		var wg sync.WaitGroup
		wg.Add(param.numPeers)

		// selected random peers
		for k := range peers {
			go func(i int) {
				peer := peers[i]
				defer wg.Done()

				data := make([]byte, 1024)
				io.ReadFull(rand.Reader, data)
				peer.Propose(data)

				for {
					newHeight, newRound, newState := peer.GetLatestState()
					if newHeight > currentHeight {
						now := time.Now()
						atomic.AddInt64(&totalConfirms, 1)
						atomic.AddInt64(&totalDuration, int64(now.Sub(epoch)))
						// only one peer print the decide
						if i == 0 {
							rounds = append(rounds, fmt.Sprint(newRound))
							h := blake2b.Sum256(newState)
							t.Logf("%v <decide> at height:%v round:%v hash:%v", now.Format("15:04:05"), newHeight, newRound, hex.EncodeToString(h[:]))
						}

						// countings
						atomic.AddInt64(&totalMessages, peer.GetMessageCount())
						atomic.AddInt64(&totalBytes, peer.GetBytesCount())
						min, max, all := peer.GetLatencies()
						if atomic.LoadInt64(&minLatency) > int64(min) {
							atomic.StoreInt64(&minLatency, int64(min))
						}

						if atomic.LoadInt64(&maxLatency) < int64(max) {
							atomic.StoreInt64(&maxLatency, int64(max))
						}

						atomic.AddInt64(&allLatency, int64(all))
						return
					}

					// wait
					<-time.After(20 * time.Millisecond)
				}
			}(k)
		}

		// wait for all peers exit
		wg.Wait()
		// close all peers when waitgroup exit
		for k := range peers {
			peers[k].Close()
		}
	}

	// loop to stopHeight
	for i := 0; i < param.stopHeight; i++ {
		consensusOneHeight(uint64(i), initialState)
	}

	t.Logf("consensus stopped at height:%v for %v peers %v participants", param.stopHeight, param.numPeers, param.numParticipants)
	t.Logf("average confirmation period: %v", time.Duration(totalDuration/totalConfirms))

	t.Logf("network total exchanged message:%v, total bytes:%v, avg msg size:%v",
		totalMessages,
		bytefmt.ByteSize(uint64(totalBytes)),
		bytefmt.ByteSize(uint64(float64(totalBytes)/float64(totalMessages))))

	bps := float64(totalBytes) / float64(param.numPeers) / time.Now().Sub(start).Seconds()
	t.Logf("peer bandwidth required:%v/s", bytefmt.ByteSize(uint64(bps)))

	t.Logf("network latency(min/max/avg): %v/%v/%v", time.Duration(minLatency), time.Duration(maxLatency), time.Duration(allLatency/totalMessages))

	return []string{
		fmt.Sprint(time.Duration(totalDuration / totalConfirms).Truncate(10 * time.Millisecond)),
		strings.Join(rounds, ";"),
		fmt.Sprint(param.numPeers),
		fmt.Sprint(param.numParticipants),
		fmt.Sprint(totalMessages),
		fmt.Sprint(bytefmt.ByteSize(uint64(totalBytes))),
		fmt.Sprint(bytefmt.ByteSize(uint64(float64(totalBytes) / float64(totalMessages)))),
		fmt.Sprintf("%.2f/s", float64(totalMessages)/time.Duration(totalDuration).Seconds()),
		fmt.Sprintf("%v/s", bytefmt.ByteSize(uint64(bps))),
		fmt.Sprint(time.Duration(minLatency).Truncate(10 * time.Microsecond)),
		fmt.Sprint(time.Duration(maxLatency).Truncate(10 * time.Microsecond)),
		fmt.Sprint(time.Duration(allLatency / totalMessages).Truncate(10 * time.Microsecond)),
		fmt.Sprint(param.expectedLatency.Truncate(10 * time.Microsecond)),
	}

}
