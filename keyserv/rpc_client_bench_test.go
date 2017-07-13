package keyserv

import (
	"runtime"
	"testing"
)

func BenchmarkSaveKey(b *testing.B) {
	client, _, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if _, err := client.CreateKey(CreateKeyReq{
			Password:         HashPassword(salt, TEST_RPC_PASS),
			Hostname:         "localhost",
			UUID:             "aaa",
			MountPoint:       "/a",
			MountOptions:     []string{"ro", "noatime"},
			MaxActive:        -1,
			AliveIntervalSec: 1,
			AliveCount:       4,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkAutoRetrieveKey(b *testing.B) {
	client, _, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if resp, err := client.AutoRetrieveKey(AutoRetrieveKeyReq{
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(resp.Granted) != 1 {
			b.Fatal(err, resp)
		}
	}
	b.StopTimer()
}

func BenchmarkManualRetrieveKey(b *testing.B) {
	client, _, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all transactions in a single goroutine
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
			Password: HashPassword(salt, TEST_RPC_PASS),
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(resp.Granted) != 1 {
			b.Fatal(err, resp)
		}
	}
	b.StopTimer()
}

func BenchmarkReportAlive(b *testing.B) {
	client, _, tearDown := StartTestServer(b)
	defer tearDown(b)
	// Retrieve server's password salt
	salt, err := client.GetSalt()
	if err != nil {
		b.Fatal(err)
	}
	// Run all benchmark operations in a single goroutine to know the real performance
	oldMaxprocs := runtime.GOMAXPROCS(-1)
	defer runtime.GOMAXPROCS(oldMaxprocs)
	runtime.GOMAXPROCS(1)
	if _, err := client.CreateKey(CreateKeyReq{
		Password:         HashPassword(salt, TEST_RPC_PASS),
		Hostname:         "localhost",
		UUID:             "aaa",
		MountPoint:       "/a",
		MountOptions:     []string{"ro", "noatime"},
		MaxActive:        -1,
		AliveIntervalSec: 1,
		AliveCount:       4,
	}); err != nil {
		b.Fatal(err)
	}
	// Retrieve the key so that this computer becomes eligible to send alive messages
	if resp, err := client.ManualRetrieveKey(ManualRetrieveKeyReq{
		Password: HashPassword(salt, TEST_RPC_PASS),
		UUIDs:    []string{"aaa"},
		Hostname: "localhost",
	}); err != nil || len(resp.Granted) != 1 {
		b.Fatal(err, resp)
	}
	b.ResetTimer()
	// The benchmark will run all RPC operations consecutively
	for i := 0; i < b.N; i++ {
		if rejected, err := client.ReportAlive(ReportAliveReq{
			UUIDs:    []string{"aaa"},
			Hostname: "localhost",
		}); err != nil || len(rejected) > 0 {
			b.Fatal(err, rejected)
		}
	}
	b.StopTimer()
}
