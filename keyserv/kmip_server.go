// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/keydb"
	"github.com/HouzuoGuo/cryptctl/kmip/structure"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"log"
	"net"
	"reflect"
	"strings"
	"time"
)

const (
	LenKMIPRandomPass = 256 // length of random password validated by KMIP server
)

// Create a new disk encryption key out of entropy from cryptographic random pool.
func GetNewDiskEncryptionKeyBits() []byte {
	random := make([]byte, KMIPAESKeySizeBits/8)
	if _, err := rand.Read(random); err != nil {
		log.Fatalf("GetNewDiskEncryptionKeyBits: system is out of entropy - %v", err)
	}
	return random
}

/*
A partially implemented KMIP protocol server that creates and serves encryption keys upon request. The implementation
is specifically tailored to the requirements of RPC server, hence it does not validate client certificate and only relies
on a long random password for authentication.
*/
type KMIPServer struct {
	DB                *keydb.DB    // key content database
	Listener          net.Listener // listener for client connections
	TLSConfig         *tls.Config  // TLS certificate chain and private key
	PasswordChallenge []byte       // a random hex-encoded string secret that must be presented by KMIP client as authentication password
}

func NewKMIPServer(db *keydb.DB, certFilePath, certKeyPath string) (*KMIPServer, error) {
	server := &KMIPServer{
		DB:        db,
		TLSConfig: new(tls.Config),
	}
	serverID, err := tls.LoadX509KeyPair(certFilePath, certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("NewKMIPClient: failed to load client certificate/key - %v", err)
	}
	server.TLSConfig.Certificates = []tls.Certificate{serverID}
	return server, nil
}

// Start KMIP server's listener.
func (srv *KMIPServer) Listen() error {
	// KMIP challenge is similar to shutdown challenge, but it is encoded into string.
	randPass := make([]byte, LenKMIPRandomPass)
	if _, err := rand.Read(randPass); err != nil {
		return err
	}
	// In protocol specification, KMIP authentication password has to be a text string, hence the password challenge is encoded here.
	srv.PasswordChallenge = []byte(hex.EncodeToString(randPass))
	var err error
	srv.Listener, err = tls.Listen("tcp", "localhost:0", srv.TLSConfig)
	if err != nil {
		return err
	}
	log.Printf("KMIPServer.Listen: listening on 127.0.0.1:%d", srv.GetPort())
	return nil
}

// Process incoming KMIP requests, block caller until listener is told to shut down.
func (srv *KMIPServer) HandleConnections() {
	for {
		conn, err := srv.Listener.Accept()
		if err != nil {
			log.Printf("KMIPServer.Listen: quit now - %v", err)
			return
		}
		go srv.HandleConnection(conn)
	}
}

// Return the TCP port server is listening on.
func (srv *KMIPServer) GetPort() int {
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// Close listener and shutdown service.
func (srv *KMIPServer) Shutdown() {
	if listener := srv.Listener; listener != nil {
		srv.Listener.Close()
	}
}

/*
Converse with KMIP client.
This KMIP server is made only for cryptctl's own KMIP client, hence a lot of validation work are skipped intentionally.
Normally KMIP service is capable of handling more than one requests per connection, but cryptctl's own KMIP client only
submits one request per connection.
*/
func (srv *KMIPServer) HandleConnection(conn net.Conn) {
	defer func() {
		/*
		 In the unlikely case that user connects a fully featured KMIP client to this server and the client
		 unexpectedly triggers a buffer handling issue, the error is logged here and then ignored.
		*/
		if r := recover(); r != nil {
			log.Printf("KMIPServer.HandleConnection: panic occured with client %s - %v", conn.RemoteAddr().String(), r)
		}
	}()
	defer conn.Close()
	var err error
	var successfulDecodeAttempt structure.SerialisedItem
	decodeAttempts := []structure.SerialisedItem{&structure.SCreateRequest{}, &structure.SGetRequest{}, &structure.SDestroyRequest{}}
	log.Printf("KMIPServer.HandleConnection: connected from %s", conn.RemoteAddr().String())
	ttlvItem, err := ReadFullTTLV(conn)
	if err != nil {
		log.Printf("KMIPServer.HandleConnection: IO failure occured with client %s - %v", conn.RemoteAddr().String(), err)
		return
	}
	// Try decoding request into request structures and see which one succeeds
	for _, attempt := range decodeAttempts {
		if decodeErr := attempt.DeserialiseFromTTLV(ttlvItem); decodeErr == nil {
			successfulDecodeAttempt = attempt
			break
		}
	}
	if successfulDecodeAttempt == nil {
		err = fmt.Errorf("Server does not understand request from client %s", conn.RemoteAddr())
		goto Error
	}
	if err = srv.HandleRequest(successfulDecodeAttempt, conn); err != nil {
		goto Error
	}
	return
Error:
	log.Printf("KMIPServer.HandleConnection: error occured with client %s - %v", conn.RemoteAddr().String(), err)
}

// Try to match KMIP request's password with server's challenge. If there is a mismatch, return an error.
func (srv *KMIPServer) CheckPassword(header structure.SRequestHeader) error {
	// Username is intentionally ignored since password alone authorises client KMIP access.
	providedPass := []byte(header.SAuthentication.SCredential.SCredentialValue.TPassword.Value)
	if subtle.ConstantTimeCompare(providedPass, []byte(srv.PasswordChallenge)) != 1 {
		return errors.New("KMIP password mismatch")
	}
	return nil
}

/*
Handle a KMIP request, produce a response structure and send it back to client.
*/
func (srv *KMIPServer) HandleRequest(req structure.SerialisedItem, conn net.Conn) (err error) {
	defer func() {
		/*
			The KMIP request only comes from cryptctl program itself, so all type assertions and attributes
			will function properly. This crash recovery routine guards against a crash caused by programming errors.
		*/
		if r := recover(); r != nil {
			err = fmt.Errorf("KMIPServer.HandleRequest: panic - %v", r)
		}
	}()
	var resp structure.SerialisedItem
	switch t := req.(type) {
	case *structure.SCreateRequest:
		if err = srv.CheckPassword(t.SRequestHeader); err == nil {
			resp, err = srv.HandleCreateRequest(t)
		}
	case *structure.SGetRequest:
		if err := srv.CheckPassword(t.SRequestHeader); err == nil {
			resp, err = srv.HandleGetRequest(t)
		}
	case *structure.SDestroyRequest:
		if err := srv.CheckPassword(t.SRequestHeader); err == nil {
			resp, err = srv.HandleDestroyRequest(t)
		}
	default:
		err = fmt.Errorf("KMIPServer.HandleRequest: unknown request type %s", reflect.TypeOf(req).String())
	}
	log.Printf("KMIPServer.HandleRequest: handled request type %s from %s, err is %v", reflect.TypeOf(req).String(), conn.RemoteAddr().String(), err)
	if err == nil {
		conn.SetWriteDeadline(time.Now().Add(KMIPTimeoutSec * time.Second))
		_, err = conn.Write(ttlv.EncodeAny(resp.SerialiseToTTLV()))
	}
	return
}

// Handle a KMIP create key request by generating the key as requested and place the key in a database record.
func (srv *KMIPServer) HandleCreateRequest(req *structure.SCreateRequest) (*structure.SCreateResponse, error) {
	var keyName string
	for _, attr := range req.SRequestBatchItem.SRequestPayload.(*structure.SRequestPayloadCreate).STemplateAttribute.Attributes {
		if attr.TAttributeName.Value == structure.ValAttributeNameKeyName {
			keyName = attr.AttributeValue.(*ttlv.Structure).Items[0].(*ttlv.Text).Value
		}
	}
	/*
		Insert a rather blank record with only a disk UUID and generated encryption key.
		RPC server will then fill up the stored record with client computer details, such as its host name and disk UUID.
	*/
	creationTime := time.Now()
	kmipID, err := srv.DB.Upsert(keydb.Record{
		/*
			Name prefix explains key's origin to make it more visible when stored in an external KMIP appliance.
			But key database only recognises UUID, there's no need for a prefix to be stored in key database.
		*/
		UUID:         strings.TrimPrefix(keyName, KeyNamePrefix),
		CreationTime: creationTime,
		Key:          GetNewDiskEncryptionKeyBits(),
	})
	log.Printf("KMIPServer.HandleCreateRequest: just created a key named \"%s\" ID \"%s\"", keyName, kmipID)
	if err != nil {
		return nil, err
	}
	// By KMIP protocol convention, respond with with the sequence number of newly created key
	ret := structure.SCreateResponse{
		SResponseHeader: structure.SResponseHeader{
			SVersion: structure.SProtocolVersion{
				IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
				IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
			},
			TTimestamp:  ttlv.DateTime{Time: creationTime},
			IBatchCount: ttlv.Integer{Value: 1},
		},
		SResponseBatchItem: structure.SResponseBatchItem{
			EOperation:    ttlv.Enumeration{Value: structure.ValOperationCreate},
			EResultStatus: ttlv.Enumeration{Value: structure.ValResultStatusSuccess},
			SResponsePayload: &structure.SResponsePayloadCreate{
				EObjectType: ttlv.Enumeration{Value: structure.ValObjectTypeSymmetricKey},
				TUniqueID:   ttlv.Text{Value: kmipID},
			},
		},
	}
	return &ret, nil
}

// Handle a KMIP get request by responding with key content.
func (srv *KMIPServer) HandleGetRequest(req *structure.SGetRequest) (*structure.SGetResponse, error) {
	kmipID := req.SRequestBatchItem.SRequestPayload.(*structure.SRequestPayloadGet).TUniqueID.Value
	rec, found := srv.DB.GetByID(kmipID)
	var ret *structure.SGetResponse
	if found {
		ret = &structure.SGetResponse{
			SResponseHeader: structure.SResponseHeader{
				SVersion: structure.SProtocolVersion{
					IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
					IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
				},
				TTimestamp:  ttlv.DateTime{Time: rec.CreationTime},
				IBatchCount: ttlv.Integer{Value: 1},
			},
			SResponseBatchItem: structure.SResponseBatchItem{
				EOperation:    ttlv.Enumeration{Value: structure.ValOperationGet},
				EResultStatus: ttlv.Enumeration{Value: structure.ValResultStatusSuccess},
				SResponsePayload: &structure.SResponsePayloadGet{
					EObjectType: ttlv.Enumeration{Value: structure.ValObjectTypeSymmetricKey},
					TUniqueID:   ttlv.Text{Value: kmipID},
					SSymmetricKey: structure.SSymmetricKey{
						SKeyBlock: structure.SKeyBlock{
							EFormatType: ttlv.Enumeration{Value: structure.ValKeyFormatTypeRaw},
							SKeyValue: structure.SKeyValue{
								BKeyMaterial: ttlv.Bytes{Value: rec.Key},
							},
							ECryptoAlgorithm: ttlv.Enumeration{Value: structure.ValCryptoAlgoAES},
							ECryptoLen:       ttlv.Integer{Value: int32(len(rec.Key))},
						},
					},
				},
			},
		}
	} else {
		ret = &structure.SGetResponse{
			SResponseHeader: structure.SResponseHeader{
				SVersion: structure.SProtocolVersion{
					IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
					IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
				},
				TTimestamp:  ttlv.DateTime{Time: rec.CreationTime},
				IBatchCount: ttlv.Integer{Value: 1},
			},
			SResponseBatchItem: structure.SResponseBatchItem{
				EOperation:     ttlv.Enumeration{Value: structure.ValOperationGet},
				EResultStatus:  ttlv.Enumeration{Value: structure.ValResultStatusFailed},
				EResultReason:  ttlv.Enumeration{Value: structure.ValResultReasonNotFound},
				EResultMessage: ttlv.Text{Value: "cannot find a key with matching sequence number"},
			},
		}
	}
	return ret, nil
}

// Handle a KMIP destroy request by removing the key record entirely from memory and disk.
func (srv *KMIPServer) HandleDestroyRequest(req *structure.SDestroyRequest) (*structure.SDestroyResponse, error) {
	kmipID := req.SRequestBatchItem.SRequestPayload.(*structure.SRequestPayloadDestroy).TUniqueID.Value
	rec, found := srv.DB.GetByID(kmipID)
	var ret *structure.SDestroyResponse
	if found {
		ret = &structure.SDestroyResponse{
			SResponseHeader: structure.SResponseHeader{
				SVersion: structure.SProtocolVersion{
					IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
					IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
				},
				TTimestamp:  ttlv.DateTime{Time: rec.CreationTime},
				IBatchCount: ttlv.Integer{Value: 1},
			},
			SResponseBatchItem: structure.SResponseBatchItem{
				EOperation:    ttlv.Enumeration{Value: structure.ValOperationDestroy},
				EResultStatus: ttlv.Enumeration{Value: structure.ValResultStatusSuccess},
				SResponsePayload: &structure.SResponsePayloadDestroy{
					TUniqueID: ttlv.Text{Value: kmipID},
				},
			},
		}
	} else {
		ret = &structure.SDestroyResponse{
			SResponseHeader: structure.SResponseHeader{
				SVersion: structure.SProtocolVersion{
					IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
					IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
				},
				TTimestamp:  ttlv.DateTime{Time: rec.CreationTime},
				IBatchCount: ttlv.Integer{Value: 1},
			},
			SResponseBatchItem: structure.SResponseBatchItem{
				EOperation:     ttlv.Enumeration{Value: structure.ValOperationDestroy},
				EResultStatus:  ttlv.Enumeration{Value: structure.ValResultStatusFailed},
				EResultReason:  ttlv.Enumeration{Value: structure.ValResultReasonNotFound},
				EResultMessage: ttlv.Text{Value: "cannot find a key with matching sequence number"},
			},
		}
	}
	return ret, nil
}
