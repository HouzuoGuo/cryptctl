// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/kmip/structure"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"io"
	"log"
	"reflect"
	"time"
)

const (
	KMIPTimeoutSec = 30 // timeout in seconds
	/*
		Both server and client refuse to accept a structure larger than this number. The number is
		reasonable and big enough for all three operations supported by server and client: create, get, and destroy.
	*/
	MaxKMIPStructLen   = 65536
	KMIPAESKeySizeBits = 256 // The only kind of AES encryption key the KMIP server and client will expect to use
	ClientMaxRetry     = 7   // Maximum number of times for client to retry failed KMIP connection.
)

/*
Implement a KMIP client that supports three operations - create, get, destroy.
The client is designed to interoperate not only with KMIPServer that comes with cryptctl, but also with
KMIP servers implemented by other vendors.
*/
type KMIPClient struct {
	ServerAddrs        []string
	Username, Password string
	TLSConfig          *tls.Config
}

/*
Initialise a KMIP client.
The function does not immediately establish a connection to server.
*/
func NewKMIPClient(addrs []string, username, password string, caCertPEM []byte, certFilePath, certKeyPath string) (*KMIPClient, error) {
	client := &KMIPClient{
		ServerAddrs: addrs,
		Username:    username,
		Password:    password,
		TLSConfig:   new(tls.Config),
	}
	if caCertPEM != nil && len(caCertPEM) > 0 {
		// Use custom CA
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("NewKMIPClient: failed to load custom CA certificates from PEM")
		}
		client.TLSConfig.RootCAs = caCertPool
	}
	if certFilePath != "" {
		// Identify the client itself via certificate
		clientID, err := tls.LoadX509KeyPair(certFilePath, certKeyPath)
		if err != nil {
			return nil, fmt.Errorf("NewKMIPClient: failed to load client certificate/key - %v", err)
		}
		client.TLSConfig.Certificates = []tls.Certificate{clientID}
	}
	client.TLSConfig.BuildNameToCertificate()
	return client, nil
}

// Read an entire TTLV structure from reader's input and return.
func ReadFullTTLV(reader io.Reader) (ttlv.Item, error) {
	var structLen int32
	var ttlValue, fullTTLV []byte
	ttlHeader := make([]byte, 8) // 3 bytes of tag, 1 byte of type, 4 bytes of length
	if _, err := reader.Read(ttlHeader); err != nil {
		return nil, err
	}
	// Decode structure length
	if err := binary.Read(bytes.NewReader(ttlHeader[4:]), binary.BigEndian, &structLen); err != nil || structLen < 1 || structLen > MaxKMIPStructLen {
		return nil, err
	}
	// Read remainder of request structure
	ttlValue = make([]byte, structLen)
	if n, err := reader.Read(ttlValue); err != nil {
		if int32(n) == structLen {
			err = nil
		} else {
			return nil, err
		}
	}
	// Assemble TTL header and structure value for deserialisation
	fullTTLV = make([]byte, 8+len(ttlValue))
	copy(fullTTLV[:8], ttlHeader)
	copy(fullTTLV[8:], ttlValue)
	// Decode binary into TTLV
	ttlvItem, _, err := ttlv.DecodeAny(fullTTLV)
	return ttlvItem, err
}

/*
Establish a TLS connection to server, send exactly one request and expect exactly one response, then close the connection.
Retry up to a certain number of times in case IO error occurs.
*/
func (client *KMIPClient) ConverseWithRetry(request structure.SerialisedItem) (ttlv.Item, error) {
	var err error
	serialisedRequest := request.SerialiseToTTLV()
	encodedRequest := ttlv.EncodeAny(serialisedRequest)
	for i := 0; i < ClientMaxRetry; i++ {
		if i > 0 {
			// Introduce an artificial sleep to delay attempts after failure
			time.Sleep(1 * time.Second)
		}
		// Always prefer to use the first server among the list of servers
		addr := client.ServerAddrs[i%len(client.ServerAddrs)]
		var conn *tls.Conn
		conn, err = tls.Dial("tcp", addr, client.TLSConfig)
		if err != nil {
			log.Printf("KMIPClient.ConverseWithRetry: IO failure occured with KMIP server %s", addr)
			continue
		}
		if _, err = conn.Write(encodedRequest); err != nil {
			log.Printf("KMIPClient.ConverseWithRetry: IO failure occured with KMIP server %s", addr)
			conn.Close()
			continue
		}
		var ttlvResp ttlv.Item
		ttlvResp, err = ReadFullTTLV(conn)
		if err != nil {
			log.Printf("KMIPClient.ConverseWithRetry: IO failure occured with KMIP server %s", addr)
			conn.Close()
			continue
		}
		conn.Close()
		return ttlvResp, nil
	}
	return nil, fmt.Errorf("KMIPClient.ConverseWithRetry: ultimately failed in all attempts at conversing with server - %v", err)
}

/*
Establish a TLS connection to server, send exactly one request and expect exactly one response, then close the connection.
TLS handshake is way more expensive than KMIP operations, so consider using the connection for more requests in the future.
*/
func (client *KMIPClient) MakeRequest(request structure.SerialisedItem) (structure.SerialisedItem, error) {
	ttlvResp, err := client.ConverseWithRetry(request)
	if err != nil {
		return nil, err
	}
	// TODO: refactor this into interface function in all request structures
	var respItem structure.SerialisedItem
	switch request.(type) {
	case *structure.SCreateRequest:
		respItem = &structure.SCreateResponse{}
	case *structure.SGetRequest:
		respItem = &structure.SGetResponse{}
	case *structure.SDestroyRequest:
		respItem = &structure.SDestroyResponse{}
	default:
		return nil, fmt.Errorf("KMIPClient.MakeRequest: does not understand the request type \"%s\"", reflect.TypeOf(request).String())
	}
	if err := respItem.DeserialiseFromTTLV(ttlvResp); err != nil {
		return nil, fmt.Errorf("KMIPClient.MakeRequest: failed to deserialise response - %v", err)
	}
	return respItem, err
}

// Return a SRequestHeader structure that has client's protocol version and user credentials.
func (client *KMIPClient) GetRequestHeader() structure.SRequestHeader {
	return structure.SRequestHeader{
		SProtocolVersion: structure.SProtocolVersion{
			IMajor: ttlv.Integer{Value: structure.ValProtocolVersionMajorKMIP1_3},
			IMinor: ttlv.Integer{Value: structure.ValProtocolVersionMinorKMIP1_3},
		},
		SAuthentication: structure.SAuthentication{
			SCredential: structure.SCredential{
				ICredentialType: ttlv.Enumeration{Value: structure.ValCredentialTypeUsernamePassword},
				SCredentialValue: structure.SCredentialValueUsernamePassword{
					TUsername: ttlv.Text{Value: client.Username},
					TPassword: ttlv.Text{Value: client.Password},
				},
			},
		},
		IBatchCount: ttlv.Integer{Value: 1},
	}
}

// If KMIP response item contains an error, return the error, otherwise return nil.
func ResponseItemToError(resp structure.SResponseBatchItem) error {
	if resp.EResultStatus.Value == structure.ValResultStatusSuccess {
		return nil
	}
	return fmt.Errorf("KMIP response error: status %d, reason %d, message %s.",
		resp.EResultStatus.Value, resp.EResultReason.Value, resp.EResultMessage.Value)
}

// Create a new disk encryption key and return its KMIP ID.
func (client *KMIPClient) CreateKey(keyName string) (id string, err error) {
	defer func() {
		// In the unlikely case that a misbehaving server causes client to crash.
		if r := recover(); r != nil {
			msg := fmt.Sprintf("KMIPClient.CreateKey: the function crashed due to programming error - %v", r)
			log.Print(msg)
			err = errors.New(msg)
		}
	}()
	resp, err := client.MakeRequest(&structure.SCreateRequest{
		SRequestHeader: client.GetRequestHeader(),
		SRequestBatchItem: structure.SRequestBatchItem{
			EOperation: ttlv.Enumeration{Value: structure.ValOperationCreate},
			SRequestPayload: &structure.SRequestPayloadCreate{
				EObjectType: ttlv.Enumeration{Value: structure.ValObjectTypeSymmetricKey},
				STemplateAttribute: structure.STemplateAttribute{
					Attributes: []structure.SAttribute{
						{
							TAttributeName: ttlv.Text{Value: structure.ValAttributeNameCryptoAlg},
							AttributeValue: &ttlv.Enumeration{
								TTL:   ttlv.TTL{Tag: structure.TagAttributeValue},
								Value: structure.ValCryptoAlgoAES,
							},
						},
						{
							TAttributeName: ttlv.Text{Value: structure.ValAttributeNameCryptoLen},
							AttributeValue: &ttlv.Integer{
								TTL:   ttlv.TTL{Tag: structure.TagAttributeValue},
								Value: KMIPAESKeySizeBits, // keep in mind that key size is in bits
							},
						},
						{
							TAttributeName: ttlv.Text{Value: structure.ValAttributeNameCryptoUsageMask},
							AttributeValue: &ttlv.Integer{
								TTL:   ttlv.TTL{Tag: structure.TagAttributeValue},
								Value: structure.MaskCryptoUsageEncrypt | structure.MaskCryptoUsageDecrypt,
							},
						},
						{
							TAttributeName: ttlv.Text{Value: structure.ValAttributeNameKeyName},
							AttributeValue: structure.SCreateRequestNameAttributeValue{
								TKeyName: ttlv.Text{Value: keyName},
								EKeyType: ttlv.Enumeration{Value: structure.ValObjectTypeSymmetricKey},
							}.SerialiseToTTLV(), // TODO: get rid of this ugly call to SerialiseToTTLV()
						},
					},
				},
			},
		},
	})
	if err != nil {
		return
	}
	typedResp := resp.(*structure.SCreateResponse)
	if err = ResponseItemToError(typedResp.SResponseBatchItem); err != nil {
		return
	}
	id = typedResp.SResponseBatchItem.SResponsePayload.(*structure.SResponsePayloadCreate).TUniqueID.Value
	if id == "" {
		err = errors.New("KMIPClient.CreateKey: server did not return a key ID")
	}
	return
}

// Retrieve a disk encryption key by its ID.
func (client *KMIPClient) GetKey(id string) (key []byte, err error) {
	defer func() {
		// In the unlikely case that a misbehaving server causes client to crash.
		if r := recover(); r != nil {
			msg := fmt.Sprintf("KMIPClient.GetKey: (ID %s) the function crashed due to programming error - %v", id, r)
			log.Print(msg)
			err = errors.New(msg)
		}
	}()
	resp, err := client.MakeRequest(&structure.SGetRequest{
		SRequestHeader: client.GetRequestHeader(),
		SRequestBatchItem: structure.SRequestBatchItem{
			EOperation: ttlv.Enumeration{Value: structure.ValOperationGet},
			SRequestPayload: &structure.SRequestPayloadGet{
				TUniqueID: ttlv.Text{Value: id},
			},
		},
	})
	if err != nil {
		return
	}
	typedResp := resp.(*structure.SGetResponse)
	if err = ResponseItemToError(typedResp.SResponseBatchItem); err != nil {
		return
	}
	key = typedResp.SResponseBatchItem.SResponsePayload.(*structure.SResponsePayloadGet).SSymmetricKey.SKeyBlock.SKeyValue.BKeyMaterial.Value
	if key == nil || len(key) != KMIPAESKeySizeBits/8 {
		err = fmt.Errorf("KMIPClient.GetKey: (ID %s) key content looks wrong (%d)", id, len(key))
	}
	return
}

// Erase a key record.
func (client *KMIPClient) DestroyKey(id string) (err error) {
	defer func() {
		// In the unlikely case that a misbehaving server causes client to crash.
		if r := recover(); r != nil {
			msg := fmt.Sprintf("KMIPClient.DestroyKey: (ID %s) the function crashed due to programming error - %v", id, r)
			log.Print(msg)
			err = errors.New(msg)
		}
	}()
	resp, err := client.MakeRequest(&structure.SDestroyRequest{
		SRequestHeader: client.GetRequestHeader(),
		SRequestBatchItem: structure.SRequestBatchItem{
			EOperation: ttlv.Enumeration{Value: structure.ValOperationDestroy},
			SRequestPayload: &structure.SRequestPayloadDestroy{
				TUniqueID: ttlv.Text{Value: id},
			},
		},
	})
	if err != nil {
		return
	}
	return ResponseItemToError(resp.(*structure.SDestroyResponse).SResponseBatchItem)
}
