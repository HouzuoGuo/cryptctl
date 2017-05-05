package structure

import (
	"encoding/hex"
	"github.com/HouzuoGuo/cryptctl/kmip/ttlv"
	"log"
)

var AllDefinedTags = map[string]ttlv.Tag{} // String encoded hex value of tag VS tag

// Place a tag into AllDefinedTags map for faster look-up.
func RegisterDefinedTag(str string) (ret ttlv.Tag) {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		log.Panicf("RegisterDefinedTag: failed to decode hex tag string - %v", err)
	}
	copy(ret[:], decoded)
	AllDefinedTags[str] = ret
	return ret
}

// Create request
var TagRequestMessage = RegisterDefinedTag("420078")
var TagRequestHeader = RegisterDefinedTag("420077")
var TagProtocolVersion = RegisterDefinedTag("420069")
var TagProtocolVersionMajor = RegisterDefinedTag("42006a")

const ValProtocolVersionMajorKMIP1_3 = 1

var TagProtocolVersionMinor = RegisterDefinedTag("42006b")

const ValProtocolVersionMinorKMIP1_3 = 2

var TagAuthentication = RegisterDefinedTag("42000c")
var TagCredential = RegisterDefinedTag("420023")
var TagCredentialType = RegisterDefinedTag("420024")

const ValCredentialTypeUsernamePassword = 1

var TagCredentialValue = RegisterDefinedTag("420025")
var TagUsername = RegisterDefinedTag("420099")
var TagPassword = RegisterDefinedTag("4200a1")

var TagBatchCount = RegisterDefinedTag("42000d")
var TagBatchItem = RegisterDefinedTag("42000f")
var TagOperation = RegisterDefinedTag("42005c")

const ValOperationCreate = 1

var TagRequestPayload = RegisterDefinedTag("420079")
var TagObjectType = RegisterDefinedTag("420057")

const ValAttributeNameKeyName = "Name"

const ValObjectTypeSymmetricKey = 2

var TagTemplateAttribute = RegisterDefinedTag("420091")
var TagAttribute = RegisterDefinedTag("420008")
var TagAttributeName = RegisterDefinedTag("42000a")

const ValAttributeNameCryptoAlg = "Cryptographic Algorithm"
const ValAttributeNameCryptoLen = "Cryptographic Length"
const ValAttributeNameCryptoUsageMask = "Cryptographic Usage Mask"
const MaskCryptoUsageEncrypt = 4
const MaskCryptoUsageDecrypt = 8

var TagAttributeValue = RegisterDefinedTag("42000b")
var TagNameType = RegisterDefinedTag("420054")

const ValNameTypeText = 1

var TagNameValue = RegisterDefinedTag("420055")

// Create response
var TagResponseMessage = RegisterDefinedTag("42007b")
var TagResponseHeader = RegisterDefinedTag("42007a")
var TagTimestamp = RegisterDefinedTag("420092")
var TagResultStatus = RegisterDefinedTag("42007f")

const ValResultStatusSuccess = 0
const ValResultStatusFailed = 1
const ValResultStatusPending = 2
const ValResultStatusUndone = 3

const ValResultReasonNotFound = 1

var TagResponsePayload = RegisterDefinedTag("42007c")
var TagUniqueID = RegisterDefinedTag("420094")

// Get request
const ValOperationGet = 10

// Get response
var TagSymmetricKey = RegisterDefinedTag("42008f")
var TagKeyBlock = RegisterDefinedTag("420040")
var TagFormatType = RegisterDefinedTag("420042")
var TagKeyValue = RegisterDefinedTag("420045")
var TagKeyMaterial = RegisterDefinedTag("420043")
var TagCryptoAlgorithm = RegisterDefinedTag("420028")
var TagCryptoLen = RegisterDefinedTag("42002a")
var TagResultReason = RegisterDefinedTag("42007e")
var TagResultMessage = RegisterDefinedTag("42007d")

const ValKeyFormatTypeRaw = 1
const ValCryptoAlgoAES = 3

// Destroy request
const ValOperationDestroy = 20

// Destroy response - nothing more
