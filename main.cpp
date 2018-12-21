/* 
 * File:   main.cpp
 * Author: Hannu Honkanen
 *
 * A test program to test OpenSC's C_WrapKey and C_UnwrapKey implementation
 * 
 * To test unwrapping with RSA, import an RSA key to the card first.
 *
 * Different use cases can be tested by commenting and uncommenting calls to WrapKey and Unwrap, and by modifying the
 * templates.
 * 
 * Created on September 12, 2017, 12:40 PM
 */

#include <cstdlib>
#include <cstdarg>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11.h"
#include <iostream>
#include "wraptest.h"


using namespace std;

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	void *handle;
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*typedef unsigned int size_t; */

static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_SLOT_ID_PTR p11_slots = NULL;
static CK_ULONG p11_num_slots = 0;
static void *module = NULL;
static CK_BYTE		opt_object_id[100], new_object_id[100];
static const char *	opt_attr_from_file = NULL;
static size_t		opt_object_id_len = 0, new_object_id_len = 0;
static unsigned char    iv_test          = 0;   /* use a 16 byte iv of 0,1,2,3,4,5 etc... */

static CK_BYTE ID_GEN_SECRET[] = {'g','e','n',' ','s','e','c','r','e','t'};
static CK_BYTE ID_GEN_SECRET_2[] = {'g','e','n',' ','s','e','c','r','e','t',' ', '2'};
static CK_BYTE ID_AES_KEY[] = {'a','e','s', ' ', 'k','e','y'};

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

// key length 23 bytes, wrapped using 2K RSA
unsigned char RSA_WRAPPED_GEN_SECRET[] = { 0x74,0xFB,0xA0,0xBE,0x5F,0xF2,0x2B,0x9B,0x26,0x67,0x2F,0xB7,0x35,0xAE,0x68,0xBA,0x33,0x8B,0xE7,0x48,0xCA,0x3E,0x30,0x85,0x2A,0x46,0x8C,0x6E,0x4E,0x6D,0xBF,0xD7,0x1E,0xA3,0x45,0x57,0x92,0xC4,0x2E,0x2E,0x89,0x20,0x37,0x0C,0xED,0x62,0xA0,0x33,0xD9,0xF6,0x0D,0x6D,0x5B,0xC2,0x65,0x7C,0xAA,0xC9,0x31,0xE2,0xCD,0xF6,0xED,0x81,0x6A,0x81,0x6D,0xA7,0xCA,0x8A,0x3E,0x5A,0x61,0xF1,0x8A,0x9A,0xDC,0x3D,0xD2,0x42,0x56,0x1E,0x46,0xE8,0x5C,0x6D,0x91,0x87,0xEC,0xF0,0x2E,0xFF,0x52,0x10,0x25,0x3A,0xE0,0xB2,0x79,0xBB,0x8D,0x2F,0x8F,0x26,0xBC,0x26,0xDA,0xDF,0x5D,0xA0,0xCA,0xB5,0x7E,0xEE,0xA0,0xE0,0xFA,0x72,0xF9,0xD2,0x12,0x43,0xCD,0xD4,0x41,0x42,0x51,0x9D,0x9E,0x46,0xA1,0xD7,0x20,0x13,0xE9,0xAC,0xF8,0x15,0x63,0x07,0x20,0x4A,0x0F,0x02,0x71,0x4C,0xE9,0xE7,0x2B,0x8A,0x2A,0xA2,0x40,0x56,0xD2,0x27,0xAE,0x5D,0x0C,0xAB,0x7C,0x86,0x6E,0x91,0xAE,0xE6,0xC0,0x78,0x35,0x92,0x94,0xCF,0xAE,0xFB,0x76,0x2C,0xB3,0x9E,0x86,0x69,0x2C,0xCE,0x69,0xBB,0xD7,0xD4,0x2A,0xEC,0xFE,0x82,0x48,0x81,0x30,0xC1,0xCC,0x83,0x17,0xA9,0x99,0xC6,0x15,0x71,0x84,0xF1,0xBD,0x8A,0x8D,0xD9,0x62,0x59,0xC7,0x20,0x1B,0x88,0x3B,0xCC,0xE0,0x64,0xC3,0xEA,0x58,0xAB,0x6B,0x9D,0xFF,0x00,0x42,0x23,0x30,0x3C,0xDA,0xB7,0x6B,0x32,0x1B,0xC5,0x5D,0x30,0x3C,0xDC,0x88,0x54,0xD7,0xCD,0x60,0x4B,0x8F,0x80,0x42,0xA2,0xBC,0xA0,0xE9,0xC1,0x39,0xAB };

unsigned char RSA_WRAPPED_AES_KEY[] = {  0xA9,0xAA,0x10,0xB0,0xE8,0x05,0x09,0xE2,0x0A,0x5C,0x38,0xB9,0x3F,0xF1,0x23,0xD8,0x1B,0x70,0x75,0x00,0x6A,0x9B,0x6B,0x2B,0x19,0x72,0xA9,0x0A,0x00,0x80,0xEF,0xC5,0x00,0x0B,0xAA,0xDE,0xFB,0x2E,0xFA,0x9B,0x6E,0xAB,0x2D,0x52,0x19,0x4C,0xAD,0xD4,0x4D,0xFB,0xC5,0xEC,0x8E,0xE4,0xCD,0xF4,0xD4,0x42,0x8C,0x9C,0x50,0xAD,0x4D,0x89,0xBE,0x09,0xB6,0x25,0xBF,0xC9,0x66,0x7B,0xF5,0x88,0x39,0xD6,0xA9,0x56,0xFE,0x6D,0xFA,0xC1,0x8E,0xC2,0xD1,0xAA,0xDB,0x9C,0x86,0x27,0x48,0x29,0x3B,0xFA,0xB0,0xBF,0xA8,0x65,0xFC,0x2C,0x0C,0x2A,0xBC,0x63,0xAD,0x18,0x4E,0xE4,0x3E,0x38,0x99,0x1A,0x04,0x46,0xC1,0xEF,0x4A,0x66,0x5C,0xE6,0x4D,0x5A,0x4F,0x6B,0xF1,0x1E,0x3C,0x6C,0xAB,0xCC,0x74,0x1A,0x1A,0xB3,0x83,0xD5,0x01,0xC4,0x69,0x9C,0xDD,0xA5,0x8F,0xA3,0x28,0x7C,0xD5,0x10,0x9F,0xA1,0x18,0x0E,0xCD,0xC6,0x80,0x63,0x9F,0xF2,0x05,0xC9,0x76,0xEE,0x5B,0x21,0x74,0xB2,0xC7,0x2B,0x4F,0xD0,0xC0,0x72,0x3D,0xF3,0xA0,0x2D,0x48,0x98,0x8C,0xAE,0x5D,0x57,0x33,0x1F,0xC8,0x88,0xC2,0x4F,0xB4,0x2A,0xF2,0x83,0x5A,0xA5,0x78,0x3D,0xB6,0x89,0x29,0x49,0x74,0x26,0xCB,0x4B,0x1A,0xE5,0x01,0xB3,0x43,0x8A,0xBB,0x2C,0x3A,0x12,0x00,0xDA,0x3F,0x4B,0x0D,0x7D,0x93,0xB2,0x13,0x14,0xBE,0x61,0x84,0xCB,0x87,0x65,0x3B,0x3A,0x04,0xD3,0x6B,0xDC,0x33,0x16,0x12,0xFB,0x92,0x1A,0xCD,0x90,0x78,0x56,0xAB,0xE0,0x55,0xC5,0x95,0x91,0xF3,0x14,0x36,0xE3 };

unsigned char AES_WRAPPED_AES_KEY[] = { 0x29, 0xA2, 0x57, 0xCA, 0xDE, 0x25, 0x72, 0x60, 0x27, 0xEF, 0x44, 0x26, 0x7C, 0x78, 0x84, 0xD0, 0x32, 0x62, 0x4C, 0x9D, 0xDE, 0x3D, 0x4C, 0x94, 0x39, 0xC4, 0x8D, 0x14, 0x48, 0x96, 0xDE, 0xD8 };

unsigned char AES_WRAPPED_GEN_SECRET[] = { 0x0F,0x8A,0x80,0x6B,0xA0,0x22,0xC4,0x8F,0xC8,0x2C,0xC1,0x2F,0x4F,0x1B,0x38,0x30,0x96,0x45,0x5B,0x3F,0xBE,0xD2,0x56,0xDB,0xE4,0x00,0x16,0xFA,0xF5,0x84,0xA7,0xC2};

void OutputHexString(unsigned char* buffer, size_t len)
{
    for (size_t i = 0; i < len; i++)
	printf("%02X", buffer[i]);
}

CK_RV
C_UnloadModule(void *module);

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
void *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	mod = (sc_pkcs11_module_t*) calloc(1, sizeof(*mod));
	mod->_magic = MAGIC;

	if (mspec == NULL) {
		free(mod);
		return NULL;
	}
	mod->handle = dlopen(mspec, RTLD_LAZY);
	if (mod->handle == NULL) {
		fprintf(stderr, "sc_dlopen failed: %s\n", dlerror());
		goto failed;
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				dlsym(mod->handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto failed;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return (void *) mod;
	else {
		fprintf(stderr, "C_GetFunctionList failed %lx", rv);
		C_UnloadModule((void *) mod);
		return NULL;
	}
failed:
	free(mod);
	return NULL;
}


/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV
C_UnloadModule(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (mod->handle != NULL && dlclose(mod->handle) < 0)
		return CKR_FUNCTION_FAILED;

	memset(mod, 0, sizeof(*mod));
	free(mod);
	return CKR_OK;
}

void
util_fatal(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\nAborting.\n");
	va_end(ap);

	/*sc_notify_close();*/

	exit(1);
}

static void p11_fatal(const char *func, CK_RV rv)
{
	if (p11)
		p11->C_Finalize(NULL_PTR);
	if (module)
		C_UnloadModule(module);

	p11 = NULL;
	module = NULL;

	util_fatal("PKCS11 function %s failed: rv = %s (0x%0x)", func, CKR2Str(rv), (unsigned int) rv);
}

static void list_slots(int tokens, int refresh, int print)
{
	CK_SLOT_INFO info;
	CK_ULONG n;
	CK_RV rv;
	int verbose = 0;

	/* Get the list of slots */
	if (refresh) {
		rv = p11->C_GetSlotList(tokens, NULL, &p11_num_slots);
		if (rv != CKR_OK)
			p11_fatal("C_GetSlotList(NULL)", rv);
		free(p11_slots);
		p11_slots = (CK_SLOT_ID_PTR) calloc(p11_num_slots, sizeof(CK_SLOT_ID));
		if (p11_slots == NULL) {
			perror("calloc failed");
			return;
		}

		rv = p11->C_GetSlotList(tokens, p11_slots, &p11_num_slots);
		if (rv != CKR_OK)
			p11_fatal("C_GetSlotList()", rv);
	}

	if (!print)
		return;
/*
	printf("Available slots:\n");
	for (n = 0; n < p11_num_slots; n++) {
		printf("Slot %lu (0x%lx): ", n, p11_slots[n]);
		rv = p11->C_GetSlotInfo(p11_slots[n], &info);
		if (rv != CKR_OK) {
			printf("(GetSlotInfo failed, %s)\n", CKR2Str(rv));
			continue;
		}
		printf("%s\n", p11_utf8_to_local(info.slotDescription,
					sizeof(info.slotDescription)));
		if ((!verbose) && !(info.flags & CKF_TOKEN_PRESENT)) {
			printf("  (empty)\n");
			continue;
		}

		if (verbose) {
			printf("  manufacturer:  %s\n", p11_utf8_to_local(info.manufacturerID,
						sizeof(info.manufacturerID)));
			printf("  hardware ver:  %u.%u\n",
						info.hardwareVersion.major,
						info.hardwareVersion.minor);
			printf("  firmware ver:  %u.%u\n",
						info.firmwareVersion.major,
						info.firmwareVersion.minor);
			printf("  flags:         %s\n", p11_slot_info_flags(info.flags));
		}
		if (info.flags & CKF_TOKEN_PRESENT)
			show_token(p11_slots[n]);
	} */
}

static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len, int obj_index)
{
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;
	int i;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id) {
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void *) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}

	rv = p11->C_FindObjectsInit(sess, attrs, nattrs);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjectsInit", rv);

	for (i = 0; i < obj_index; i++) {
		rv = p11->C_FindObjects(sess, ret, 1, &count);
		if (rv != CKR_OK)
			p11_fatal("C_FindObjects", rv);
		if (count == 0)
			goto done;
	}
	rv = p11->C_FindObjects(sess, ret, 1, &count);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjects", rv);

done:	if (count == 0)
		*ret = CK_INVALID_HANDLE;
	p11->C_FindObjectsFinal(sess);

	return count;
}

int Unwrap(CK_SESSION_HANDLE session, int unwrappingKeyType, CK_MECHANISM* mech, CK_ATTRIBUTE keyId, CK_ATTRIBUTE* keyTemplate, CK_ULONG attrCount,
            CK_BYTE_PTR wrappedData, CK_ULONG wrappedDataLen, CK_OBJECT_HANDLE *unwrappedKey)
{
    CK_OBJECT_HANDLE unwrappingKey; 
                     
    
    if (!find_object(session, unwrappingKeyType, &unwrappingKey,
	    (const unsigned char*) keyId.pValue,
	    keyId.ulValueLen, 0))
    {
    		p11_fatal("Wrapping key not found", 0);
		//return -1;
    }
    
    CK_RV rv = p11->C_UnwrapKey(session, mech, unwrappingKey,
	wrappedData, wrappedDataLen, keyTemplate, attrCount, unwrappedKey);
    
    return rv;
}


int WrapKey(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE wrappingKey = 0;
	CK_OBJECT_HANDLE targetKey = 0;	
	CK_BYTE wrappedData[256];
	CK_ULONG wrappedDataLen = sizeof(wrappedData);

	if (!find_object(session, CKO_SECRET_KEY, &wrappingKey,
		    ID_AES_KEY,
		    sizeof(ID_AES_KEY), 0))
	{
			//p11_fatal("Wrapping key not found", 0);

			return -1;
	}

	if (!find_object(session, CKO_SECRET_KEY, &targetKey,
		    ID_GEN_SECRET,
		    sizeof(ID_GEN_SECRET), 0))
	{
			//p11_fatal("Wrapping key not found", 0);

			return -1;
	}


	CK_BBOOL ckTrue = CK_TRUE;
	CK_BBOOL ckFalse = CK_FALSE;
	CK_ULONG targetValueLen = 256;
	int rv = CKR_OK;

	CK_BYTE iv[0x10];
	memset(&iv, 0, sizeof(iv));
        if (iv_test)
                for (unsigned char i = 0; i < sizeof(iv); i++)
                    iv[i] = i;
	CK_MECHANISM mech = { CKM_AES_CBC_PAD, &iv, sizeof(iv) };

        wrappedDataLen = 256;
        
//        wrappedDataLen = 0;
        
        /* ask for needed buffer size first */
//        rv = p11->C_WrapKey(session, &mech, wrappingKey,
//		targetKey, NULL, &wrappedDataLen);
        
        if (rv == CKR_OK) /* then do the wrapping (we have a 256 byte buffer, add check/alloc in real use */
        {           
            rv = p11->C_WrapKey(session, &mech, wrappingKey,
                  	targetKey, wrappedData, &wrappedDataLen);

            if (rv == CKR_OK && wrappedDataLen > 0)
            {
		cout << "Wrapped data: ";
		OutputHexString(wrappedData, wrappedDataLen);
		cout << "\n";
            }
        }

	return rv;
}


/*
 * 
 */
int main(int argc, char** argv) {

    static CK_SLOT_ID	opt_slot = 0;
    CK_UTF8CHAR* pin	= (CK_UTF8CHAR*) NULL; // "1111";
    CK_UTF8CHAR* sopin	= (CK_UTF8CHAR*) "12345678";
    int flags		= 0;

    module = C_LoadModule("/usr/local/lib/pkcs11/opensc-pkcs11.so", &p11);    

    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session = 0;
    rv = p11->C_Initialize(NULL);

    list_slots(1, 1, 0);

    if (p11_num_slots > 0)
	    opt_slot = p11_slots[0];

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = p11->C_OpenSession(opt_slot, flags, NULL, NULL, &session);
    rv = p11->C_Login(session, CKU_USER,
	    (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen((const char*)pin));
    rv = p11->C_Login(session, CKU_SO,
	    (CK_UTF8CHAR *) sopin, sopin == NULL ? 0 : strlen((const char*)sopin));

    // Test case 1: Unwrap GENERIC SECRET using RSA

    fprintf(stderr, "RSA unwrap test\n");
    
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType_GenSecret= CKK_GENERIC_SECRET;
    CK_KEY_TYPE keyType_AES= CKK_AES;
    CK_ULONG targetValueLen = 23;
    CK_ULONG targetValueLen_AES = 32;
    CK_ULONG targetValueLen_Gen_2 = 22;
    CK_MECHANISM mechRsaPkcs = { CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE iv[0x10],
            ivZeros[0x10];
    memset(&iv, 0, sizeof(iv));
    memset(&ivZeros, 0, sizeof(ivZeros));
    if (iv_test)
          for (unsigned char i = 0; i < sizeof(iv); i++)
              iv[i] = i;
    CK_MECHANISM mechAesIvSeq = { CKM_AES_CBC_PAD, &iv, sizeof(iv) };
    CK_MECHANISM mechAesIvZeros = { CKM_AES_CBC_PAD, &ivZeros, sizeof(ivZeros) };
    
    
    CK_ATTRIBUTE keyTemplate_gen_1[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType_GenSecret, sizeof(keyType_GenSecret)},
	{CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
	{CKA_DERIVE, &ckFalse, sizeof(ckFalse)},
	{CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
	{CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
	{CKA_VALUE_LEN, &targetValueLen, sizeof(targetValueLen)},
	{CKA_ID, &ID_GEN_SECRET, sizeof(ID_GEN_SECRET)},
        {CKA_OPENSC_ALWAYS_AUTH_ANY_OBJECT, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE keyTemplate_AES_1[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType_AES, sizeof(keyType_AES)},
	{CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
	{CKA_DERIVE, &ckFalse, sizeof(ckFalse)},
	{CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
	{CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
	{CKA_WRAP, &ckTrue, sizeof(ckTrue)},
        {CKA_UNWRAP, &ckTrue, sizeof(ckTrue)},
	{CKA_VALUE_LEN, &targetValueLen_AES, sizeof(targetValueLen_AES)},
	{CKA_ID, &ID_AES_KEY, sizeof(ID_AES_KEY)}
    };

        CK_ATTRIBUTE keyTemplate_AES_2[] = {    /* AES, non extractable, session object*/
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType_AES, sizeof(keyType_AES)},
	{CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
	{CKA_DERIVE, &ckFalse, sizeof(ckFalse)},
	{CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
	{CKA_EXTRACTABLE, &ckFalse, sizeof(ckTrue)},
	{CKA_WRAP, &ckTrue, sizeof(ckTrue)},
        {CKA_UNWRAP, &ckTrue, sizeof(ckTrue)},
	{CKA_VALUE_LEN, &targetValueLen_AES, sizeof(targetValueLen_AES)},
	{CKA_ID, &ID_AES_KEY, sizeof(ID_AES_KEY)}
    };

     CK_ATTRIBUTE keyTemplate_gen_2[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType_GenSecret, sizeof(keyType_GenSecret)},
	{CKA_TOKEN, &ckTrue, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
	{CKA_DERIVE, &ckFalse, sizeof(ckFalse)},
	{CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
	{CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
	{CKA_VALUE_LEN, &targetValueLen_Gen_2, sizeof(targetValueLen_Gen_2)},
        {CKA_ID, &ID_GEN_SECRET_2, sizeof(ID_GEN_SECRET_2)}
    };



    CK_OBJECT_HANDLE unwrappedGenSecret = 0,
                     unwrappedAesKey = 0,
                     unwrappedGen2 = 0;

    CK_ATTRIBUTE null_id;
    null_id.type = CKA_ID;  // look for the first private key, so don't define an id.
    null_id.pValue = NULL;
    null_id.ulValueLen = 0;
    rv = Unwrap(session, CKO_PRIVATE_KEY, &mechRsaPkcs, null_id, keyTemplate_gen_1, sizeof(keyTemplate_gen_1) / sizeof(keyTemplate_gen_1[0]),
            RSA_WRAPPED_GEN_SECRET, sizeof(RSA_WRAPPED_GEN_SECRET), &unwrappedGenSecret);

    if (rv == CKR_OK)
        fprintf(stderr, "Unwrapping generic secret using RSA succeeded\n");
    else
        fprintf(stderr, "Unwrapping generic secret using RSA failed: %lx\n", rv);
          
    fprintf(stderr, "Unwrapping a CKA_TOKEN=FALSE AES key using RSA\n");

    /* Unwrap an AES key */

    rv = Unwrap(session, CKO_PRIVATE_KEY, &mechRsaPkcs, null_id, keyTemplate_AES_2, sizeof(keyTemplate_AES_1) / sizeof(keyTemplate_AES_1[0]),
            RSA_WRAPPED_AES_KEY, sizeof(RSA_WRAPPED_AES_KEY), &unwrappedAesKey);
/*    rv = Unwrap(session, CKO_PRIVATE_KEY, &mechRsaPkcs, null_id, keyTemplate_AES_1, sizeof(keyTemplate_AES_1) / sizeof(keyTemplate_AES_1[0]),
            RSA_WRAPPED_AES_KEY, sizeof(RSA_WRAPPED_AES_KEY), &unwrappedAesKey);*/

  if (rv == CKR_OK)
        fprintf(stderr, "Unwrapping AES key using RSA succeeded\n");
    else
        fprintf(stderr, "Unwrapping AES key using RSA failed: %lx\n", rv);

  fprintf(stderr, "Symmetric unwrap test\n");
  // unwrap a CKK_GENERIC_SECRET using an AES key.
  //rv = UnwrapKey_Case_X(session);

  CK_ATTRIBUTE idAesKey = { CKA_ID, ID_AES_KEY, sizeof(ID_AES_KEY) };

  /*
  rv = Unwrap(session, CKO_SECRET_KEY, &mechAesIvSeq, idAesKey, keyTemplate_gen_2, sizeof(keyTemplate_gen_2) / sizeof(keyTemplate_gen_2[0]),
            AES_WRAPPED_GEN_SECRET, sizeof(AES_WRAPPED_GEN_SECRET), &unwrappedGen2);

  if (rv == CKR_OK)
        fprintf(stderr, "Unwrapping Generic Secret key using AES succeeded\n");
    else
        fprintf(stderr, "Unwrapping Generic Secret key using AES failed: %lx\n", rv);*/

    /* Wrap the GENERIC SECRET key using the AES key */
   if (rv == CKR_OK)
        rv = WrapKey(session);

       /* Wrap the GENERIC SECRET key using the AES key */
   if (rv == CKR_OK)
   {
        fprintf(stderr, "Checking CKA_OPENSC_ALWAYS_AUTH_ANY_OBJECT.Trying to wrap the key again\n");

        rv = WrapKey(session);

        if (rv == CKR_OK)
            fprintf(stderr, "Wrapping second time succeeded\n" );
        else
            fprintf(stderr, "Wrapping second time FAILED.\n" );
   }
   else
   {
        fprintf(stderr, "Key wrapping failed: %x\n", rv);
   }

 cleanup:

    if (session != CK_INVALID_HANDLE) {
	    rv = p11->C_CloseSession(session);
		    if (rv != CKR_OK)
			    p11_fatal("C_CloseSession", rv);
    }

    rv = p11->C_Finalize(NULL);
end:

    return 0;
}

