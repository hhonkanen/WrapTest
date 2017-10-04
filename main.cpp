/* 
 * File:   main.cpp
 * Author: hannu
 *
 * Created on September 12, 2017, 12:40 PM
 */

#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11.h"


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

static void p11_fatal(const char *func, CK_RV rv)
{
	if (p11)
		p11->C_Finalize(NULL_PTR);
	if (module)
		C_UnloadModule(module);

	//util_fatal("PKCS11 function %s failed: rv = %s (0x%0x)", func, CKR2Str(rv), (unsigned int) rv);
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




/*
 * 
 */
int main(int argc, char** argv) {

    static CK_SLOT_ID	opt_slot = 0;
    CK_UTF8CHAR* pin	= (CK_UTF8CHAR*) "1111";
    int flags		= 0;
    CK_OBJECT_HANDLE unwrappingKey = 0;

    module = C_LoadModule("/usr/local/lib/pkcs11/opensc-pkcs11.so", &p11);

    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };

/* CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };*/

    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    rv = p11->C_Initialize(NULL);

    list_slots(1, 1, 0);

    if (p11_num_slots > 0)
	    opt_slot = p11_slots[0];

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = p11->C_OpenSession(opt_slot, flags, NULL, NULL, &session);
    rv = p11->C_Login(session, CKU_USER,
	    (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen((const char*)pin));

    if (!find_object(session, CKO_PRIVATE_KEY, &unwrappingKey,
	    opt_object_id_len ? opt_object_id : NULL,
	    opt_object_id_len, 0))
	    p11_fatal("Private key not found", 0);


    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType= CKK_GENERIC_SECRET;
    CK_ULONG attrCount = 7;
    CK_OBJECT_HANDLE unwrappedKey = 0;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ULONG targetValueLen = 256;

    CK_ATTRIBUTE keyTemplate[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
	{CKA_DERIVE, &ckFalse, sizeof(ckFalse)},
	{CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
	{CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
	{CKA_VALUE_LEN, &targetValueLen, sizeof(targetValueLen)}
    };
    CK_BYTE wrappedKey[] = { 0x23,0x8E,0xE7,0xD2,0x90,0xCC,0xCF,0x81,0xF8,0x49,0x19,0x1E,0x86,0xF5,0x7A,0xE8,0xAC,0x35,0x75,0xBA,0xA8,0x11,0xE2,0x7E,0x81,0x55,0x02,0xFB,0x41,0xCE,0xCA,0xB6,0xF9,0xA8,0x6B,0xD2,0x7F,0x2F,0x54,0xEC,0x80,0x4E,0xEC,0x4F,0x5A,0x9E,0x1E,0x19,0x58,0x0C,0x37,0x15,0x61,0x37,0x73,0x7D,0x51,0x4C,0x2F,0x56,0x15,0x72,0x28,0x42,0x66,0x43,0x3C,0xE7,0xDF,0x4A,0x5A,0xAD,0x75,0xC7,0x47,0x2B,0x07,0xD7,0xD0,0xB0,0x31,0x4A,0x17,0x7E,0xBC,0x80,0x4B,0x8C,0x76,0xF4,0x31,0xFD,0x5B,0xE1,0x5B,0x17,0xEB,0x3B,0x5F,0xF6,0x4D,0x08,0x47,0x04,0x73,0xDE,0x68,0xAF,0x7E,0x6E,0xB8,0xB1,0xA5,0xF6,0x28,0xAC,0xE8,0xAC,0xFC,0x8C,0xD3,0x2B,0x2D,0x60,0xC2,0x61,0xC0,0x5C };
    CK_ULONG ulWrappedKeyLen = sizeof(wrappedKey);

    rv = p11->C_UnwrapKey(session, &mech, unwrappingKey,
	wrappedKey, ulWrappedKeyLen,keyTemplate, attrCount, &unwrappedKey);


    if (session != CK_INVALID_HANDLE) {
	    rv = p11->C_CloseSession(session);
		    if (rv != CKR_OK)
			    p11_fatal("C_CloseSession", rv);
    }

    rv = p11->C_Finalize(NULL);


    return 0;
}

