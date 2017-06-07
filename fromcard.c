#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include "base64enc.h"
#include "derdata.h"


#ifndef _WIN32
#include <unix.h>
#include <pkcs11.h>
#else
#include <Windows.h>
//allign at 1 byte
#pragma pack(push, cryptoki, 1)
#include <win32.h>
#include <pkcs11.h>
#pragma pack(pop, cryptoki)
//back to default allignment

#define dlopen(lib,h) LoadLibrary(lib)
#define dlsym(h, function) GetProcAddress(h, function)
#define dlclose(h) FreeLibrary(h)
#define PKCS11_LIB L"beidpkcs11.dll"
#define RTLD_LAZY	1
#define RTLD_NOW	2
#define RTLD_GLOBAL 4

CK_FUNCTION_LIST_PTR 	functions;

#endif

#define check_rv(call) { CK_RV rv = call; if (rv != CKR_OK) { printf("E: %s failed: %#010lx\n", #call, rv); exit(EXIT_FAILURE); } }

#ifndef _WIN32
#define get_func(C_function) C_function
#else
#define get_func(C_function) (*functions->C_function)
#endif


/* SEQUENCE { OBJECT (rsaEncryption), NULL } */
static uint8_t rsaalg[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x01, 0x05, 0x00
};

static struct derdata rsa = { rsaalg, sizeof rsaalg, 1 };

/* OBJECT (commonName) */
static uint8_t o_cn[] = {
	0x06, 0x03, 0x55, 0x04, 0x03
};

static struct derdata cn = { o_cn, sizeof o_cn, 1 };

/* OBJECT (surname) */
static uint8_t o_sn[] = {
	0x06, 0x03, 0x55, 0x04, 0x04
};

static struct derdata sn = { o_sn, sizeof o_sn, 1 };

/* OBJECT (serialNumber) */
static uint8_t o_serial[] = {
	0x06, 0x03, 0x55, 0x04, 0x05
};

static struct derdata serial = { o_serial, sizeof o_serial, 1 };

/* OBJECT (givenName) */
static uint8_t o_gn[] = {
	0x06, 0x03, 0x55, 0x04, 0x2a
};

static struct derdata gn = { o_gn, sizeof o_gn, 1 };

/* SET { SEQUENCE { OBJECT (countryName), PRINTABLESTRING "BE" } } */
static uint8_t c_be[] = {
	0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x42, 0x45
};

static struct derdata be = { c_be, sizeof c_be, 1 };

/* INTEGER(0) -- used for version number */
static uint8_t version_d[] = {
	0x02, 0x01, 0x00
};

static struct derdata version = { version_d, sizeof version_d, 1 };

/* SEQUENCE { OBJECT(sha256WithRSAEncryption), NULL } */
static uint8_t sha256_d[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0b, 0x05, 0x00
};

static struct derdata sha256 = { sha256_d, sizeof sha256_d, 1 };

/* SEQUENCE { OBJECT(sha1WithRSAEncryption), NULL } */
static uint8_t sha1_d[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x05, 0x05, 0x00
};

static struct derdata sha1 = { sha1_d, sizeof sha1_d, 1 };

/* Empty attributes */
static uint8_t attr_d[] = {
	0xa0, 0x00
};

static struct derdata attributes = { attr_d, sizeof attr_d, 1 };

/* Generate something based on a BeID card which OpenSSL will accept as
 * a certificate signing request.
 * No, I do not guarantee that the output is 100% conform the PKCS#10
 * standard. It may be, it may not be. There are also a number of things
 * which are hardcoded in this implementation. That's fine, since we
 * don't need to modify them anyway.
 * The point of this exercise is to get a certificate signed by a CA for
 * *testing* purposes. If you use this for anything else, and someone
 * manages to break into your infrastructure, you have only yourself to
 * blame.
 */
struct derdata* gen_csr(CK_SESSION_HANDLE session, char* type, char* sn_str, char*
		gn_str, char* rrn_str, int do_256) {
	CK_OBJECT_HANDLE key;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_LABEL, type, strlen(type) },
		{ CKA_CLASS, &klass, sizeof klass }
	};
	CK_ULONG count, bits;
	char mod[256], exp[4];
	CK_ATTRIBUTE attr[] = {
		{ CKA_MODULUS, mod, sizeof mod },
		{ CKA_MODULUS_BITS, &bits, sizeof bits },
		{ CKA_PUBLIC_EXPONENT, exp, sizeof exp },
	};
	CK_MECHANISM mech;
	CK_BYTE signature[256];
	CK_ULONG siglen = sizeof(signature);
	struct derdata *csr, *csr_unsigned;
	char cn_str[1024];
	char firstname[1024];
	char *space;

	/* Get the public half of the key */
	check_rv(get_func(C_FindObjectsInit)(session, tmpl, 2));
	check_rv(get_func(C_FindObjects)(session, &key, 1, &count));
	if(count != 1) {
		fprintf(stderr, "E: Could not read public key with label '%s': %lu found", type, count);
		return NULL;
	}
	check_rv(get_func(C_GetAttributeValue)(session, key, attr, 3));
	check_rv(get_func(C_FindObjectsFinal)(session));
	/* Get a handle to the private key */
	klass = CKO_PRIVATE_KEY;
	check_rv(get_func(C_FindObjectsInit)(session, tmpl, 2));
	check_rv(get_func(C_FindObjects)(session, &key, 1, &count));
	check_rv(get_func(C_FindObjectsFinal)(session));
	if(count != 1) {
		fprintf(stderr, "E: Could not find private key with label '%s': %lu found", type, count);
		return NULL;
	}

	strncpy(firstname, gn_str, sizeof firstname);
	if((space = strchr(firstname, ' ')) != NULL) {
		*space = '\0';
	}
	snprintf(cn_str, sizeof cn_str, "%s %s (%s)", firstname, sn_str,
			type);

	/* Build a DER-representation of a CertificationRequestInfo */
	csr_unsigned = der_sequence(
		&version,
		der_sequence( // subject
			&be,
			der_setseqstr(&cn, cn_str),
			der_setseqstr(&sn, sn_str),
			der_setseqstr(&gn, gn_str),
			der_setseqstr(&serial, rrn_str),
			NULL
			),
		der_sequence( // SubjectPublicKeyInfo
			&rsa,
			der_bitder(
				der_sequence(
					der_longint(mod, attr[0].ulValueLen),
					der_longint(exp, attr[2].ulValueLen),
					NULL
					)
				),
			NULL
			),
		&attributes,
		NULL
		);

	/* Now sign the request */
	mech.mechanism = do_256 ? CKM_SHA256_RSA_PKCS : CKM_SHA1_RSA_PKCS;
	check_rv(get_func(C_SignInit)(session, &mech, key));
	check_rv(get_func(C_Sign)(session, csr_unsigned->data, csr_unsigned->len, signature, &siglen));
	/* combine the CertificationRequestInfo with the signature to
	 * produce a PKCS#10 CSR (or at least, something similar enough
	 * for OpenSSL to accept it) */
	csr = der_sequence(
		csr_unsigned,
		do_256 ? &sha256 : &sha1,
		der_bitstring(signature, siglen * 8),
		NULL
		);

	return csr;
}

char* pem_csr(struct derdata* csr) {
	size_t b64len = (csr->len / 3 + 1) * 4;
	size_t newlines = b64len / 65 + 2;
#ifdef _WIN32
	char header[] = "-----BEGIN CERTIFICATE REQUEST-----\n\r";
	char footer[] = "-----END CERTIFICATE REQUEST-----\n\r";
	char *encoded = malloc(b64len + newlines * 2 + 1 + sizeof header + sizeof footer);
#else
	char header[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
	char footer[] = "-----END CERTIFICATE REQUEST-----\n";
	char *encoded = malloc(b64len + newlines + 1 + sizeof header + sizeof footer);
#endif
	char *retval = encoded;
	base64_encodestate state;
	int count;

	strcpy(encoded, header);
	encoded += sizeof header - 1;
	base64_init_encodestate(&state);
	count = base64_encode_block((char*)csr->data, csr->len, encoded, &state);
	encoded += count;
	count = base64_encode_blockend(encoded, &state);
	encoded += count - 1;
	if(*encoded != '\n' && *encoded != '\r') {
		*(++encoded) = '\n';
#ifdef _WIN32
		*(++encoded) = '\r';
#endif
	}
	encoded++;
	strcpy(encoded, footer);
	return retval;
}

int main(int argc, char** argv) {
	CK_SESSION_HANDLE session;
	CK_SLOT_ID slot;
	char auth[] = "Authentication";
	char sign[] = "Signature";
	CK_ULONG count = 1;
	struct derdata* data;
	char* pem;
	int do_256;
	char *given, *sur, *rrn;

#ifdef _WIN32
	int						hpkcs11 = NULL;
	CK_C_GetFunctionList 	pC_GetFunctionList;
	CK_RV 					rv;

	hpkcs11 = dlopen(PKCS11_LIB, RTLD_LAZY); // RTLD_NOW is slower
	if (hpkcs11 == NULL)
	{
		return -1;
	}

	// get function pointer to C_GetFunctionList
	pC_GetFunctionList = (CK_C_GetFunctionList)dlsym(hpkcs11, "C_GetFunctionList");
	if (pC_GetFunctionList == NULL)
	{
		dlclose(hpkcs11);
		return -2;
	}

	// invoke C_GetFunctionList
	rv = (*pC_GetFunctionList) (&functions);
	if (rv != CKR_OK)
	{
		return -3;
	}

#endif
	if(argc != 5) {
		fprintf(stderr, "E: Require four arguments: given name(s), last name, RRN number, SHA algorithm\n");
		fprintf(stderr, "e.g.: %s \"Altay Mergo\" Geurdin 39012940734 1 (for SHA1)\n", argv[0]);
		fprintf(stderr, "or  : %s \"Altay Mergo\" Geurdin 39012940734 256 (for SHA256)\n", argv[0]);
		return -1;
	}

	given = argv[1];
	sur = argv[2];
	rrn = argv[3];
	if(strcmp(argv[4], "1") == 0) {
		do_256 = 0;
	} else if (strcmp(argv[4], "256") == 0) {
		do_256 = 1;
	} else {
		fprintf(stderr, "E: unknown SHA algorithm: %s\n", argv[4]);
		return -1;
	}

	check_rv(get_func(C_Initialize)(NULL_PTR));
	check_rv(get_func(C_GetSlotList)(CK_TRUE, &slot, &count));
	check_rv(get_func(C_OpenSession)(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
	/* This will fail if there is more than one eID card. Don't do
	 * that. We want to keep this simple. */
	data = gen_csr(session, sign, sur, given, rrn, do_256);
	if(!data) {
		printf("No signature key found on card, not generating a signature certificate\n");
	} else {
		pem = pem_csr(data);
		printf("Signature certificate:\n%s", pem);
		free(pem);
	}
	data = gen_csr(session, auth, sur, given, rrn, do_256);
	if(!data) {
		printf("No authentication key found on card, not generating an authentication certificate\n");
	} else {
		pem = pem_csr(data);
		printf("Authentication certificate:\n%s", pem);
		free(pem);
	}
	check_rv(get_func(C_CloseAllSessions)(slot));
	check_rv(get_func(C_Finalize)(NULL_PTR));
#ifdef _WIN32
	dlclose(hpkcs11);
#endif
}
