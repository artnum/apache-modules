#include <ctype.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "apr_strings.h"
#include "apr_cstr.h"
#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_pools.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"
#include "util_cookies.h"

#define HTYPE_SHA256 1
#define HTYPE_SHA384 2
#define HTYPE_SHA512 3

struct auth_params {
  int htype;
  unsigned char * cid;
  unsigned char * sig;
  unsigned char * rsig; /* raw sig */
  size_t rsigLen;
};

int fromHex (const unsigned char * str, size_t str_len, unsigned char * out, size_t out_len) {
  size_t i = 0;
  unsigned char v = 0;
  for (i = 0; i < str_len && str[i] != '\0'; i++) {
    switch (str[i]) {
    case '0': v += 0x0; break;
    case '1': v += 0x1; break;
    case '2': v += 0x2; break;
    case '3': v += 0x3; break;
    case '4': v += 0x4; break;
    case '5': v += 0x5; break;
    case '6': v += 0x6; break;
    case '7': v += 0x7; break;
    case '8': v += 0x8; break;
    case '9': v += 0x9; break;
    case 'a': case 'A': v += 0xA; break;
    case 'b': case 'B': v += 0xB; break;
    case 'c': case 'C': v += 0xC; break;
    case 'd': case 'D': v += 0xD; break;
    case 'e': case 'E': v += 0xE; break;
    case 'f': case 'F': v += 0xF; break;
    default:
      return -1; /* invalid */
    }

    if (i % 2 == 0) {
      v <<= 4;
    } else {
      if ((i - 1) / 2 >= out_len) {
	return -1; /* invalid */
      }
      out[(i - 1) / 2] = v;
      v = 0;
    }
  }
  
  return 0;
}

#define METHOD_MAX_LENGTH 30
#define AUTH_TYPE "Menshen"
#define AUTH_PARAM_SIG "Sig"
#define AUTH_PARAM_CID "Cid"
#define AUTH_PARAM_HTYPE "HType"

unsigned char * reqFullId (apr_pool_t * authPool, request_rec * r) {
  unsigned char method[METHOD_MAX_LENGTH];
  const unsigned char * reqId = NULL;
  unsigned char * signId = NULL;
  int i = 0;

  for (i = 0; r->method[i] != '\0' && i < METHOD_MAX_LENGTH - 1; i++) {
    method[i] = tolower(r->method[i]);
    method[i + 1] = '\0';
  }
  
  reqId = apr_table_get(r->headers_in, "X-Request-Id");
  /* signId is "$method|$uri|$reqId" */
  return apr_psprintf(authPool, "%s|%s|%s", method, r->unparsed_uri, reqId);
}

struct auth_params * reqAuthParams (apr_pool_t * authPool, request_rec * r) {
  unsigned char * last = NULL;
  unsigned char * token = NULL;
  unsigned char * tmp = NULL;
  unsigned char * authString = NULL;
  struct auth_params * authParams = NULL;

  authString = apr_pstrdup(authPool, apr_table_get(r->headers_in, "Authorization"));
  if (authString) {
    /* skip blank */
    while (*authString == ' ' || *authString == '\t') { authString++; }
    /* check and skip auth type */
    if (strlen(authString) < sizeof(AUTH_TYPE)) { return NULL; }
    if (apr_cstr_casecmpn(authString, AUTH_TYPE, sizeof(AUTH_TYPE))) { return NULL; }
    
    authString += sizeof(AUTH_TYPE);
    while (*authString == ' ' || *authString == '\t') { authString++; }

    /* we reach auth params, so init and parse */
    authParams = apr_pcalloc(authPool, sizeof(*authParams));
    if (!authParams) { return NULL; }
    authParams->htype = HTYPE_SHA256; /* default hash algo */
    authParams->sig = NULL;
    authParams->rsig = NULL;
    authParams->cid = NULL;

    for (token = apr_strtok(authString, ",", &last); token; apr_strtok(NULL, ",", &last)) {
      if (apr_cstr_casecmpn(token, AUTH_PARAM_SIG, sizeof(AUTH_PARAM_SIG)) == 0) {
	token += sizeof(AUTH_PARAM_SIG);
	while (*token == '=' || *token == ' ' || *token == '\t') { token++; }
	authParams->sig = token;
	for (tmp = token + strlen(token) - 1; tmp > token; tmp--) {
	  if(*tmp == ' ' || *tmp == '\t') { *tmp = '\0'; }
	}
	if ((authParams->rsig = apr_pcalloc(authPool, strlen(authParams->sig) / 2)) == NULL) {
	  return NULL;
	}
	if (fromHex(token, strlen(token), authParams->rsig, strlen(authParams->sig) / 2) == -1) {
	  return NULL;
	}
	authParams->rsigLen = strlen(authParams->sig) / 2;
      } else if (apr_cstr_casecmpn(token, AUTH_PARAM_CID, sizeof(AUTH_PARAM_CID)) == 0) {
	token += sizeof(AUTH_PARAM_CID);
	while (*token == '=' || *token == ' ' || *token == '\t') { token++; }
	authParams->cid = token;
	for (tmp = token + strlen(token) - 1; tmp > token; tmp--) {
	  if(*tmp == ' ' || *tmp == '\t') { *tmp = '\0'; }
	}
      } if (apr_cstr_casecmpn(token, AUTH_PARAM_HTYPE, sizeof(AUTH_PARAM_HTYPE)) == 0) {
	token += sizeof(AUTH_PARAM_HTYPE);
	while (*token == '=' || *token == ' ' || *token == '\t') { token++; }
	/* default to sha256 except if specified a valid alternative */
	if (apr_cstr_casecmpn(token, "sha384", 6) == 0) {
	  authParams->htype = HTYPE_SHA384;
	} else if (apr_cstr_casecmpn(token, "sha512", 6) == 0) {
	  authParams->htype = HTYPE_SHA512;
	}
      }
    }
  }

  return authParams;
}

int auth_verify (apr_hash_t * certList,
		 apr_pool_t * authPool,
		 request_rec * r,
		 struct auth_params * authParams,
		 const unsigned char * authString) {
  int retVal = 0;
  RSA * pubKey = NULL;
  EVP_PKEY * pkey = NULL;
  EVP_MD_CTX * mdCtx = NULL;
  EVP_PKEY_CTX * kCtx = NULL;
  const EVP_MD * md = NULL;
  
  pubKey = apr_hash_get(certList, authParams->cid, APR_HASH_KEY_STRING);
  if (!pubKey) { goto free_exit; }
  if (!(kCtx = EVP_PKEY_new())) { goto free_exit; }
  if (!(mdCtx = EVP_MD_CTX_new())) { goto free_exit; }
  if (!EVP_PKEY_set1_RSA(pkey, pubKey)) { goto free_exit; }
  
  switch (authParams->htype) {
  case HTYPE_SHA256: md = EVP_sha256(); break;
  case HTYPE_SHA384: md = EVP_sha384(); break;
  case HTYPE_SHA512: md = EVP_sha512(); break;
  }

  if (!EVP_DigestVerifyInit(mdCtx, kCtx, md, NULL, &pkey)) { goto free_exit; }
  if (!EVP_PKEY_CTX_set_rsa_padding(kCtx, RSA_PKCS1_PSS_PADDING)) { goto free_exit; }
  if (!EVP_DigestVerifyUpdate(mdCtx, authString, strlen(authString))) { goto free_exit; }
  retVal = EVP_DigestVerifyFinal(mdCtx, authParams->rsig, authParams->rsigLen);

 free_exit:
  if (pkey) { EVP_PKEY_free(pkey); }
  if (mdCtx) { EVP_MD_CTX_free(mdCtx); }
  if (kCtx) { EVP_PKEY_CTX_free(kCtx); }

  return retVal;
}

int load_pukeys (apr_hash_t * certList, const char * dirName) {
  int retVal = 0;
  apr_pool_t * loadPool = NULL;
  apr_dir_t * dh = NULL;
  apr_finfo_t finfo;
  RSA * pubKey = NULL;
  FILE * fp = NULL;
  
  if (APR_SUCCESS != apr_pool_create(&loadPool, NULL)) { goto free_exit; }
  if (APR_SUCCESS != apr_dir_open(&dh, dirName, loadPool)) { goto free_exit; }
  
  while (APR_ENOENT != apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE, dh)) {
    if (finfo.filetype == APR_REG) {
      if ((fp = fopen(finfo.fname, "r"))) {
	if ((pubKey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL))) {
	  apr_hash_set(certList, finfo.name, APR_HASH_KEY_STRING, pubKey);
	}
	fclose(fp);
      }
    }
  }

 free_exit:
  if (dh) { apr_dir_close(dh); }
  if (loadPool) { apr_pool_destroy(loadPool); }
}

apr_status_t unload_pubkeys (apr_hash_t * certList) {
  RSA *pubKey = NULL;
  apr_hash_index_t * idx;
  for (idx = apr_hash_first(apr_hash_pool_get(certList), certList); idx; idx = apr_hash_next(idx)) {
    apr_hash_this(idx, NULL, NULL, (void **)&pubKey);
    RSA_free(pubKey);
  }
}

static authz_status menshen_check_authorization (request_rec * r,
						 const char * require_args,
						 const void * parsed_require_args) {
  authz_status authzStatus = AUTHZ_DENIED;
  return authzStatus;
}

static apr_hash_t * CertList = NULL;

static void menshen_init (apr_pool_t * p) {
  CertList = apr_hash_make(p);
  apr_pool_cleanup_register(p, CertList, unload_pubkeys, NULL);
}

static const authz_provider authz_menshen_provider =
  {
   &menshen_check_authorization,
   NULL
  };

static void register_hooks (apr_pool_t * p) {
  ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "menshen",
			    AUTHZ_PROVIDER_VERSION,
			    &authz_menshen_provider,
			    AP_AUTH_INTERNAL_PER_CONF);
  menshen_init (p);
}

module AP_MODULE_DECLARE_DATA authz_menshen =
  {
   STANDARD20_MODULE_STUFF,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   register_hooks
  };
