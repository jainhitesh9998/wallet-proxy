/** Bundled JSON-LD contexts (fetched 2026-11-01) so canonicalization never depends on remote context fetches. */
export const BUNDLED_CONTEXTS: Record<string, unknown> = {
 "https://www.w3.org/ns/credentials/v2": {
  "@context": {
   "@protected": true,
   "id": "@id",
   "type": "@type",
   "description": "https://schema.org/description",
   "digestMultibase": {
    "@id": "https://w3id.org/security#digestMultibase",
    "@type": "https://w3id.org/security#multibase"
   },
   "digestSRI": {
    "@id": "https://www.w3.org/2018/credentials#digestSRI",
    "@type": "https://www.w3.org/2018/credentials#sriString"
   },
   "mediaType": {
    "@id": "https://schema.org/encodingFormat"
   },
   "name": "https://schema.org/name",
   "VerifiableCredential": {
    "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "confidenceMethod": {
      "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
      "@type": "@id"
     },
     "credentialSchema": {
      "@id": "https://www.w3.org/2018/credentials#credentialSchema",
      "@type": "@id"
     },
     "credentialStatus": {
      "@id": "https://www.w3.org/2018/credentials#credentialStatus",
      "@type": "@id"
     },
     "credentialSubject": {
      "@id": "https://www.w3.org/2018/credentials#credentialSubject",
      "@type": "@id"
     },
     "description": "https://schema.org/description",
     "evidence": {
      "@id": "https://www.w3.org/2018/credentials#evidence",
      "@type": "@id"
     },
     "issuer": {
      "@id": "https://www.w3.org/2018/credentials#issuer",
      "@type": "@id"
     },
     "name": "https://schema.org/name",
     "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
     },
     "refreshService": {
      "@id": "https://www.w3.org/2018/credentials#refreshService",
      "@type": "@id"
     },
     "relatedResource": {
      "@id": "https://www.w3.org/2018/credentials#relatedResource",
      "@type": "@id"
     },
     "renderMethod": {
      "@id": "https://www.w3.org/2018/credentials#renderMethod",
      "@type": "@id"
     },
     "termsOfUse": {
      "@id": "https://www.w3.org/2018/credentials#termsOfUse",
      "@type": "@id"
     },
     "validFrom": {
      "@id": "https://www.w3.org/2018/credentials#validFrom",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "validUntil": {
      "@id": "https://www.w3.org/2018/credentials#validUntil",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     }
    }
   },
   "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
   "VerifiablePresentation": {
    "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "holder": {
      "@id": "https://www.w3.org/2018/credentials#holder",
      "@type": "@id"
     },
     "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
     },
     "termsOfUse": {
      "@id": "https://www.w3.org/2018/credentials#termsOfUse",
      "@type": "@id"
     },
     "verifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
      "@type": "@id",
      "@container": "@graph",
      "@context": null
     }
    }
   },
   "EnvelopedVerifiablePresentation": "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",
   "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
   "JsonSchema": {
    "@id": "https://www.w3.org/2018/credentials#JsonSchema",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "jsonSchema": {
      "@id": "https://www.w3.org/2018/credentials#jsonSchema",
      "@type": "@json"
     }
    }
   },
   "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
   "BitstringStatusList": {
    "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "encodedList": {
      "@id": "https://www.w3.org/ns/credentials/status#encodedList",
      "@type": "https://w3id.org/security#multibase"
     },
     "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
     "ttl": "https://www.w3.org/ns/credentials/status#ttl"
    }
   },
   "BitstringStatusListEntry": {
    "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "statusListCredential": {
      "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
      "@type": "@id"
     },
     "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
     "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
     "statusMessage": {
      "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "message": "https://www.w3.org/ns/credentials/status#message",
       "status": "https://www.w3.org/ns/credentials/status#status"
      }
     },
     "statusReference": {
      "@id": "https://www.w3.org/ns/credentials/status#statusReference",
      "@type": "@id"
     },
     "statusSize": {
      "@id": "https://www.w3.org/ns/credentials/status#statusSize",
      "@type": "https://www.w3.org/2001/XMLSchema#integer"
     }
    }
   },
   "DataIntegrityProof": {
    "@id": "https://w3id.org/security#DataIntegrityProof",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "challenge": "https://w3id.org/security#challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "cryptosuite": {
      "@id": "https://w3id.org/security#cryptosuite",
      "@type": "https://w3id.org/security#cryptosuiteString"
     },
     "domain": "https://w3id.org/security#domain",
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "nonce": "https://w3id.org/security#nonce",
     "previousProof": {
      "@id": "https://w3id.org/security#previousProof",
      "@type": "@id"
     },
     "proofPurpose": {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "assertionMethod": {
        "@id": "https://w3id.org/security#assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "https://w3id.org/security#authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityDelegation": {
        "@id": "https://w3id.org/security#capabilityDelegationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityInvocation": {
        "@id": "https://w3id.org/security#capabilityInvocationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "keyAgreement": {
        "@id": "https://w3id.org/security#keyAgreementMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": {
      "@id": "https://w3id.org/security#proofValue",
      "@type": "https://w3id.org/security#multibase"
     },
     "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
     }
    }
   },
   "...": {
    "@id": "https://www.iana.org/assignments/jwt#..."
   },
   "_sd": {
    "@id": "https://www.iana.org/assignments/jwt#_sd",
    "@type": "@json"
   },
   "_sd_alg": {
    "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
   },
   "aud": {
    "@id": "https://www.iana.org/assignments/jwt#aud",
    "@type": "@id"
   },
   "cnf": {
    "@id": "https://www.iana.org/assignments/jwt#cnf",
    "@context": {
     "@protected": true,
     "kid": {
      "@id": "https://www.iana.org/assignments/jwt#kid",
      "@type": "@id"
     },
     "jwk": {
      "@id": "https://www.iana.org/assignments/jwt#jwk",
      "@type": "@json"
     }
    }
   },
   "exp": {
    "@id": "https://www.iana.org/assignments/jwt#exp",
    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
   },
   "iat": {
    "@id": "https://www.iana.org/assignments/jwt#iat",
    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
   },
   "iss": {
    "@id": "https://www.iana.org/assignments/jose#iss",
    "@type": "@id"
   },
   "jku": {
    "@id": "https://www.iana.org/assignments/jose#jku",
    "@type": "@id"
   },
   "kid": {
    "@id": "https://www.iana.org/assignments/jose#kid",
    "@type": "@id"
   },
   "nbf": {
    "@id": "https://www.iana.org/assignments/jwt#nbf",
    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
   },
   "sub": {
    "@id": "https://www.iana.org/assignments/jose#sub",
    "@type": "@id"
   },
   "x5u": {
    "@id": "https://www.iana.org/assignments/jose#x5u",
    "@type": "@id"
   }
  }
 },
 "https://www.w3.org/2018/credentials/v1": {
  "@context": {
   "@version": 1.1,
   "@protected": true,
   "id": "@id",
   "type": "@type",
   "VerifiableCredential": {
    "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "cred": "https://www.w3.org/2018/credentials#",
     "sec": "https://w3id.org/security#",
     "xsd": "http://www.w3.org/2001/XMLSchema#",
     "credentialSchema": {
      "@id": "cred:credentialSchema",
      "@type": "@id",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "cred": "https://www.w3.org/2018/credentials#",
       "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
      }
     },
     "credentialStatus": {
      "@id": "cred:credentialStatus",
      "@type": "@id"
     },
     "credentialSubject": {
      "@id": "cred:credentialSubject",
      "@type": "@id"
     },
     "evidence": {
      "@id": "cred:evidence",
      "@type": "@id"
     },
     "expirationDate": {
      "@id": "cred:expirationDate",
      "@type": "xsd:dateTime"
     },
     "holder": {
      "@id": "cred:holder",
      "@type": "@id"
     },
     "issued": {
      "@id": "cred:issued",
      "@type": "xsd:dateTime"
     },
     "issuer": {
      "@id": "cred:issuer",
      "@type": "@id"
     },
     "issuanceDate": {
      "@id": "cred:issuanceDate",
      "@type": "xsd:dateTime"
     },
     "proof": {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph"
     },
     "refreshService": {
      "@id": "cred:refreshService",
      "@type": "@id",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "cred": "https://www.w3.org/2018/credentials#",
       "ManualRefreshService2018": "cred:ManualRefreshService2018"
      }
     },
     "termsOfUse": {
      "@id": "cred:termsOfUse",
      "@type": "@id"
     },
     "validFrom": {
      "@id": "cred:validFrom",
      "@type": "xsd:dateTime"
     },
     "validUntil": {
      "@id": "cred:validUntil",
      "@type": "xsd:dateTime"
     }
    }
   },
   "VerifiablePresentation": {
    "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "cred": "https://www.w3.org/2018/credentials#",
     "sec": "https://w3id.org/security#",
     "holder": {
      "@id": "cred:holder",
      "@type": "@id"
     },
     "proof": {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph"
     },
     "verifiableCredential": {
      "@id": "cred:verifiableCredential",
      "@type": "@id",
      "@container": "@graph"
     }
    }
   },
   "EcdsaSecp256k1Signature2019": {
    "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "sec": "https://w3id.org/security#",
     "xsd": "http://www.w3.org/2001/XMLSchema#",
     "challenge": "sec:challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "xsd:dateTime"
     },
     "domain": "sec:domain",
     "expires": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
     },
     "jws": "sec:jws",
     "nonce": "sec:nonce",
     "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "sec": "https://w3id.org/security#",
       "assertionMethod": {
        "@id": "sec:assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "sec:authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": "sec:proofValue",
     "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
     }
    }
   },
   "EcdsaSecp256r1Signature2019": {
    "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "sec": "https://w3id.org/security#",
     "xsd": "http://www.w3.org/2001/XMLSchema#",
     "challenge": "sec:challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "xsd:dateTime"
     },
     "domain": "sec:domain",
     "expires": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
     },
     "jws": "sec:jws",
     "nonce": "sec:nonce",
     "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "sec": "https://w3id.org/security#",
       "assertionMethod": {
        "@id": "sec:assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "sec:authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": "sec:proofValue",
     "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
     }
    }
   },
   "Ed25519Signature2018": {
    "@id": "https://w3id.org/security#Ed25519Signature2018",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "sec": "https://w3id.org/security#",
     "xsd": "http://www.w3.org/2001/XMLSchema#",
     "challenge": "sec:challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "xsd:dateTime"
     },
     "domain": "sec:domain",
     "expires": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
     },
     "jws": "sec:jws",
     "nonce": "sec:nonce",
     "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "sec": "https://w3id.org/security#",
       "assertionMethod": {
        "@id": "sec:assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "sec:authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": "sec:proofValue",
     "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
     }
    }
   },
   "RsaSignature2018": {
    "@id": "https://w3id.org/security#RsaSignature2018",
    "@context": {
     "@version": 1.1,
     "@protected": true,
     "challenge": "sec:challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "xsd:dateTime"
     },
     "domain": "sec:domain",
     "expires": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
     },
     "jws": "sec:jws",
     "nonce": "sec:nonce",
     "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@version": 1.1,
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "sec": "https://w3id.org/security#",
       "assertionMethod": {
        "@id": "sec:assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "sec:authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": "sec:proofValue",
     "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
     }
    }
   },
   "proof": {
    "@id": "https://w3id.org/security#proof",
    "@type": "@id",
    "@container": "@graph"
   }
  }
 },
 "https://w3id.org/security/suites/ed25519-2020/v1": {
  "@context": {
   "id": "@id",
   "type": "@type",
   "@protected": true,
   "proof": {
    "@id": "https://w3id.org/security#proof",
    "@type": "@id",
    "@container": "@graph"
   },
   "Ed25519VerificationKey2020": {
    "@id": "https://w3id.org/security#Ed25519VerificationKey2020",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "controller": {
      "@id": "https://w3id.org/security#controller",
      "@type": "@id"
     },
     "revoked": {
      "@id": "https://w3id.org/security#revoked",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "publicKeyMultibase": {
      "@id": "https://w3id.org/security#publicKeyMultibase",
      "@type": "https://w3id.org/security#multibase"
     }
    }
   },
   "Ed25519Signature2020": {
    "@id": "https://w3id.org/security#Ed25519Signature2020",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "challenge": "https://w3id.org/security#challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "domain": "https://w3id.org/security#domain",
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "nonce": "https://w3id.org/security#nonce",
     "proofPurpose": {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "assertionMethod": {
        "@id": "https://w3id.org/security#assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "https://w3id.org/security#authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityInvocation": {
        "@id": "https://w3id.org/security#capabilityInvocationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityDelegation": {
        "@id": "https://w3id.org/security#capabilityDelegationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "keyAgreement": {
        "@id": "https://w3id.org/security#keyAgreementMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "proofValue": {
      "@id": "https://w3id.org/security#proofValue",
      "@type": "https://w3id.org/security#multibase"
     },
     "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
     }
    }
   }
  }
 },
 "https://w3id.org/security/data-integrity/v2": {
  "@context": {
   "id": "@id",
   "type": "@type",
   "@protected": true,
   "proof": {
    "@id": "https://w3id.org/security#proof",
    "@type": "@id",
    "@container": "@graph"
   },
   "DataIntegrityProof": {
    "@id": "https://w3id.org/security#DataIntegrityProof",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "challenge": "https://w3id.org/security#challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "domain": "https://w3id.org/security#domain",
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "nonce": "https://w3id.org/security#nonce",
     "previousProof": {
      "@id": "https://w3id.org/security#previousProof",
      "@type": "@id"
     },
     "proofPurpose": {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "assertionMethod": {
        "@id": "https://w3id.org/security#assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "https://w3id.org/security#authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityInvocation": {
        "@id": "https://w3id.org/security#capabilityInvocationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityDelegation": {
        "@id": "https://w3id.org/security#capabilityDelegationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "keyAgreement": {
        "@id": "https://w3id.org/security#keyAgreementMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "cryptosuite": {
      "@id": "https://w3id.org/security#cryptosuite",
      "@type": "https://w3id.org/security#cryptosuiteString"
     },
     "proofValue": {
      "@id": "https://w3id.org/security#proofValue",
      "@type": "https://w3id.org/security#multibase"
     },
     "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
     }
    }
   }
  }
 },
 "https://w3id.org/security/data-integrity/v1": {
  "@context": {
   "id": "@id",
   "type": "@type",
   "@protected": true,
   "proof": {
    "@id": "https://w3id.org/security#proof",
    "@type": "@id",
    "@container": "@graph"
   },
   "DataIntegrityProof": {
    "@id": "https://w3id.org/security#DataIntegrityProof",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "challenge": "https://w3id.org/security#challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "domain": "https://w3id.org/security#domain",
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "nonce": "https://w3id.org/security#nonce",
     "proofPurpose": {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "assertionMethod": {
        "@id": "https://w3id.org/security#assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "https://w3id.org/security#authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityInvocation": {
        "@id": "https://w3id.org/security#capabilityInvocationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityDelegation": {
        "@id": "https://w3id.org/security#capabilityDelegationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "keyAgreement": {
        "@id": "https://w3id.org/security#keyAgreementMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "cryptosuite": "https://w3id.org/security#cryptosuite",
     "proofValue": {
      "@id": "https://w3id.org/security#proofValue",
      "@type": "https://w3id.org/security#multibase"
     },
     "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
     }
    }
   }
  }
 },
 "https://w3id.org/security/multikey/v1": {
  "@context": {
   "id": "@id",
   "type": "@type",
   "@protected": true,
   "Multikey": {
    "@id": "https://w3id.org/security#Multikey",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "controller": {
      "@id": "https://w3id.org/security#controller",
      "@type": "@id"
     },
     "revoked": {
      "@id": "https://w3id.org/security#revoked",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "publicKeyMultibase": {
      "@id": "https://w3id.org/security#publicKeyMultibase",
      "@type": "https://w3id.org/security#multibase"
     },
     "secretKeyMultibase": {
      "@id": "https://w3id.org/security#secretKeyMultibase",
      "@type": "https://w3id.org/security#multibase"
     }
    }
   }
  }
 },
 "https://www.w3.org/ns/did/v1": {
  "@context": {
   "@protected": true,
   "id": "@id",
   "type": "@type",
   "alsoKnownAs": {
    "@id": "https://www.w3.org/ns/activitystreams#alsoKnownAs",
    "@type": "@id"
   },
   "assertionMethod": {
    "@id": "https://w3id.org/security#assertionMethod",
    "@type": "@id",
    "@container": "@set"
   },
   "authentication": {
    "@id": "https://w3id.org/security#authenticationMethod",
    "@type": "@id",
    "@container": "@set"
   },
   "capabilityDelegation": {
    "@id": "https://w3id.org/security#capabilityDelegationMethod",
    "@type": "@id",
    "@container": "@set"
   },
   "capabilityInvocation": {
    "@id": "https://w3id.org/security#capabilityInvocationMethod",
    "@type": "@id",
    "@container": "@set"
   },
   "controller": {
    "@id": "https://w3id.org/security#controller",
    "@type": "@id"
   },
   "keyAgreement": {
    "@id": "https://w3id.org/security#keyAgreementMethod",
    "@type": "@id",
    "@container": "@set"
   },
   "service": {
    "@id": "https://www.w3.org/ns/did#service",
    "@type": "@id",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "serviceEndpoint": {
      "@id": "https://www.w3.org/ns/did#serviceEndpoint",
      "@type": "@id"
     }
    }
   },
   "verificationMethod": {
    "@id": "https://w3id.org/security#verificationMethod",
    "@type": "@id"
   }
  }
 },
 "https://w3id.org/vc/status-list/2021/v1": {
  "@context": {
   "@protected": true,
   "StatusList2021Credential": {
    "@id": "https://w3id.org/vc/status-list#StatusList2021Credential",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "description": "http://schema.org/description",
     "name": "http://schema.org/name"
    }
   },
   "StatusList2021": {
    "@id": "https://w3id.org/vc/status-list#StatusList2021",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "statusPurpose": "https://w3id.org/vc/status-list#statusPurpose",
     "encodedList": "https://w3id.org/vc/status-list#encodedList"
    }
   },
   "StatusList2021Entry": {
    "@id": "https://w3id.org/vc/status-list#StatusList2021Entry",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "statusPurpose": "https://w3id.org/vc/status-list#statusPurpose",
     "statusListIndex": "https://w3id.org/vc/status-list#statusListIndex",
     "statusListCredential": {
      "@id": "https://w3id.org/vc/status-list#statusListCredential",
      "@type": "@id"
     }
    }
   }
  }
 },
 "https://w3id.org/security/suites/jws-2020/v1": {
  "@context": {
   "privateKeyJwk": {
    "@id": "https://w3id.org/security#privateKeyJwk",
    "@type": "@json"
   },
   "JsonWebKey2020": {
    "@id": "https://w3id.org/security#JsonWebKey2020",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "publicKeyJwk": {
      "@id": "https://w3id.org/security#publicKeyJwk",
      "@type": "@json"
     }
    }
   },
   "JsonWebSignature2020": {
    "@id": "https://w3id.org/security#JsonWebSignature2020",
    "@context": {
     "@protected": true,
     "id": "@id",
     "type": "@type",
     "challenge": "https://w3id.org/security#challenge",
     "created": {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "domain": "https://w3id.org/security#domain",
     "expires": {
      "@id": "https://w3id.org/security#expiration",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
     },
     "jws": "https://w3id.org/security#jws",
     "nonce": "https://w3id.org/security#nonce",
     "proofPurpose": {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
      "@context": {
       "@protected": true,
       "id": "@id",
       "type": "@type",
       "assertionMethod": {
        "@id": "https://w3id.org/security#assertionMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "authentication": {
        "@id": "https://w3id.org/security#authenticationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityInvocation": {
        "@id": "https://w3id.org/security#capabilityInvocationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "capabilityDelegation": {
        "@id": "https://w3id.org/security#capabilityDelegationMethod",
        "@type": "@id",
        "@container": "@set"
       },
       "keyAgreement": {
        "@id": "https://w3id.org/security#keyAgreementMethod",
        "@type": "@id",
        "@container": "@set"
       }
      }
     },
     "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
     }
    }
   }
  }
 },
 "https://www.w3.org/ns/credentials/examples/v2": {
  "@context": {
   "@vocab": "https://www.w3.org/ns/credentials/examples#"
  }
 }
};
