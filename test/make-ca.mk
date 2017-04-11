X509_CERTIFICATES = top l1 l2 revoked l1-dup

X509_ENV_ca0 = \
  CN='${CN}' \

X509_ENV_l1 = \
  CN='Level 1' \

X509_ENV_l2 = \
  CN='Level 2' \

X509_ENV_l1-dup = ${X509_ENV_l1}

X509_ENV_revoked = \
  CN='revoked' \

CA_REQ = ca_cert

OPENSSL = openssl
OPENSSL_ENV = \
	WORKDIR='$(CA_DIR)' \
	REQ='$(CA_REQ)' \
	$(X509_ENV_$*) \

OPENSSL_X509 = env $(OPENSSL_ENV) $(OPENSSL) x509 \
	-req \
        -extfile '$(filter %.conf,$^)' \
	-in '$(filter %.req,$^)' \
	-signkey '$(filter %.key,$^)' \
	-out '$@'

OPENSSL_REQ = env $(OPENSSL_ENV) $(OPENSSL) req \
	-batch -new \
	-key '$(filter %.key,$^)' \
	-config '$(filter %.conf,$^)' \
	-out '$@'

OPENSSL_CA = env $(OPENSSL_ENV) $(OPENSSL) ca \
	-batch \
	-config '$(filter %.conf,$^)' \
	-in '$(filter %.req,$^)' \
	-out '$@'

OPENSSL_CRL = env $(OPENSSL_ENV) $(OPENSSL) ca \
	-batch -gencrl \
	-config '$(filter %.conf,$^)' \
	-out $(CA_DIR)/$*.crl

_certs = $(addsuffix .pem,$(addprefix $(CA_DIR)/,$(X509_CERTIFICATES)))
_hashes = $(addsuffix .hash,$(addprefix $(CA_DIR)/,$(X509_CERTIFICATES)))

init-ca:	$(CA_DIR)/top.pem $(_certs) $(_hashes) gen-crl-0 gen-crl-1 gen-crl-2

gen-crl-%:	openssl.conf .sleep-%-dup | $(CA_DIR)/top.crt $(CA_DIR)/top.key
	$(OPENSSL_CRL)

$(CA_DIR)/%.revoke:	openssl.conf $(CA_DIR)/%.crt
	$(OPENSSL_CRL) -revoke '$(filter %.crt,$^)' -crl_reason unspecified
	@touch $@

$(CA_DIR) $(CA_DIR)/.ca/newcerts $(CA_DIR)/.ca:
	mkdir -p $@

$(CA_DIR)/.ca/index.txt: | $(CA_DIR)/.ca
	touch $@

$(CA_DIR)/.ca/serial: | $(CA_DIR)/.ca
	@rm -f $@
	echo 01 > $@

$(CA_DIR)/top.crt:${CA_DIR}/%.crt: openssl.conf $(CA_DIR)/%.req $(CA_DIR)/%.key
	$(call OPENSSL_X509) -days 10

$(CA_DIR)/%.crt: openssl.conf $(CA_DIR)/%.req .sleep-% $(CA_DIR)/top.key \
	  $(CA_DIR)/top.crt | \
	$(CA_DIR)/.ca/newcerts $(CA_DIR)/.ca/index.txt $(CA_DIR)/.ca/serial
	$(call OPENSSL_CA) -days 10

$(CA_DIR)/%.req: openssl.conf $(CA_DIR)/%.key | $(CA_DIR)
	$(OPENSSL_REQ) 

$(CA_DIR)/%.key: | $(CA_DIR)
	$(OPENSSL) genrsa -out $@ 2048

$(CA_DIR)/%.pem: $(CA_DIR)/%.crt $(CA_DIR)/%.key
	@rm -f $@
	$(OPENSSL) x509 -text -in $(filter %.crt,$^) -out $@
	cat $(filter %.key,$^) >> $@

$(CA_DIR)/%.hash: $(CA_DIR)/%.crt
	@rm -f $@
	$(OPENSSL) x509 -hash -noout -in $(filter %.crt,$^) > $@

.sleep-%:	DURATION=0
.sleep-%-dup:	DURATION=2
.sleep-%-dup:	$(CA_DIR)/%.crt

.sleep-%:
	sleep ${DURATION}

.SECONDARY:

# 'openssl ca' does not support parallel execution
.NOTPARALLEL:
