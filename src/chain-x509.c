/*	--*- c -*--
 * Copyright (C) 2025 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/x509.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <dirent.h>
#include <search.h>
#include <inttypes.h>
#include <unistd.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* some const-casts */
#  define X509_STORE_get0_objects(_store) \
	X509_STORE_get0_objects((X509_STORE *)(_store))
#  define PEM_write_X509(_f, _x509)	 \
	PEM_write_X509((_f), (X509 *)(_x509))
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
#  define X509_CRL_get0_lastUpdate(_c)	X509_CRL_get_lastUpdate(_c)
#  define X509_STORE_get0_objects(_s)	((_s)->objs)
#  define X509_OBJECT_get_type(_o)	((_o)->type)
#  define X509_OBJECT_get0_X509(_o)	((_o)->data.x509)
#  define X509_OBJECT_get0_X509_CRL(_o)	((_o)->data.crl)

typedef int	X509_LOOKUP_TYPE;
#endif



struct x509_chain_object {
	X509 const	*x509;
	unsigned int		depth;
	bool			is_anchor;
};

struct x509_chain {
	struct x509_chain_object	*obj;
	size_t				num;
};

static void chain_add_x509(struct x509_chain *chain, X509 const *x509,
			   unsigned int depth)
{
	X509_NAME *issuer  = X509_get_issuer_name(x509);
	X509_NAME *subject = X509_get_subject_name(x509);
	struct x509_chain_object	*tmp;

	tmp = realloc(chain->obj, (chain->num + 1) * sizeof *tmp);
	if (!tmp)
		abort();

	chain->num += 1;
	chain->obj  = tmp;

	chain->obj[chain->num - 1] = (struct x509_chain_object) {
		.x509	   = x509,
		.depth     = depth,
		.is_anchor =  X509_NAME_cmp(issuer, subject) == 0,
	};
}

static int fill_chain(struct x509_chain *chain, X509 const *crt, X509_STORE const *store,
		      unsigned int depth)
{
	X509_NAME *issuer  = X509_get_issuer_name(crt);
	X509_NAME *subject = X509_get_subject_name(crt);
	STACK_OF(X509_OBJECT)	*chain_objects;

	chain_add_x509(chain, crt, depth);

	if (X509_NAME_cmp(issuer, subject) == 0) {
		return 0;
	}

	chain_objects = X509_STORE_get0_objects(store);
	for (int i = 0; i < sk_X509_OBJECT_num(chain_objects); ++i) {
		X509_OBJECT	*o = sk_X509_OBJECT_value(chain_objects, i);
		X509 const	*ca;
		X509_NAME const	*ca_subject;

		if (X509_OBJECT_get_type(o) != X509_LU_X509)
			continue;

		ca = X509_OBJECT_get0_X509(o);
		ca_subject = X509_get_subject_name(ca);

		if (X509_NAME_cmp(issuer, ca_subject) != 0)
			continue;

		fill_chain(chain, ca, store, depth + 1);
	}

	return 0;
}

static int chain_cmp_depth(void const *a_, void const *b_)
{
	struct x509_chain_object const *a = a_;
	struct x509_chain_object const *b = b_;

	return a->depth - b->depth;
}

static void show_help(void)
{
	printf("Usage: chain-x509 [-A|--no-anchor] <certificate> <chain>+\n");
	printf("  -A, --no-anchor    Do not include self-signed anchor certificates\n");
	printf("  --help             Show this help message\n");}

int main(int argc, char *argv[])
{
	X509_STORE	*crt_store = X509_STORE_new();
	X509_LOOKUP	*crt_lookup = X509_STORE_add_lookup(crt_store, X509_LOOKUP_file());
	STACK_OF(X509_OBJECT)	*crt_store_objects;
	X509_OBJECT	*crt;

	X509_STORE	*ca_store = X509_STORE_new();
	X509_LOOKUP	*ca_lookup = X509_STORE_add_lookup(ca_store, X509_LOOKUP_file());

	bool		no_anchor = false;
	bool		have_anchor = false;
	struct x509_chain	chain = {};

	int		optidx = 1;

	if (!crt_lookup || !ca_lookup) {
		fprintf(stderr, "failed to construct x509 lookup\n");
		return EXIT_FAILURE;
	}

	if (!argv[optidx]) {
		fprintf(stderr, "missing option\n");
		return EXIT_FAILURE;
	}

	if (strcmp(argv[optidx], "-A") == 0 ||
	    strcmp(argv[optidx], "--no-anchor") == 0) {
		no_anchor = true;
		++optidx;
	} else if (strcmp(argv[optidx], "--help") == 0) {
		show_help();
		return EXIT_SUCCESS;
	}

	if (!argv[optidx]) {
		fprintf(stderr, "missing certificate\n");
		return EXIT_FAILURE;
	}

	if (X509_load_cert_file(crt_lookup, argv[optidx], X509_LU_X509) < 0) {
		fprintf(stderr, "ERROR: failed to add '%s'\n",
			argv[optidx]);
		return EXIT_FAILURE;
	}

	crt_store_objects = X509_STORE_get0_objects(crt_store);
	if (sk_X509_OBJECT_num(crt_store_objects) != 1) {
		fprintf(stderr, "ERROR: more than one certificate in crt\n");
		return EXIT_FAILURE;
	}

	crt = sk_X509_OBJECT_value(crt_store_objects, 0);

	++optidx;

	for (int i = optidx; i < argc; ++i) {
		if (X509_LOOKUP_load_file(ca_lookup, argv[i], X509_LU_X509) < 0) {
			fprintf(stderr, "ERROR: failed to add '%s'\n",
				argv[i]);
			return EXIT_FAILURE;
		}
	}

	if (fill_chain(&chain, X509_OBJECT_get0_X509(crt), ca_store, 0) < 0)
		return EXIT_FAILURE;

	qsort(chain.obj, chain.num, sizeof chain.obj[0], chain_cmp_depth);

	for (size_t i = 0; i < chain.num; ++i) {
		X509 const *x509 = chain.obj[i].x509;

		if (chain.obj[i].is_anchor)
			have_anchor = true;

		if (chain.obj[i].is_anchor && no_anchor)
			continue;

		printf("Subject: ");
		X509_NAME_print_ex_fp(
			stdout, X509_get_subject_name(x509), 0, 0);
		printf("\n");

		printf("Issuer:  ");
		X509_NAME_print_ex_fp(
			stdout, X509_get_issuer_name(x509), 0, 0);
		printf("\n");

		PEM_write_X509(stdout, x509);
	}

	free(chain.obj);

	X509_STORE_free(crt_store);
	X509_STORE_free(ca_store);

	if (!have_anchor) {
		fprintf(stderr, "no anchor found for certificate\n");
		return EXIT_FAILURE;
	}
}
