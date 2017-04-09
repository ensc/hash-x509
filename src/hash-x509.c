/*	--*- c -*--
 * Copyright (C) 2017 Enrico Scholz <enrico.scholz@ensc.de>
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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <dirent.h>
#include <search.h>
#include <inttypes.h>
#include <unistd.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#define MAX_DIR_IDX	(LONG_MAX)

struct x509_crt {
	X509		*x509;
	unsigned int	dir_idx;
	char const	*fname;

	/* crt is in new crt bundle too */
	bool		is_new;
};

struct x509_crl {
	X509_CRL	*crl;
	unsigned int	dir_idx;
	char const	*fname;

	/* crl is in new crl list too */
	bool		is_new;
};

struct x509_hash {
	uint32_t		hash;

	struct x509_crt		*crts;
	size_t			num_crts;

	/* there are new crts from the bundle which were not in the hash
	 * directory yet */
	bool			new_crts;

	struct x509_crl		*crls;
	size_t			num_crls;

	/* there are new crls from the bundle which were not in the hash
	 * directory yet */
	bool			new_crls;
};

struct x509_objects {
	struct x509_hash	*list;
	size_t			num;
};

static int cmp_hash(void const *numeric_hash_, void const *hash_)
{
	unsigned long const		*a = numeric_hash_;
	struct x509_hash const		*b = hash_;

	if (*a < b->hash)
		return -1;
	else if (*a > b->hash)
		return +1;
	else
		return 0;
}

static int cmp_crl_crl(void const *a_, void const *b_)
{
	struct x509_crl const		*a = a_;
	struct x509_crl const		*b = b_;

	ASN1_TIME const	*tm_a = X509_CRL_get_lastUpdate(a->crl);
	ASN1_TIME const	*tm_b = X509_CRL_get_lastUpdate(b->crl);

	int		day;
	int		sec;
	int		d;

	if (!ASN1_TIME_diff(&day, &sec, tm_b, tm_a)) {
		d = 0;
	} else {
		if (day < 0 || sec < 0)
			d = -1;
		else if (day == 0 && sec == 0)
			d =  0;
		else
			d = +1;
	}

	if (d != 0)
		return d;
	else
		return X509_CRL_cmp(b->crl, a->crl);
}

static int cmp_x509_x509(void const *a_, void const *b_)
{
	struct x509_crt const		*a = a_;
	struct x509_crt const		*b = b_;

	ASN1_INTEGER const	*ser_a = X509_get_serialNumber((X509 *)(a->x509));
	ASN1_INTEGER const	*ser_b = X509_get_serialNumber((X509 *)(b->x509));

	/* sort in descending order to emit certificates with higher serial
	 * number first */
	int	d = ASN1_INTEGER_cmp(ser_b, ser_a);
	if (d != 0)
		return d;
	else
		return X509_cmp(b->x509, a->x509);
}

static int cmp_x509_crl(void const *crl_, void const *crl_obj_)
{
	X509_CRL const		*a = crl_;
	struct x509_crl const	*b = crl_obj_;

	assert(a != NULL);

	if (a == b->crl)
		return 0;
	else if (a == NULL)
		return -1;
	else if (b == NULL)
		return +1;
	else
		return X509_CRL_cmp(a, b->crl);
}

static int cmp_x509_crt(void const *crt_, void const *crt_obj_)
{
	X509 const		*a = crt_;
	struct x509_crt const	*b = crt_obj_;

	assert(a != NULL);

	if (a == b->x509)
		return 0;
	else if (a == NULL)
		return -1;
	else if (b == NULL)
		return +1;
	else
		return X509_cmp(a, b->x509);
}

static struct x509_hash *new_hash(struct x509_objects *objs)
{
	struct x509_hash	*tmp;
	struct x509_hash	*res;

	tmp = realloc(objs->list, (objs->num + 1u) * sizeof objs->list[0]);
	if (!tmp)
		return NULL;

	res        = &tmp[objs->num];
	objs->list = tmp;
	++objs->num;

	*res = (struct x509_hash) {
		.crts = NULL,
		.num_crts = 0,

		.crls = NULL,
		.num_crls = 0,
	};

	return res;
}

static struct x509_crl *new_crl(struct x509_hash *hash)
{
	struct x509_crl		*tmp;
	struct x509_crl		*res;

	tmp = realloc(hash->crls, (hash->num_crls + 1u) * sizeof hash->crls[0]);
	if (!tmp)
		return NULL;

	res        = &tmp[hash->num_crls];
	hash->crls = tmp;
	++hash->num_crls;

	*res = (struct x509_crl) {
		.crl = NULL,
		.fname = NULL,
		.is_new = false,
	};

	return res;
}

static struct x509_crt *new_crt(struct x509_hash *hash)
{
	struct x509_crt		*tmp;
	struct x509_crt		*res;

	tmp = realloc(hash->crts, (hash->num_crts + 1u) * sizeof hash->crts[0]);
	if (!tmp)
		return NULL;

	res        = &tmp[hash->num_crts];
	hash->crts = tmp;
	++hash->num_crts;

	*res = (struct x509_crt) {
		.x509 = NULL,
		.fname = NULL,
		.is_new = false,
	};

	return res;
}

static struct x509_crl *add_crl(struct x509_objects *objs, X509_CRL *crl,
				bool is_new)
{
	X509_NAME		*issuer = X509_CRL_get_issuer(crl);
	unsigned long		hash = X509_NAME_hash(issuer);
	struct x509_hash	*h;
	struct x509_crl		*crl_obj;

	h = lfind(&hash, objs->list, &objs->num, sizeof objs->list[0], cmp_hash);
	if (!h) {
		h = new_hash(objs);
		if (!h)
			return NULL;

		h->hash = hash;
	}

	if (is_new) {
		crl_obj = lfind(crl, h->crls, &h->num_crls,
				sizeof h->crls[0], cmp_x509_crl);

		if (crl_obj) {
			crl_obj->is_new = true;
			return crl_obj;
		}

		h->new_crls = true;
	}

	crl_obj = new_crl(h);
	if (!crl_obj)
		return NULL;

	crl_obj->crl = X509_CRL_dup(crl);
	crl_obj->is_new = is_new;

	return crl_obj;
}

static struct x509_crt *add_crt(struct x509_objects *objs, X509 *crt,
				bool is_new)
{
	unsigned long		hash = X509_subject_name_hash(crt);
	struct x509_hash	*h;
	struct x509_crt		*crt_obj;

	h = lfind(&hash, objs->list, &objs->num, sizeof objs->list[0], cmp_hash);
	if (!h) {
		h = new_hash(objs);
		if (!h)
			return NULL;

		h->hash = hash;
	}

	if (is_new) {
		crt_obj = lfind(crt, h->crts, &h->num_crts,
				sizeof h->crts[0], cmp_x509_crt);

		if (crt_obj) {
			crt_obj->is_new = true;
			return crt_obj;
		}

		h->new_crts = true;
	}

	crt_obj = new_crt(h);
	if (!crt_obj)
		return NULL;

	crt_obj->x509 = X509_dup(crt);
	crt_obj->is_new = is_new;

	return crt_obj;
}

static bool read_crl(FILE *f, struct x509_objects *objs,
		     char const *fname, char const *idx_str)
{
	X509_CRL	*crl;
	struct x509_crl	*crl_obj;
	char		*err;
	unsigned long	idx;

	idx = strtoul(idx_str, &err, 10);
	if (*err || err == idx_str)
		/* index not a number */
		return false;

	if (idx > (unsigned long)MAX_DIR_IDX)
		return false;

	crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
	if (!crl)
		return false;

	crl_obj = add_crl(objs, crl, false);
	X509_CRL_free(crl);

	if (!crl_obj)
		return false;

	crl_obj->dir_idx = idx;
	crl_obj->fname = strdup(fname);

	if (!crl_obj->fname)
		/* TODO: improve error handling! */
		abort();

	return true;
}

static bool read_crt(FILE *f, struct x509_objects *objs,
		     char const *fname, char const *idx_str)
{
	X509		*crt;
	struct x509_crt	*crt_obj;
	char		*err;
	unsigned long	idx;

	idx = strtoul(idx_str, &err, 10);
	if (*err || err == idx_str)
		/* index not a number */
		return false;

	if (idx > (unsigned long)MAX_DIR_IDX)
		return false;

	crt = PEM_read_X509(f, NULL, NULL, NULL);
	if (!crt)
		return false;

	crt_obj = add_crt(objs, crt, false);
	X509_free(crt);

	if (!crt_obj)
		return false;

	crt_obj->dir_idx = idx;
	crt_obj->fname = strdup(fname);
	if (!crt_obj->fname)
		/* TODO: improve error handling! */
		abort();

	return true;
}

static bool read_dir(int dir_fd, struct x509_objects *objs)
{
	int	new_fd = dup(dir_fd);	/* allow closedir() */
	DIR	*dir = fdopendir(new_fd);

	if (!dir) {
		perror("fdopen()");
		return false;
	}

	for (;;) {
		struct dirent	*entry;
		size_t		len;
		char const	*fname;
		FILE		*f;
		int		fd;

		errno = 0;
		entry = readdir(dir);
		if (!entry && errno != 0) {
			perror("readdir()");
			goto err;
		}
		if (!entry)
			break;

		fname = entry->d_name;
		len = strlen(fname);
		if (len < sizeof("01234567.0") - 1u)
			continue;

		if (fname[8] != '.')
			continue;

		fd = openat(dir_fd, fname, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			/* TODO: add diagnostics? */
			continue;

		f = fdopen(fd, "r");
		if (fname[9] == 'r') {
			read_crl(f, objs, fname, fname + 10);
		} else {
			read_crt(f, objs, fname, fname + 9);
		}
		fclose(f);
	}

	closedir(dir);
	return true;

err:
	closedir(dir);
	return false;
}

static unsigned int get_next_crt_idx(struct x509_hash const *hash)
{
	unsigned int	res = 0;

	for (;;) {
		bool		found = false;

		for (size_t i = 0; i < hash->num_crts; ++i) {
			struct x509_crt const	*crt = &hash->crts[i];

			if (crt->fname && crt->dir_idx == res) {
				found = true;
				break;
			}
		}

		if (!found)
			break;

		++res;
	}

	return res;
}

static unsigned int get_next_crl_idx(struct x509_hash const *hash)
{
	unsigned int	res = 0;

	for (;;) {
		bool		found = false;

		for (size_t i = 0; i < hash->num_crls; ++i) {
			struct x509_crl const	*crl = &hash->crls[i];

			if (crl->fname && crl->dir_idx == res) {
				found = true;
				break;
			}
		}

		if (!found)
			break;

		++res;
	}

	return res;
}

static bool emit_new_crt(int dir_fd, struct x509_crt const *crt,
			 struct x509_hash const *hash, unsigned int *idx)
{
	char	fname_buf[sizeof hash->hash * 2 + sizeof(".") +
			  sizeof *idx * 3];
	int	fd;
	FILE	*f;

	if (!crt->is_new || crt->fname)
		return true;

	sprintf(fname_buf, "%08" PRIx32 ".%u", hash->hash, *idx);

	fd = openat(dir_fd, fname_buf, O_WRONLY | O_CREAT | O_CLOEXEC | O_EXCL, 0644);
	if (fd < 0) {
		fprintf(stderr, "openat(..., %s): %s\n", fname_buf,
			strerror(errno));
		return false;
	}

	f = fdopen(fd, "w");
	PEM_write_X509(f, crt->x509);
	fclose(f);

	*idx += 1;

	return true;
}

static bool remove_old_crt(int dir_fd, struct x509_crt const *crt)
{
	int	rc;

	if (crt->is_new || !crt->fname)
		return true;

	rc = unlinkat(dir_fd, crt->fname, 0);
	if (rc < 0) {
		fprintf(stderr, "unlinkat(... %s): %s\n", crt->fname,
			strerror(errno));
		return false;
	}

	return true;
}

static bool remove_old_crl(int dir_fd, struct x509_crl const *crl)
{
	int	rc;

	if (crl->is_new || !crl->fname)
		return true;

	rc = unlinkat(dir_fd, crl->fname, 0);
	if (rc < 0) {
		fprintf(stderr, "unlinkat(... %s): %s\n", crl->fname,
			strerror(errno));
		return false;
	}

	return true;
}

static bool emit_new_crl(int dir_fd, struct x509_crl const *crl,
			 struct x509_hash const *hash, unsigned int *idx)
{
	char	fname_buf[sizeof hash->hash * 2 + sizeof(".") +
			  sizeof *idx * 3];
	int	fd;
	FILE	*f;

	if (!crl->is_new || crl->fname)
		return true;

	sprintf(fname_buf, "%08" PRIx32 ".r%u", hash->hash, *idx);

	fd = openat(dir_fd, fname_buf, O_WRONLY | O_CREAT | O_CLOEXEC | O_EXCL, 0644);
	if (fd < 0) {
		fprintf(stderr, "openat(..., %s): %s\n", fname_buf,
			strerror(errno));
		return false;
	}

	f = fdopen(fd, "w");
	PEM_write_X509_CRL(f, crl->crl);
	fclose(f);

	*idx += 1;

	return true;
}

static bool emit_object(int dir_fd, struct x509_hash const *hash)
{
	unsigned int	next_idx;

	next_idx = get_next_crt_idx(hash);
	for (size_t i = 0; i < hash->num_crts; ++i)
		emit_new_crt(dir_fd, &hash->crts[i], hash, &next_idx);

	next_idx = get_next_crl_idx(hash);
	for (size_t i = 0; i < hash->num_crls; ++i)
		emit_new_crl(dir_fd, &hash->crls[i], hash, &next_idx);

	for (size_t i = 0; i < hash->num_crls; ++i)
		remove_old_crl(dir_fd, &hash->crls[i]);

	for (size_t i = 0; i < hash->num_crts; ++i)
		remove_old_crt(dir_fd, &hash->crts[i]);

	return true;
}

static void sort_objects(struct x509_hash *hash)
{
	qsort(hash->crts, hash->num_crts, sizeof hash->crts[0], cmp_x509_x509);
	qsort(hash->crls, hash->num_crls, sizeof hash->crls[0], cmp_crl_crl);
}

int main(int argc, char *argv[])
{
	char const	*outdir = argv[1];
	X509_STORE	*store = X509_STORE_new();
	X509_LOOKUP	*lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	int		dir_fd;
	int		lock_fd;
	int		rc;
	struct x509_objects	objects = {
		.list	= NULL,
		.num	= 0,
	};

	if (!lookup) {
		fprintf(stderr, "failed to construct x509 lookup\n");
		return EXIT_FAILURE;
	}

	for (int i = 2; i < argc; ++i) {
		if (X509_LOOKUP_load_file(lookup, argv[i], X509_LU_X509) < 0 ||
		    X509_LOOKUP_load_file(lookup, argv[i], X509_LU_CRL) < 0) {
			fprintf(stderr, "WARNING: failed to add '%s'\n",
				argv[i]);
			continue;
		}
	}

	dir_fd = open(outdir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dir_fd < 0) {
		perror("open(<dir>)");
		return EXIT_FAILURE;
	}

	lock_fd = openat(dir_fd, ".lock",
			 O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_RDWR, 0600);
	if (lock_fd < 0) {
		perror("open(<lock>)");
		return EXIT_FAILURE;
	}

	rc = lockf(lock_fd, F_LOCK, 0);
	if (rc < 0) {
		perror("flock()");
		return EXIT_FAILURE;
	}

	if (!read_dir(dir_fd, &objects))
		return EXIT_FAILURE;

	for (int i = 0; i < sk_X509_OBJECT_num(store->objs); ++i) {
		X509_OBJECT	*o = sk_X509_OBJECT_value(store->objs, i);

		switch (o->type) {
		case X509_LU_X509:
			add_crt(&objects, o->data.x509, true);
			break;

		case X509_LU_CRL:
			add_crl(&objects, o->data.crl, true);
			break;

		default:
			break;
		}
	}

	for (size_t i = 0; i < objects.num; ++i) {
		sort_objects(&objects.list[i]);
		emit_object(dir_fd, &objects.list[i]);
	}
}
