/* SPDX-License-Identifier: MIT */
/*
 * Test SQE group feature
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <assert.h>

#include "liburing.h"
#include "helpers.h"

//#define DEBUG
#ifdef DEBUG
#define GRP_DBG(...) printf(__VA_ARGS__)
#else
#define GRP_DBG(...)
#endif

struct test_data {
	unsigned int lead_flags, mem_flags;
	unsigned off;
	unsigned nr_cqes;
	unsigned int sqe_grp		: 1;	/* belong to sqe group */
	unsigned int fail_leader	: 1;	/* fail leader */
	unsigned int fail_member	: 1;	/* fail member */
	unsigned int fail_issue		: 1;	/* fail to issue */
};

#define INJECTED_ERR (-EIO)

/* inject failure via NOP */
static void fail_nop_sqe(struct io_uring_sqe *sqe)
{
	sqe->len = INJECTED_ERR;
	sqe->rw_flags = 0x1;
}

static void build_nop_group(struct io_uring *ring, struct test_data *d)
{
	struct io_uring_sqe *sqe, *sqe2, *sqe1;
	int nr = 0;

	sqe = io_uring_get_sqe(ring);
	sqe1 = io_uring_get_sqe(ring);
	sqe2 = io_uring_get_sqe(ring);
	assert(sqe && sqe1 && sqe2);

	io_uring_prep_nop(sqe);
	sqe->user_data = d->off + 2;
	sqe->flags |= d->lead_flags;
	if (d->sqe_grp)
		sqe->flags |= IOSQE_GROUP_LINK;
	else
		sqe->flags &= ~IOSQE_GROUP_LINK;
	if (d->fail_leader)
		fail_nop_sqe(sqe);

	io_uring_prep_nop(sqe1);
	sqe1->user_data = d->off + 0;
	sqe1->flags |= d->mem_flags;
	if (d->sqe_grp)
		sqe1->flags |= IOSQE_GROUP_LINK;
	else
		sqe1->flags &= ~IOSQE_GROUP_LINK;
	if (d->fail_member)
		fail_nop_sqe(sqe1);

	io_uring_prep_nop(sqe2);
	sqe2->user_data = d->off + 1;
	sqe2->flags |= d->mem_flags;
	if (!d->sqe_grp)
		sqe2->flags &= ~IOSQE_GROUP_LINK;

	if (!(d->lead_flags & IOSQE_CQE_SKIP_SUCCESS))
		nr += 1;
	if (!(d->mem_flags & IOSQE_CQE_SKIP_SUCCESS))
		nr += 2;

	d->nr_cqes = nr;
}

static int check_nop_group(struct io_uring *ring, struct test_data *d)
{
	struct io_uring_cqe cqes[16];
	struct io_uring_cqe *cqe;
	int errs = 0;
	int oks = 0;
	int i, ret;

	for (i = 0; i < d->nr_cqes; ++i) {
		ret = io_uring_peek_cqe(ring, &cqe);
	        if (ret) {
			fprintf(stderr, "peek failed: %d\n", ret);
			return ret;
	        }
	        io_uring_cqe_seen(ring, cqe);
		cqes[i] = *cqe;
	}

	if (d->nr_cqes == 0)
		return 0;

	cqe = &cqes[d->nr_cqes - 1];
	if (cqe->user_data != d->off + 2)
		goto fail;

	for (i = 0; i < d->nr_cqes; ++i) {
		if (cqes[i].res == 0)
			oks++;
		if (cqes[i].res < 0)
			errs++;
	}

	/* all should be failed */
	if (d->fail_issue || d->fail_leader) {
		int exp_errs = d->nr_cqes;

		if (errs != exp_errs) {
			printf("group test failed: group errors %d, exp errors %d\n",
				errs, exp_errs);
			goto fail;
		}
	}

	if (d->fail_member) {
		if (errs == 0) {
			printf("group test failed: failed members ok %d, errs %d\n",
				oks, errs);
			goto fail;
		}
	}

	return 0;
fail:
	printf("group test failed: %s leader %x member %x nr_cqes %u\n",
			__func__, d->lead_flags, d->mem_flags, d->nr_cqes);
	for (i = 0; i < d->nr_cqes; ++i) {
		cqe = &cqes[i];
		printf("No %d cqe %lld res %d\n", i, cqe->user_data, cqe->res);
	}
	return 1;
}

static int check_nop_linked_group(struct io_uring *ring, struct test_data *d,
		struct test_data *d2)
{
	int i, ret;
	struct io_uring_cqe cqes[16];
	struct io_uring_cqe *cqe, *cqe2;

	if (d->nr_cqes + d2->nr_cqes == 0)
		return 0;

	for (i = 0; i < d->nr_cqes + d2->nr_cqes; ++i) {
		ret = io_uring_peek_cqe(ring, &cqe);
	        if (ret) {
			fprintf(stderr, "peek failed: %d\n", ret);
			return ret;
	        }
	        io_uring_cqe_seen(ring, cqe);
		cqes[i] = *cqe;
	}

	cqe = &cqes[d->nr_cqes - 1];
	cqe2 = &cqes[d->nr_cqes + d2->nr_cqes - 1];

	if (cqe->user_data != d->off + 2 || cqe2->user_data != d2->off + 2)
		goto fail;

	if (d->fail_leader) {
		if (cqe->res != INJECTED_ERR) {
			printf("link group test failed: fail_leader, group res %d, exp res %d\n",
				cqe->res, -EINVAL);
			goto fail;
		}
		for (i = d->nr_cqes; i < d->nr_cqes + d2->nr_cqes; ++i) {
			cqe = &cqes[i];
			if (cqe->res != -ECANCELED) {
				printf("link group test failed: fail_leader, group2 isn't canceled\n");
				goto fail;
			}
		}
	}

	if (d->fail_member) {
		int canceled = 0, injected = 0;

		for (i = 0; i < d->nr_cqes + d2->nr_cqes; ++i) {
			cqe = &cqes[i];
			if (cqe->res == -ECANCELED)
				canceled += 1;
			if (cqe->res == INJECTED_ERR)
				injected += 1;
		}
		/* member in 1st group is failed, the other group should be canceled */
		if (canceled < d2->nr_cqes) {
			printf("link group test failed: fail_member, canceled %d"
					" invalid %d\n", canceled, injected);
			goto fail;
		}
	}

	return 0;
fail:
	printf("linked group test failed: %s group(leader %x member %x nr_cqes %u)\n",
			__func__, d->lead_flags, d->mem_flags, d->nr_cqes);
	printf("\t group2(leader %x member %x nr_cqes %u)\n",
			d2->lead_flags, d2->mem_flags, d2->nr_cqes);
	for (i = 0; i < d->nr_cqes + d2->nr_cqes; ++i) {
		cqe = &cqes[i];
		printf("No %d cqe %lld res %d grp %d\n",
			i, cqe->user_data, cqe->res, i >= d->nr_cqes);
	}
	return 1;
}

static int test(struct io_uring *ring, struct test_data *d)
{
	int ret;

	GRP_DBG("SQE Group Test (flags %x mem flags %x fail %d %d %d)\n",
				d->lead_flags, d->mem_flags, d->fail_leader,
				d->fail_member, d->fail_issue);
	build_nop_group(ring, d);
	ret = io_uring_submit_and_wait(ring, d->nr_cqes);
	GRP_DBG("Test ret %d\n", ret);
	if (ret < 0) {
                fprintf(stderr, "submit failed: %d\n", ret);
		return T_EXIT_FAIL;
        }

	ret = check_nop_group(ring, d);
	if (ret)
		return T_EXIT_FAIL;
	return T_EXIT_PASS;
}

static int test_link(struct io_uring *ring, struct test_data *d,
		struct test_data *d2)
{
	int ret;

	GRP_DBG("SQE Group Test link (flags %x mem flags %x) (flags %x mem flags %x)\n",
				d->lead_flags, d->mem_flags,
				d2->lead_flags, d2->mem_flags);
	build_nop_group(ring, d);
	build_nop_group(ring, d2);
	ret = io_uring_submit_and_wait(ring, d->nr_cqes + d2->nr_cqes);
	GRP_DBG("Test link ret %d\n", ret);
	if (ret < 0) {
                fprintf(stderr, "submit failed: %d\n", ret);
                return 1;
        }

	ret = check_nop_linked_group(ring, d, d2);
	return ret;
}

static int run_test(struct io_uring *ring, struct test_data *d)
{
	int ret = test(ring, d);
	if (ret) {
		fprintf(stderr, "Test failed lead flags %x mem flags %x"
				" fail_leader %d fail_member %d\n",
				d->lead_flags, d->mem_flags,
				d->fail_leader, d->fail_member);
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

static int __run_tests(struct io_uring *ring, struct test_data *d)
{
	unsigned char g_flag, m_flag;

	for (g_flag = 0; g_flag < 128; g_flag++)
		for (m_flag = 0; m_flag < 128; m_flag++) {
			unsigned char g_mask = IOSQE_FIXED_FILE |
				IOSQE_BUFFER_SELECT | IOSQE_CQE_SKIP_SUCCESS;
			unsigned char m_mask = g_mask | IOSQE_IO_DRAIN |
				IOSQE_IO_LINK | IOSQE_IO_HARDLINK;

			d->lead_flags = g_flag & ~g_mask;
			d->mem_flags = m_flag & ~m_mask;

			/* set IO_LINK on member for failing to issue SQE group */
			if (d->fail_issue)
				d->mem_flags = (m_flag & ~IOSQE_CQE_SKIP_SUCCESS) |
					IOSQE_IO_LINK;
			d->nr_cqes = 0;
			d->off = 0;
			if (run_test(ring, d))
				return T_EXIT_FAIL;
		}

	return T_EXIT_PASS;
}

static int run_tests(struct io_uring *ring)
{
	struct test_data data = {
		.sqe_grp = 1,
		.fail_issue = 0,
	};
	int ret;

	data.fail_leader = 0;
	data.fail_member = 0;
	ret = __run_tests(ring, &data);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 1;
	data.fail_member = 0;
	ret = __run_tests(ring, &data);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 0;
	data.fail_member = 1;
	ret = __run_tests(ring, &data);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 1;
	data.fail_member = 1;
	ret = __run_tests(ring, &data);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 0;
	data.fail_member = 0;
	data.fail_issue = 1;
	ret = __run_tests(ring, &data);
	if (ret != T_EXIT_PASS)
		return ret;

	return T_EXIT_PASS;
}

static int __run_link_tests(struct io_uring *ring, struct test_data *d,
		struct test_data *d2)
{
	int g_drain, g_async, g_link;
	int g_drain2, g_async2, g_link2;
	g_link = 1;
	for (g_async = 0; g_async < 2; g_async += 1)
		for (g_drain = 0; g_drain < 2; g_drain += 1)
			for (g_async2 = 0; g_async2 < 2; g_async2 += 1)
				for (g_drain2 = 0; g_drain2 < 2; g_drain2 += 1)
					for (g_link2 = 0; g_link2 < 2; g_link2 += 1)  {
				d->lead_flags = (g_async ? IOSQE_ASYNC : 0) |
					(g_drain ? IOSQE_IO_DRAIN : 0) |
					(g_link ? IOSQE_IO_LINK : 0);
				d->mem_flags = (g_async ? IOSQE_ASYNC : 0);
				d->nr_cqes = 0;
				d->off = 0;

				d2->lead_flags = (g_async2 ? IOSQE_ASYNC : 0) |
					(g_drain2 ? IOSQE_IO_DRAIN : 0) |
					(g_link2 ? IOSQE_IO_LINK : 0);
				d2->mem_flags = (g_async2 ? IOSQE_ASYNC : 0);
				d2->nr_cqes = 0;
				d2->off = 3;

				if (test_link(ring, d, d2))
					return T_EXIT_FAIL;
			}
	return T_EXIT_PASS;
}

static int run_link_tests(struct io_uring *ring)
{
	struct test_data data = {
		.sqe_grp = 1,
	};
	struct test_data data2 = {
		.sqe_grp = 1,
	};
	int ret;

	data.fail_leader = 0;
	data.fail_member = 0;
	ret =  __run_link_tests(ring, &data, &data2);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 1;
	data.fail_member = 0;
	ret =  __run_link_tests(ring, &data, &data2);
	if (ret != T_EXIT_PASS)
		return ret;

	data.fail_leader = 0;
	data.fail_member = 1;
	ret =  __run_link_tests(ring, &data, &data2);
	if (ret != T_EXIT_PASS)
		return ret;

	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring_params param;
	struct io_uring ring;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	memset(&param, 0, sizeof(param));
	ret = t_create_ring_params(16, &ring, &param);
	if (ret == T_SETUP_SKIP)
		return T_EXIT_SKIP;
	else if (ret < 0)
		return T_EXIT_FAIL;

	if (!(param.features & IORING_FEAT_SQE_GROUP))
		return T_EXIT_SKIP;

	ret = run_tests(&ring);
	if (ret != T_EXIT_PASS)
		return ret;

	ret = run_link_tests(&ring);
	if (ret != T_EXIT_PASS)
		return ret;

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
}
