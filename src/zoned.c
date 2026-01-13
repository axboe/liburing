/* SPDX-License-Identifier: MIT */
/*
 * Zone device support for io_uring
 */
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/blkzoned.h>
#include "liburing/zoned.h"
#include "lib.h"

/* ========================================================================
 * Zone Information and Discovery
 * ======================================================================== */

int liburing_get_zones(int fd, uint64_t sector, int max_zones, struct uring_zone_info *zones)
{
    if (!zones || max_zones <= 0)
        return -EINVAL;

    size_t report_size = sizeof(struct blk_zone_report) + max_zones * sizeof(struct blk_zone);
    struct blk_zone_report *report = calloc(1, report_size);
    if (!report)
        return -ENOMEM;

    report->sector = sector;
    report->nr_zones = max_zones;

    if (ioctl(fd, BLKREPORTZONE, report) < 0) {
        int err = errno;
        free(report);
        return -err;
    }

    for (uint32_t i = 0; i < report->nr_zones && i < (uint32_t)max_zones; i++) {
        zones[i].start_lba = report->zones[i].start;
        zones[i].length = report->zones[i].len;
        zones[i].write_pointer = report->zones[i].wp;
        zones[i].capacity = report->zones[i].capacity;
        zones[i].zone_type = report->zones[i].type;
        zones[i].zone_cond = report->zones[i].cond;
    }

    int num_zones = report->nr_zones;
    free(report);
    return num_zones;
}

int liburing_discover_zones(int fd, struct uring_zone_info **zones_out, size_t *zone_count_out)
{
    if (!zones_out || !zone_count_out)
        return -EINVAL;

    size_t allocated = 1024;
    struct uring_zone_info *zones = calloc(allocated, sizeof(struct uring_zone_info));
    if (!zones)
        return -ENOMEM;

    size_t total_zones = 0;
    uint64_t sector = 0;
    const int batch_size = 512;

    while (1) {
        size_t report_size = sizeof(struct blk_zone_report) + batch_size * sizeof(struct blk_zone);
        struct blk_zone_report *report = calloc(1, report_size);
        if (!report) {
            free(zones);
            return -ENOMEM;
        }

        report->sector = sector;
        report->nr_zones = batch_size;

        if (ioctl(fd, BLKREPORTZONE, report) < 0) {
            int err = errno;
            free(report);
            free(zones);
            return -err;
        }

        if (report->nr_zones == 0) {
            free(report);
            break;
        }

        if (total_zones + report->nr_zones > allocated) {
            allocated = (total_zones + report->nr_zones) * 2;
            zones = realloc(zones, allocated * sizeof(struct uring_zone_info));
            if (!zones) {
                free(report);
                return -ENOMEM;
            }
        }

        for (uint32_t i = 0; i < report->nr_zones; i++) {
            zones[total_zones].start_lba = report->zones[i].start;
            zones[total_zones].length = report->zones[i].len;
            zones[total_zones].write_pointer = report->zones[i].wp;
            zones[total_zones].capacity = report->zones[i].capacity;
            zones[total_zones].zone_type = report->zones[i].type;
            zones[total_zones].zone_cond = report->zones[i].cond;
            total_zones++;
        }

        sector = report->zones[report->nr_zones - 1].start + report->zones[report->nr_zones - 1].len;
        free(report);
    }

    *zones_out = zones;
    *zone_count_out = total_zones;
    return 0;
}

int liburing_zone_refresh_wp(int fd, struct uring_zone_info *zone)
{
    if (!zone)
        return -EINVAL;

    size_t report_size = sizeof(struct blk_zone_report) + sizeof(struct blk_zone);
    struct blk_zone_report *report = calloc(1, report_size);
    if (!report)
        return -ENOMEM;

    report->sector = zone->start_lba;
    report->nr_zones = 1;

    int ret = 0;
    if (ioctl(fd, BLKREPORTZONE, report) < 0) {
        ret = -errno;
    } else {
        if (report->nr_zones > 0) {
            zone->write_pointer = report->zones[0].wp;
            zone->zone_cond = report->zones[0].cond;
        } else {
            ret = -EIO;
        }
    }

    free(report);
    return ret;
}

/* ========================================================================
 * Zone Operations
 * ======================================================================== */

int liburing_zone_reset(struct io_uring *ring, int fd, struct uring_zone_info *zone)
{
    if (!ring || !zone)
        return -EINVAL;

    struct blk_zone_range range = {
        .sector = zone->start_lba,
        .nr_sectors = zone->length
    };

    if (ioctl(fd, BLKRESETZONE, &range) < 0)
        return -errno;

    zone->write_pointer = zone->start_lba;
    zone->zone_cond = BLK_ZONE_COND_EMPTY;
    return 0;
}

int liburing_zone_write(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                       const void *buf, size_t len)
{
    if (!ring || !zone || !buf)
        return -EINVAL;

    if (zone->zone_type == BLK_ZONE_TYPE_SEQWRITE_REQ) {
        uint64_t available_sectors = (zone->start_lba + zone->capacity) - zone->write_pointer;
        uint64_t sectors_to_write = (len + 511) / 512;
        
        if (sectors_to_write > available_sectors)
            return -ENOSPC;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
        return -ENOMEM;

    io_uring_prep_write(sqe, fd, buf, len, zone->write_pointer * 512);
    return 0;
}

int liburing_zone_read(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                      void *buf, size_t len, off_t zone_offset)
{
    if (!ring || !zone || !buf)
        return -EINVAL;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
        return -ENOMEM;

    off_t read_offset = (zone->start_lba * 512) + zone_offset;
    io_uring_prep_read(sqe, fd, buf, len, read_offset);
    return 0;
}

int liburing_zone_write_batch(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                              struct iovec *iov, int iovcnt)
{
    if (!ring || !zone || !iov || iovcnt <= 0)
        return -EINVAL;

    size_t total_len = 0;
    for (int i = 0; i < iovcnt; i++)
        total_len += iov[i].iov_len;

    if (zone->zone_type == BLK_ZONE_TYPE_SEQWRITE_REQ) {
        uint64_t available_sectors = (zone->start_lba + zone->capacity) - zone->write_pointer;
        uint64_t sectors_to_write = (total_len + 511) / 512;
        
        if (sectors_to_write > available_sectors)
            return -ENOSPC;
    }

    off_t write_offset = zone->write_pointer * 512;
    for (int i = 0; i < iovcnt; i++) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe)
            return -ENOMEM;

        io_uring_prep_write(sqe, fd, iov[i].iov_base, iov[i].iov_len, write_offset);
        write_offset += iov[i].iov_len;
        
        if (i < iovcnt - 1)
            sqe->flags |= IOSQE_IO_LINK;
    }

    return 0;
}

int liburing_zone_writev(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                        const struct iovec *iov, int iovcnt)
{
    if (!ring || !zone || !iov || iovcnt <= 0)
        return -EINVAL;

    size_t total_len = 0;
    for (int i = 0; i < iovcnt; i++)
        total_len += iov[i].iov_len;

    if (zone->zone_type == BLK_ZONE_TYPE_SEQWRITE_REQ) {
        uint64_t available_sectors = (zone->start_lba + zone->capacity) - zone->write_pointer;
        uint64_t sectors_to_write = (total_len + 511) / 512;
        
        if (sectors_to_write > available_sectors)
            return -ENOSPC;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
        return -ENOMEM;

    io_uring_prep_writev(sqe, fd, iov, iovcnt, zone->write_pointer * 512);
    return 0;
}

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

const char *liburing_zone_cond_str(unsigned char cond)
{
    switch (cond) {
    case BLK_ZONE_COND_NOT_WP: return "NOT_WP";
    case BLK_ZONE_COND_EMPTY: return "EMPTY";
    case BLK_ZONE_COND_IMP_OPEN: return "IMP_OPEN";
    case BLK_ZONE_COND_EXP_OPEN: return "EXP_OPEN";
    case BLK_ZONE_COND_CLOSED: return "CLOSED";
    case BLK_ZONE_COND_READONLY: return "READONLY";
    case BLK_ZONE_COND_FULL: return "FULL";
    case BLK_ZONE_COND_OFFLINE: return "OFFLINE";
    default: return "UNKNOWN";
    }
}

const char *liburing_zone_type_str(unsigned char type)
{
    switch (type) {
    case BLK_ZONE_TYPE_CONVENTIONAL: return "CONVENTIONAL";
    case BLK_ZONE_TYPE_SEQWRITE_REQ: return "SEQ_WRITE_REQ";
    case BLK_ZONE_TYPE_SEQWRITE_PREF: return "SEQ_WRITE_PREF";
    default: return "UNKNOWN";
    }
}

void *liburing_alloc_aligned_buffer(size_t size, size_t alignment)
{
    void *buf;
    if (posix_memalign(&buf, alignment, size) != 0)
        return NULL;
    return buf;
}

bool liburing_zone_is_writable(const struct uring_zone_info *zone)
{
    if (!zone)
        return false;
    
    return zone->zone_cond != BLK_ZONE_COND_READONLY &&
           zone->zone_cond != BLK_ZONE_COND_OFFLINE &&
           zone->zone_cond != BLK_ZONE_COND_FULL;
}

uint64_t liburing_zone_available_space(const struct uring_zone_info *zone)
{
    if (!zone)
        return 0;
    
    if (zone->zone_type == BLK_ZONE_TYPE_CONVENTIONAL)
        return zone->capacity;
    
    if (zone->write_pointer < zone->start_lba)
        return 0;
    
    uint64_t used = zone->write_pointer - zone->start_lba;
    if (used >= zone->capacity)
        return 0;
    
    return zone->capacity - used;
}

int liburing_filter_zones(const struct uring_zone_info *zones, size_t zone_count,
                          unsigned char zone_type, unsigned char zone_cond,
                          struct uring_zone_info **filtered_zones, size_t *filtered_count)
{
    if (!zones || !filtered_zones || !filtered_count)
        return -EINVAL;

    size_t count = 0;
    for (size_t i = 0; i < zone_count; i++) {
        bool type_match = (zone_type == 0xFF) || (zones[i].zone_type == zone_type);
        bool cond_match = (zone_cond == 0xFF) || (zones[i].zone_cond == zone_cond);
        
        if (type_match && cond_match)
            count++;
    }

    if (count == 0) {
        *filtered_zones = NULL;
        *filtered_count = 0;
        return 0;
    }

    struct uring_zone_info *result = calloc(count, sizeof(struct uring_zone_info));
    if (!result)
        return -ENOMEM;

    size_t idx = 0;
    for (size_t i = 0; i < zone_count; i++) {
        bool type_match = (zone_type == 0xFF) || (zones[i].zone_type == zone_type);
        bool cond_match = (zone_cond == 0xFF) || (zones[i].zone_cond == zone_cond);
        
        if (type_match && cond_match)
            result[idx++] = zones[i];
    }

    *filtered_zones = result;
    *filtered_count = count;
    return 0;
}

int liburing_find_suitable_zones(const struct uring_zone_info *zones, size_t zone_count,
                                 size_t required_capacity_sectors, int max_zones,
                                 struct uring_zone_info **suitable_zones, int *found_count)
{
    if (!zones || !suitable_zones || !found_count)
        return -EINVAL;

    struct uring_zone_info *result = calloc(max_zones > 0 ? max_zones : zone_count,
                                            sizeof(struct uring_zone_info));
    if (!result)
        return -ENOMEM;

    int count = 0;
    for (size_t i = 0; i < zone_count && (max_zones == 0 || count < max_zones); i++) {
        if (liburing_zone_is_writable(&zones[i])) {
            uint64_t available = liburing_zone_available_space(&zones[i]);
            if (available >= required_capacity_sectors) {
                result[count++] = zones[i];
            }
        }
    }

    *suitable_zones = result;
    *found_count = count;
    return 0;
}
