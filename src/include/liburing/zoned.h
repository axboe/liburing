/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_ZONED_H
#define LIBURING_ZONED_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <liburing.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Zone Information Structure
 * ======================================================================== */

/**
 * Zone information structure matching kernel blk_zone
 */
struct uring_zone_info {
    uint64_t start_lba;         /**< Zone start sector */
    uint64_t length;            /**< Zone length in sectors */
    uint64_t write_pointer;     /**< Current write pointer (sequential zones) */
    uint64_t capacity;          /**< Zone capacity in sectors */
    uint8_t zone_type;          /**< Zone type (conventional, sequential) */
    uint8_t zone_cond;          /**< Zone condition (empty, open, closed, etc.) */
    uint8_t reserved[6];        /**< Reserved for future use */
};

/* ========================================================================
 * Constants
 * ======================================================================== */

#define LIBURING_ZONE_SECTOR_SIZE 512
#define LIBURING_ZONE_MAX_BATCH 32

/* ========================================================================
 * Zone Discovery and Information
 * ======================================================================== */

/**
 * Get zone information starting from a specific sector
 * @fd: File descriptor of the zoned block device
 * @sector: Starting sector for zone query
 * @max_zones: Maximum number of zones to retrieve
 * @zones: Output array to store zone information
 * @return: Number of zones retrieved, or negative error code
 */
int liburing_get_zones(int fd, uint64_t sector, int max_zones, struct uring_zone_info *zones);

/**
 * Discover all zones on a zoned block device
 * @fd: File descriptor of the zoned block device
 * @zones_out: Output pointer to allocated zone array
 * @zone_count_out: Output pointer to zone count
 * @return: 0 on success, negative error code on failure
 * @note: Caller must free zones_out when done
 */
int liburing_discover_zones(int fd, struct uring_zone_info **zones_out, size_t *zone_count_out);

/**
 * Refresh the write pointer of a zone
 * @fd: File descriptor of the zoned block device
 * @zone: Zone to refresh
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_refresh_wp(int fd, struct uring_zone_info *zone);

/* ========================================================================
 * Zone Operations
 * ======================================================================== */

/**
 * Reset a zone (set write pointer to start)
 * @ring: io_uring instance
 * @fd: File descriptor of the zoned block device
 * @zone: Zone to reset
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_reset(struct io_uring *ring, int fd, struct uring_zone_info *zone);

/**
 * Write data to a zone at its current write pointer
 * @ring: io_uring instance
 * @fd: File descriptor of the zoned block device
 * @zone: Target zone
 * @buf: Data buffer to write
 * @len: Length of data in bytes
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_write(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                       const void *buf, size_t len);

/**
 * Read data from a zone
 * @ring: io_uring instance
 * @fd: File descriptor of the zoned block device
 * @zone: Source zone
 * @buf: Buffer to read into
 * @len: Length of data to read in bytes
 * @zone_offset: Offset within the zone (in bytes)
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_read(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                      void *buf, size_t len, off_t zone_offset);

/**
 * Write multiple buffers to a zone in a batch (linked operations)
 * @ring: io_uring instance
 * @fd: File descriptor of the zoned block device
 * @zone: Target zone
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec entries
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_write_batch(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                              struct iovec *iov, int iovcnt);

/**
 * Write vectored data to a zone
 * @ring: io_uring instance
 * @fd: File descriptor of the zoned block device
 * @zone: Target zone
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec entries
 * @return: 0 on success, negative error code on failure
 */
int liburing_zone_writev(struct io_uring *ring, int fd, struct uring_zone_info *zone,
                        const struct iovec *iov, int iovcnt);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * Convert zone condition to human-readable string
 * @cond: Zone condition value
 * @return: String representation of the condition
 */
const char *liburing_zone_cond_str(unsigned char cond);

/**
 * Convert zone type to human-readable string
 * @type: Zone type value
 * @return: String representation of the type
 */
const char *liburing_zone_type_str(unsigned char type);

/**
 * Allocate aligned buffer for direct I/O operations
 * @size: Size of buffer to allocate
 * @alignment: Alignment requirement (typically 4096)
 * @return: Pointer to allocated buffer, or NULL on error
 */
void *liburing_alloc_aligned_buffer(size_t size, size_t alignment);

/**
 * Check if a zone is writable (not read-only, offline, or full)
 * @zone: Zone to check
 * @return: true if zone can be written to
 */
bool liburing_zone_is_writable(const struct uring_zone_info *zone);

/**
 * Get available space in a zone
 * @zone: Zone to check
 * @return: Available space in sectors
 */
uint64_t liburing_zone_available_space(const struct uring_zone_info *zone);

/**
 * Filter zones by type and/or condition
 * @zones: Array of zones to filter
 * @zone_count: Number of zones in array
 * @zone_type: Zone type to filter by (0xFF = any)
 * @zone_cond: Zone condition to filter by (0xFF = any)
 * @filtered_zones: Output pointer to filtered zone array
 * @filtered_count: Output pointer to filtered zone count
 * @return: 0 on success, negative error code on failure
 * @note: Caller must free filtered_zones when done
 */
int liburing_filter_zones(const struct uring_zone_info *zones, size_t zone_count,
                          unsigned char zone_type, unsigned char zone_cond,
                          struct uring_zone_info **filtered_zones, size_t *filtered_count);

/**
 * Find zones suitable for writing with specified capacity
 * @zones: Array of zones to search
 * @zone_count: Number of zones in array
 * @required_capacity_sectors: Minimum required capacity in sectors
 * @max_zones: Maximum zones to return (0 = no limit)
 * @suitable_zones: Output pointer to suitable zone array
 * @found_count: Output pointer to found zone count
 * @return: 0 on success, negative error code on failure
 * @note: Caller must free suitable_zones when done
 */
int liburing_find_suitable_zones(const struct uring_zone_info *zones, size_t zone_count,
                                 size_t required_capacity_sectors, int max_zones,
                                 struct uring_zone_info **suitable_zones, int *found_count);

#ifdef __cplusplus
}
#endif

#endif /* LIBURING_ZONED_H */
