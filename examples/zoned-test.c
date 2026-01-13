/* SPDX-License-Identifier: MIT */
/*
 * Simple test application for liburing zone device support
 * Tests basic zone operations on SMR/ZAC devices
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/blkzoned.h>
#include <liburing.h>
#include <liburing/zoned.h>

#define TEST_BUFFER_SIZE (256 * 1024)  // 256KB
#define IO_DEPTH 32

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <device> [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s <size>    Write size in KB (default: 256)\n");
    fprintf(stderr, "  -z <zone>    Target zone index (default: first sequential zone)\n");
    fprintf(stderr, "  -v           Verbose output\n");
    fprintf(stderr, "\nExample: %s /dev/sdg\n", prog);
}

static int wait_completion(struct io_uring *ring, int expected)
{
    struct io_uring_cqe *cqe;
    int completed = 0;
    
    while (completed < expected) {
        int ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0) {
            fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
            return ret;
        }
        
        if (cqe->res < 0) {
            fprintf(stderr, "I/O error: %s\n", strerror(-cqe->res));
            io_uring_cqe_seen(ring, cqe);
            return cqe->res;
        }
        
        completed++;
        io_uring_cqe_seen(ring, cqe);
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    const char *device_path = NULL;
    int fd, ret, opt;
    struct io_uring ring;
    struct uring_zone_info *zones = NULL;
    size_t zone_count = 0;
    size_t target_zone_idx = 0;
    size_t write_size = TEST_BUFFER_SIZE;
    bool verbose = false;
    bool zone_specified = false;
    void *write_buf = NULL, *read_buf = NULL;
    
    // Parse arguments
    while ((opt = getopt(argc, argv, "s:z:vh")) != -1) {
        switch (opt) {
        case 's':
            write_size = atoi(optarg) * 1024;
            break;
        case 'z':
            target_zone_idx = atoi(optarg);
            zone_specified = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: Device path required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    device_path = argv[optind];
    
    printf("=== liburing Zone Device Test ===\n");
    printf("Device: %s\n", device_path);
    printf("Write size: %zu KB\n", write_size / 1024);
    
    // Open device with O_DIRECT
    fd = open(device_path, O_RDWR | O_DIRECT);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // Initialize io_uring
    ret = io_uring_queue_init(IO_DEPTH, &ring, 0);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-ret));
        close(fd);
        return 1;
    }
    
    // Discover zones
    printf("\n--- Discovering Zones ---\n");
    ret = liburing_discover_zones(fd, &zones, &zone_count);
    if (ret < 0) {
        fprintf(stderr, "liburing_discover_zones: %s\n", strerror(-ret));
        goto cleanup;
    }
    
    printf("Found %zu zones\n", zone_count);
    
    // Find a sequential write required zone
    struct uring_zone_info *test_zone = NULL;
    if (zone_specified) {
        if (target_zone_idx >= zone_count) {
            fprintf(stderr, "Error: Zone %zu does not exist (max: %zu)\n", 
                    target_zone_idx, zone_count - 1);
            ret = -EINVAL;
            goto cleanup;
        }
        test_zone = &zones[target_zone_idx];
    } else {
        for (size_t i = 0; i < zone_count; i++) {
            if (zones[i].zone_type == BLK_ZONE_TYPE_SEQWRITE_REQ &&
                liburing_zone_is_writable(&zones[i])) {
                test_zone = &zones[i];
                target_zone_idx = i;
                break;
            }
        }
    }
    
    if (!test_zone) {
        fprintf(stderr, "Error: No suitable sequential write zone found\n");
        ret = -ENODEV;
        goto cleanup;
    }
    
    printf("\n--- Target Zone ---\n");
    printf("Zone %zu:\n", target_zone_idx);
    printf("  Type: %s\n", liburing_zone_type_str(test_zone->zone_type));
    printf("  Condition: %s\n", liburing_zone_cond_str(test_zone->zone_cond));
    printf("  Start LBA: %lu (%.2f GB)\n", test_zone->start_lba,
           (test_zone->start_lba * 512.0) / (1024*1024*1024));
    printf("  Length: %lu sectors (%.2f GB)\n", test_zone->length,
           (test_zone->length * 512.0) / (1024*1024*1024));
    printf("  Write Pointer: %lu\n", test_zone->write_pointer);
    printf("  Available: %lu sectors (%.2f GB)\n",
           liburing_zone_available_space(test_zone),
           (liburing_zone_available_space(test_zone) * 512.0) / (1024*1024*1024));
    
    // Check if zone has enough space
    size_t required_sectors = (write_size + 511) / 512;
    if (liburing_zone_available_space(test_zone) < required_sectors) {
        fprintf(stderr, "Error: Zone does not have enough space\n");
        ret = -ENOSPC;
        goto cleanup;
    }
    
    // Allocate aligned buffers
    write_buf = liburing_alloc_aligned_buffer(write_size, 4096);
    read_buf = liburing_alloc_aligned_buffer(write_size, 4096);
    if (!write_buf || !read_buf) {
        fprintf(stderr, "Error: Failed to allocate buffers\n");
        ret = -ENOMEM;
        goto cleanup;
    }
    
    // Fill write buffer with test pattern
    for (size_t i = 0; i < write_size; i++) {
        ((unsigned char*)write_buf)[i] = (unsigned char)(i & 0xFF);
    }
    
    printf("\n--- Test Operations ---\n");
    
    // Reset zone
    printf("1. Resetting zone...\n");
    ret = liburing_zone_reset(&ring, fd, test_zone);
    if (ret < 0) {
        fprintf(stderr, "liburing_zone_reset: %s\n", strerror(-ret));
        goto cleanup;
    }
    printf("   Zone reset successful (WP at LBA %lu)\n", test_zone->start_lba);
    
    // Write data
    printf("2. Writing %zu KB to zone...\n", write_size / 1024);
    ret = liburing_zone_write(&ring, fd, test_zone, write_buf, write_size);
    if (ret < 0) {
        fprintf(stderr, "liburing_zone_write: %s\n", strerror(-ret));
        goto cleanup;
    }
    
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
        goto cleanup;
    }
    
    ret = wait_completion(&ring, 1);
    if (ret < 0) {
        fprintf(stderr, "Write operation failed\n");
        goto cleanup;
    }
    
    printf("   Write successful\n");
    
    // Update write pointer
    test_zone->write_pointer += required_sectors;
    
    // Read data back
    printf("3. Reading %zu KB from zone...\n", write_size / 1024);
    ret = liburing_zone_read(&ring, fd, test_zone, read_buf, write_size, 0);
    if (ret < 0) {
        fprintf(stderr, "liburing_zone_read: %s\n", strerror(-ret));
        goto cleanup;
    }
    
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
        goto cleanup;
    }
    
    ret = wait_completion(&ring, 1);
    if (ret < 0) {
        fprintf(stderr, "Read operation failed\n");
        goto cleanup;
    }
    
    printf("   Read successful\n");
    
    // Verify data
    printf("4. Verifying data integrity...\n");
    if (memcmp(write_buf, read_buf, write_size) != 0) {
        fprintf(stderr, "   FAILED: Data mismatch!\n");
        
        if (verbose) {
            for (size_t i = 0; i < write_size && i < 256; i++) {
                if (((unsigned char*)write_buf)[i] != ((unsigned char*)read_buf)[i]) {
                    fprintf(stderr, "   Mismatch at offset %zu: wrote 0x%02x, read 0x%02x\n",
                            i, ((unsigned char*)write_buf)[i], ((unsigned char*)read_buf)[i]);
                }
            }
        }
        
        ret = -EIO;
        goto cleanup;
    }
    
    printf("   PASSED: Data verified successfully\n");
    
    printf("\n=== Test PASSED ===\n");
    ret = 0;
    
cleanup:
    if (write_buf)
        free(write_buf);
    if (read_buf)
        free(read_buf);
    if (zones)
        free(zones);
    
    io_uring_queue_exit(&ring);
    close(fd);
    
    return ret;
}
