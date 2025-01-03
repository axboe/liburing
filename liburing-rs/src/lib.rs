#![allow(clippy::missing_safety_doc)]

mod uring;

use std::{
    mem,
    os::raw::{c_char, c_int, c_longlong, c_uint, c_ushort, c_void},
    ptr,
    sync::atomic::{
        AtomicU16, AtomicU32,
        Ordering::{self, Acquire, Relaxed, Release},
    },
};

pub use uring::*;

const LIBURING_UDATA_TIMEOUT: u64 = u64::MAX;

trait Atomic: Copy {
    unsafe fn store(p: *mut Self, val: Self, order: Ordering);
    unsafe fn load(p: *mut Self, order: Ordering) -> Self;
}

impl Atomic for u32 {
    #[inline]
    unsafe fn store(p: *mut u32, val: u32, order: Ordering) {
        AtomicU32::from_ptr(p).store(val, order);
    }

    #[inline]
    unsafe fn load(p: *mut u32, order: Ordering) -> u32 {
        AtomicU32::from_ptr(p).load(order)
    }
}

impl Atomic for u16 {
    #[inline]
    unsafe fn store(p: *mut u16, val: u16, order: Ordering) {
        AtomicU16::from_ptr(p).store(val, order);
    }

    #[inline]
    unsafe fn load(p: *mut u16, order: Ordering) -> u16 {
        AtomicU16::from_ptr(p).load(order)
    }
}

#[inline]
unsafe fn io_uring_smp_store_release<T: Atomic>(p: *mut T, v: T) {
    Atomic::store(p, v, Release);
}

#[inline]
unsafe fn io_uring_smp_load_acquire<T: Atomic>(p: *const T) -> T {
    Atomic::load(p as *mut T, Acquire)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn IO_URING_READ_ONCE<T: Atomic>(var: *const T) -> T {
    Atomic::load(var as *mut T, Relaxed)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn IO_URING_WRITE_ONCE<T: Atomic>(var: *mut T, val: T) {
    Atomic::store(var, val, Relaxed);
}

#[inline]
unsafe fn __io_uring_peek_cqe(
    ring: *mut io_uring,
    cqe_ptr: *mut *mut io_uring_cqe,
    nr_available: *mut c_uint,
) -> c_int {
    let mut cqe;
    let mut err = 0;

    let mut available;
    let mask = (*ring).cq.ring_mask;
    let shift = io_uring_cqe_shift(ring);

    loop {
        let tail = io_uring_smp_load_acquire((*ring).cq.ktail);
        let head = *(*ring).cq.khead;

        cqe = ptr::null_mut();
        available = tail - head;
        if available == 0 {
            break;
        }

        cqe = &raw mut *(*ring).cq.cqes.add(((head & mask) << shift) as usize);
        if ((*ring).features & IORING_FEAT_EXT_ARG) == 0
            && (*cqe).user_data == LIBURING_UDATA_TIMEOUT
        {
            if (*cqe).res < 0 {
                err = (*cqe).res;
            }
            io_uring_cq_advance(ring, 1);
            if err == 0 {
                continue;
            }
            cqe = ptr::null_mut();
        }

        break;
    }

    *cqe_ptr = cqe;
    if !nr_available.is_null() {
        *nr_available = available;
    }
    err
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_shift_from_flags(flags: c_uint) -> c_uint {
    if flags & IORING_SETUP_CQE32 > 0 {
        1
    } else {
        0
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_shift(ring: *mut io_uring) -> c_uint {
    io_uring_cqe_shift_from_flags((*ring).flags)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_iter_init(ring: *mut io_uring) -> io_uring_cqe_iter {
    io_uring_cqe_iter {
        cqes: (*ring).cq.cqes,
        mask: (*ring).cq.ring_mask,
        shift: io_uring_cqe_shift(ring),
        head: *(*ring).cq.khead,
        tail: io_uring_smp_load_acquire((*ring).cq.ktail),
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_iter_next(
    iter: *mut io_uring_cqe_iter,
    cqe: *mut *mut io_uring_cqe,
) -> bool {
    if (*iter).head == (*iter).tail {
        return false;
    }

    let head = (*iter).head;
    (*iter).head += 1;

    let offset = (head & (*iter).mask) << (*iter).shift;
    *cqe = (*iter).cqes.add(offset as usize);

    true
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_peek_cqe(
    ring: *mut io_uring,
    cqe_ptr: *mut *mut io_uring_cqe,
) -> c_int {
    if __io_uring_peek_cqe(ring, cqe_ptr, ptr::null_mut()) == 0 && !(*cqe_ptr).is_null() {
        return 0;
    }

    io_uring_wait_cqe_nr(ring, cqe_ptr, 0)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_opcode_supported(p: *mut io_uring_probe, op: c_int) -> c_int {
    if op > (*p).last_op as _ {
        return 0;
    }

    if (*(*p).ops.as_ptr().add(op as _)).flags & IO_URING_OP_SUPPORTED as u16 != 0 {
        1
    } else {
        0
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cq_advance(ring: *mut io_uring, nr: c_uint) {
    if nr > 0 {
        let cq = &raw mut (*ring).cq;

        /*
         * Ensure that the kernel only sees the new value of the head
         * index after the CQEs have been read.
         */
        io_uring_smp_store_release((*cq).khead, *(*cq).khead + nr);
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_seen(ring: *mut io_uring, cqe: *mut io_uring_cqe) {
    if !cqe.is_null() {
        io_uring_cq_advance(ring, 1);
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_buf_ring_mask(ring_entries: u32) -> c_int {
    (ring_entries - 1) as _
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_buf_ring_add(
    br: *mut io_uring_buf_ring,
    addr: *mut c_void,
    len: c_uint,
    bid: c_ushort,
    mask: c_int,
    buf_offset: c_int,
) {
    let tail = (*br).__liburing_anon_1.__liburing_anon_1.as_ref().tail;
    let buf = (*br)
        .__liburing_anon_1
        .bufs
        .as_mut()
        .as_mut_ptr()
        .add(((tail as i32 + buf_offset) & mask) as usize);

    (*buf).addr = addr as usize as u64;
    (*buf).len = len;
    (*buf).bid = bid;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_buf_ring_advance(br: *mut io_uring_buf_ring, count: c_int) {
    let tail = (*br).__liburing_anon_1.__liburing_anon_1.as_ref().tail;
    let new_tail = tail.wrapping_add(count as u16);

    io_uring_smp_store_release(
        &mut (*br).__liburing_anon_1.__liburing_anon_1.as_mut().tail,
        new_tail,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_buf_ring_available(
    ring: *mut io_uring,
    br: *mut io_uring_buf_ring,
    bgid: c_ushort,
) -> c_int {
    let mut head = 0;
    let ret = io_uring_buf_ring_head(ring, bgid as _, &raw mut head);
    if ret > 0 {
        return ret;
    }
    ((*br).__liburing_anon_1.__liburing_anon_1.as_mut().tail - head) as c_int
}

#[inline]
unsafe fn io_uring_initialize_sqe(sqe: *mut io_uring_sqe) {
    (*sqe).flags = 0;
    (*sqe).ioprio = 0;
    (*sqe).__liburing_anon_3.rw_flags = 0;
    (*sqe).__liburing_anon_4.buf_index = 0;
    (*sqe).personality = 0;
    (*sqe).__liburing_anon_5.file_index = 0;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = 0;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().__pad2[0] = 0;
}

#[inline]
unsafe fn _io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe {
    let sq = &raw mut (*ring).sq;

    let head = io_uring_load_sq_head(ring);
    let tail = (*sq).sqe_tail;

    if tail - head >= (*sq).ring_entries {
        return ptr::null_mut();
    }

    let offset = (tail & (*sq).ring_mask) << io_uring_sqe_shift(ring);
    let sqe = (*sq).sqes.add(offset as usize);
    (*sq).sqe_tail = tail + 1;
    io_uring_initialize_sqe(sqe);
    sqe
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe {
    _io_uring_get_sqe(ring)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_set_data(sqe: *mut io_uring_sqe, data: *mut c_void) {
    (*sqe).user_data = data as u64;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_set_data64(sqe: *mut io_uring_sqe, data: u64) {
    (*sqe).user_data = data;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_set_flags(sqe: *mut io_uring_sqe, flags: c_uint) {
    (*sqe).flags = flags as u8;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_set_buf_group(sqe: *mut io_uring_sqe, bgid: c_int) {
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
#[no_mangle]
unsafe fn __io_uring_set_target_fixed_file(sqe: *mut io_uring_sqe, file_index: c_uint) {
    (*sqe).__liburing_anon_5.file_index = file_index + 1;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cqe_get_data(cqe: *const io_uring_cqe) -> *mut c_void {
    (*cqe).user_data as *mut c_void
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_wait_cqe_nr(
    ring: *mut io_uring,
    cqe_ptr: *mut *mut io_uring_cqe,
    wait_nr: c_uint,
) -> c_int {
    __io_uring_get_cqe(ring, cqe_ptr, 0, wait_nr, ptr::null_mut())
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_wait_cqe(
    ring: *mut io_uring,
    cqe_ptr: *mut *mut io_uring_cqe,
) -> c_int {
    if __io_uring_peek_cqe(ring, cqe_ptr, ptr::null_mut()) == 0 && !(*cqe_ptr).is_null() {
        return 0;
    }

    io_uring_wait_cqe_nr(ring, cqe_ptr, 1)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cq_ready(ring: *mut io_uring) -> c_uint {
    io_uring_smp_load_acquire((*ring).cq.ktail) - *(*ring).cq.khead
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cq_has_overflow(ring: *mut io_uring) -> bool {
    IO_URING_READ_ONCE((*ring).sq.kflags) & IORING_SQ_CQ_OVERFLOW > 0
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_rw(
    op: c_int,
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *const c_void,
    len: c_uint,
    offset: __u64,
) {
    (*sqe).opcode = op as u8;
    (*sqe).fd = fd;
    (*sqe).__liburing_anon_1.off = offset;
    (*sqe).__liburing_anon_2.addr = addr as u64;
    (*sqe).len = len;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_read(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    buf: *mut c_void,
    nbytes: c_uint,
    offset: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_READ as _,
        sqe,
        fd,
        buf,
        nbytes,
        offset,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_readv(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    iovecs: *const iovec,
    nr_vecs: c_uint,
    offset: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_READV as _,
        sqe,
        fd,
        iovecs.cast(),
        nr_vecs,
        offset,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_read_fixed(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    buf: *mut c_void,
    nbytes: c_uint,
    offset: u64,
    buf_index: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_READ_FIXED as _,
        sqe,
        fd,
        buf,
        nbytes,
        offset,
    );
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_read_multishot(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    nbytes: c_uint,
    offset: u64,
    buf_group: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_READ_MULTISHOT as _,
        sqe,
        fd,
        ptr::null_mut(),
        nbytes,
        offset,
    );
    (*sqe).__liburing_anon_4.buf_group = buf_group as _;
    (*sqe).flags = IOSQE_BUFFER_SELECT as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_recv(
    sqe: *mut io_uring_sqe,
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_RECV as _,
        sqe,
        sockfd,
        buf,
        len as u32,
        0,
    );
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_recv_multishot(
    sqe: *mut io_uring_sqe,
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
) {
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
    (*sqe).ioprio |= IORING_RECV_MULTISHOT as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_recvmsg(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    msg: *mut msghdr,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_RECVMSG as _,
        sqe,
        fd,
        msg.cast(),
        1,
        0,
    );
    (*sqe).__liburing_anon_3.msg_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_recvmsg_multishot(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    msg: *mut msghdr,
    flags: c_uint,
) {
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
    (*sqe).ioprio |= IORING_RECV_MULTISHOT as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_validate(
    buf: *mut c_void,
    buf_len: c_int,
    msgh: *mut msghdr,
) -> *mut io_uring_recvmsg_out {
    let header = (*msgh).msg_controllen
        + (*msgh).msg_namelen as usize
        + mem::size_of::<io_uring_recvmsg_out>();

    if buf_len < 0 || (buf_len as usize) < header {
        return ptr::null_mut();
    }

    buf.cast()
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_name(o: *mut io_uring_recvmsg_out) -> *mut c_void {
    o.add(1).cast()
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_cmsg_firsthdr(
    o: *mut io_uring_recvmsg_out,
    msgh: *mut msghdr,
) -> *mut cmsghdr {
    if ((*o).controllen as usize) < mem::size_of::<cmsghdr>() {
        return ptr::null_mut();
    }

    io_uring_recvmsg_name(o)
        .cast::<u8>()
        .add((*msgh).msg_namelen as _)
        .cast()
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_cmsg_nexthdr(
    o: *mut io_uring_recvmsg_out,
    msgh: *mut msghdr,
    cmsg: *mut cmsghdr,
) -> *mut cmsghdr {
    #[allow(non_snake_case)]
    fn CMSG_ALIGN(len: usize) -> usize {
        ((len) + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1)
    }

    if (*cmsg).cmsg_len < mem::size_of::<cmsghdr>() {
        return ptr::null_mut();
    }

    let end = io_uring_recvmsg_cmsg_firsthdr(o, msgh)
        .cast::<u8>()
        .add((*o).controllen as _);

    let cmsg = cmsg
        .cast::<u8>()
        .add(CMSG_ALIGN((*cmsg).cmsg_len))
        .cast::<cmsghdr>();

    if cmsg.add(1).cast::<u8>() > end {
        return ptr::null_mut();
    }

    if cmsg.cast::<u8>().add(CMSG_ALIGN((*cmsg).cmsg_len)) > end {
        return ptr::null_mut();
    }

    cmsg
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_payload(
    o: *mut io_uring_recvmsg_out,
    msgh: *mut msghdr,
) -> *mut c_void {
    io_uring_recvmsg_name(o)
        .cast::<u8>()
        .add((*msgh).msg_namelen as usize + (*msgh).msg_controllen)
        .cast::<c_void>()
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_recvmsg_payload_length(
    o: *mut io_uring_recvmsg_out,
    buf_len: c_int,
    msgh: *mut msghdr,
) -> c_uint {
    let payload_start = io_uring_recvmsg_payload(o, msgh) as usize;
    let payload_end = o as usize + buf_len as usize;
    (payload_end - payload_start) as _
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_writev(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    iovecs: *const iovec,
    nr_vecs: c_uint,
    offset: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_WRITEV as _,
        sqe,
        fd,
        iovecs.cast(),
        nr_vecs,
        offset,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_write_fixed(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    buf: *const c_void,
    nbytes: c_uint,
    offset: u64,
    buf_index: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_WRITE_FIXED as _,
        sqe,
        fd,
        buf,
        nbytes,
        offset,
    );
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_provide_buffers(
    sqe: *mut io_uring_sqe,
    addr: *mut c_void,
    len: c_int,
    nr: c_int,
    bgid: c_int,
    bid: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_PROVIDE_BUFFERS as _,
        sqe,
        nr,
        addr,
        len as u32,
        bid as u64,
    );
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_remove_buffers(
    sqe: *mut io_uring_sqe,
    nr: c_int,
    bgid: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_REMOVE_BUFFERS as _,
        sqe,
        nr,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_write(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    buf: *const c_void,
    nbytes: c_uint,
    offset: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_WRITE as _,
        sqe,
        fd,
        buf,
        nbytes,
        offset,
    );
}

#[inline]
unsafe fn __io_uring_prep_poll_mask(poll_mask: c_uint) -> c_uint {
    poll_mask.to_le()
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_poll_add(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    poll_mask: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_POLL_ADD as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_3.poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_poll_remove(sqe: *mut io_uring_sqe, user_data: u64) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_POLL_REMOVE as _,
        sqe,
        -1,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_2.addr = user_data;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_poll_update(
    sqe: *mut io_uring_sqe,
    old_user_data: u64,
    new_user_data: u64,
    poll_mask: c_uint,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_POLL_REMOVE as _,
        sqe,
        -1,
        ptr::null_mut(),
        flags,
        new_user_data,
    );
    (*sqe).__liburing_anon_2.addr = old_user_data;
    (*sqe).__liburing_anon_3.poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_poll_multishot(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    poll_mask: c_uint,
) {
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    (*sqe).len = IORING_POLL_ADD_MULTI;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_epoll_ctl(
    sqe: *mut io_uring_sqe,
    epfd: c_int,
    fd: c_int,
    op: c_int,
    ev: *mut epoll_event,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_EPOLL_CTL as _,
        sqe,
        epfd,
        ev.cast(),
        op as u32,
        fd as u32 as u64,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fsync(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    fsync_flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FSYNC as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_3.fsync_flags = fsync_flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_msg_ring_fd(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    source_fd: c_int,
    mut target_fd: c_int,
    data: u64,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_MSG_RING as _,
        sqe,
        fd,
        io_uring_msg_ring_flags_IORING_MSG_SEND_FD as usize as *const c_void,
        0,
        data,
    );

    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = source_fd as _;

    if target_fd == IORING_FILE_INDEX_ALLOC as _ {
        target_fd -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, target_fd as _);
    (*sqe).__liburing_anon_3.msg_ring_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_msg_ring_fd_alloc(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    source_fd: c_int,
    data: u64,
    flags: c_uint,
) {
    io_uring_prep_msg_ring_fd(sqe, fd, source_fd, IORING_FILE_INDEX_ALLOC, data, flags);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_openat(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_OPENAT as _,
        sqe,
        dfd,
        path.cast(),
        mode,
        0,
    );
    (*sqe).__liburing_anon_3.open_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_openat_direct(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
    mut file_index: c_uint,
) {
    io_uring_prep_openat(sqe, dfd, path, flags, mode);
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_openat2(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    how: *mut open_how,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_OPENAT2 as _,
        sqe,
        dfd,
        path.cast(),
        mem::size_of::<open_how>() as u32,
        how as usize as u64,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_openat2_direct(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    how: *mut open_how,
    mut file_index: c_uint,
) {
    io_uring_prep_openat2(sqe, dfd, path, how);
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_files_update(
    sqe: *mut io_uring_sqe,
    fds: *mut c_int,
    nr_fds: c_uint,
    offset: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FILES_UPDATE as _,
        sqe,
        -1,
        fds.cast(),
        nr_fds,
        offset as u64,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fallocate(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    mode: c_int,
    offset: u64,
    len: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FALLOCATE as _,
        sqe,
        fd,
        ptr::null_mut(),
        mode as c_uint,
        offset,
    );
    (*sqe).__liburing_anon_2.addr = len;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_unlinkat(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_UNLINKAT as _,
        sqe,
        dfd,
        path.cast(),
        0,
        0,
    );
    (*sqe).__liburing_anon_3.unlink_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_unlink(
    sqe: *mut io_uring_sqe,
    path: *const c_char,
    flags: c_int,
) {
    io_uring_prep_unlinkat(sqe, AT_FDCWD, path, flags);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_getxattr(
    sqe: *mut io_uring_sqe,
    name: *const c_char,
    value: *mut c_char,
    path: *const c_char,
    len: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_GETXATTR as _,
        sqe,
        0,
        name.cast(),
        len,
        value as usize as u64,
    );
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = path as usize as u64;

    (*sqe).__liburing_anon_3.xattr_flags = 0;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_setxattr(
    sqe: *mut io_uring_sqe,
    name: *const c_char,
    value: *const c_char,
    path: *const c_char,
    flags: c_int,
    len: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SETXATTR as _,
        sqe,
        0,
        name.cast(),
        len,
        value as usize as u64,
    );
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = path as usize as u64;
    (*sqe).__liburing_anon_3.xattr_flags = flags as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fgetxattr(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    name: *const c_char,
    value: *mut c_char,
    len: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FGETXATTR as _,
        sqe,
        fd,
        name.cast(),
        len,
        value as usize as u64,
    );
    (*sqe).__liburing_anon_3.xattr_flags = 0;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fsetxattr(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    name: *const c_char,
    value: *mut c_char,
    flags: c_int,
    len: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FSETXATTR as _,
        sqe,
        fd,
        name.cast(),
        len,
        value as usize as u64,
    );
    (*sqe).__liburing_anon_3.xattr_flags = flags as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_renameat(
    sqe: *mut io_uring_sqe,
    olddfd: c_int,
    oldpath: *const c_char,
    newdfd: c_int,
    newpath: *const c_char,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_RENAMEAT as _,
        sqe,
        olddfd,
        oldpath.cast(),
        newdfd as u32,
        newpath as usize as u64,
    );
    (*sqe).__liburing_anon_3.rename_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_rename(
    sqe: *mut io_uring_sqe,
    oldpath: *const c_char,
    newpath: *const c_char,
) {
    io_uring_prep_renameat(sqe, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_sync_file_range(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    len: c_uint,
    offset: u64,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SYNC_FILE_RANGE as _,
        sqe,
        fd,
        ptr::null_mut(),
        len,
        offset,
    );
    (*sqe).__liburing_anon_3.sync_range_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_statx(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    statxbuf: *mut statx,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_STATX as _,
        sqe,
        dfd,
        path.cast(),
        mask,
        statxbuf as u64,
    );
    (*sqe).__liburing_anon_3.statx_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fadvise(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    offset: u64,
    len: u32,
    advice: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FADVISE as _,
        sqe,
        fd,
        ptr::null_mut(),
        len,
        offset,
    );
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_madvise(
    sqe: *mut io_uring_sqe,
    addr: *mut c_void,
    length: u32,
    advice: c_int,
) {
    io_uring_prep_rw(io_uring_op_IORING_OP_MADVISE as _, sqe, -1, addr, length, 0);
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_nop(sqe: *mut io_uring_sqe) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_NOP as _,
        sqe,
        -1,
        ptr::null_mut(),
        0,
        0,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_fixed_fd_install(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FIXED_FD_INSTALL as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );

    (*sqe).flags = IOSQE_FIXED_FILE as _;
    (*sqe).__liburing_anon_3.install_fd_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_ftruncate(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    len: c_longlong,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FTRUNCATE as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        len as _,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_close(sqe: *mut io_uring_sqe, fd: c_int) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_CLOSE as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_close_direct(sqe: *mut io_uring_sqe, file_index: c_uint) {
    io_uring_prep_close(sqe, 0);
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_cancel(
    sqe: *mut io_uring_sqe,
    user_data: *mut c_void,
    flags: c_int,
) {
    io_uring_prep_cancel64(sqe, user_data as usize as u64, flags);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_cancel_fd(sqe: *mut io_uring_sqe, fd: c_int, flags: c_uint) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_ASYNC_CANCEL as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_3.cancel_flags = flags | IORING_ASYNC_CANCEL_FD;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_cancel64(
    sqe: *mut io_uring_sqe,
    user_data: u64,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_ASYNC_CANCEL as _,
        sqe,
        -1,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.cancel_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_link_timeout(
    sqe: *mut io_uring_sqe,
    ts: *mut __kernel_timespec,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_LINK_TIMEOUT as _,
        sqe,
        -1,
        ts.cast(),
        1,
        0,
    );
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_timeout(
    sqe: *mut io_uring_sqe,
    ts: *mut __kernel_timespec,
    count: c_uint,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_TIMEOUT as c_int,
        sqe,
        -1,
        ts.cast(),
        1,
        count as __u64,
    );
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_timeout_remove(
    sqe: *mut io_uring_sqe,
    user_data: __u64,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_TIMEOUT_REMOVE as c_int,
        sqe,
        -1,
        ptr::null_mut(),
        0,
        0,
    );
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_timeout_update(
    sqe: *mut io_uring_sqe,
    ts: *mut __kernel_timespec,
    user_data: __u64,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_TIMEOUT_REMOVE as c_int,
        sqe,
        -1,
        ptr::null_mut(),
        0,
        ts as u64,
    );
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.timeout_flags = flags | IORING_TIMEOUT_UPDATE;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_accept(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_ACCEPT as _,
        sqe,
        fd,
        addr.cast(),
        0,
        addrlen as u64,
    );
    (*sqe).__liburing_anon_3.accept_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_accept_direct(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    flags: c_int,
    mut file_index: c_uint,
) {
    io_uring_prep_accept(sqe, fd, addr, addrlen, flags);

    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_multishot_accept(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    flags: c_int,
) {
    io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
    (*sqe).ioprio |= IORING_ACCEPT_MULTISHOT as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_multishot_accept_direct(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    flags: c_int,
) {
    io_uring_prep_multishot_accept(sqe, fd, addr, addrlen, flags);
    __io_uring_set_target_fixed_file(sqe, (IORING_FILE_INDEX_ALLOC - 1) as u32);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_connect(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_CONNECT as _,
        sqe,
        fd,
        addr.cast(),
        0,
        addrlen as u64,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_socket(
    sqe: *mut io_uring_sqe,
    domain: c_int,
    r#type: c_int,
    protocol: c_int,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SOCKET as _,
        sqe,
        domain,
        ptr::null_mut(),
        protocol as u32,
        r#type as u64,
    );
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_socket_direct(
    sqe: *mut io_uring_sqe,
    domain: c_int,
    r#type: c_int,
    protocol: c_int,
    mut file_index: c_uint,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SOCKET as _,
        sqe,
        domain,
        ptr::null_mut(),
        protocol as u32,
        r#type as u64,
    );
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_socket_direct_alloc(
    sqe: *mut io_uring_sqe,
    domain: c_int,
    r#type: c_int,
    protocol: c_int,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SOCKET as _,
        sqe,
        domain,
        ptr::null_mut(),
        protocol as u32,
        r#type as u64,
    );
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
    __io_uring_set_target_fixed_file(sqe, (IORING_FILE_INDEX_ALLOC - 1) as _);
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_shutdown(sqe: *mut io_uring_sqe, fd: c_int, how: c_int) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SHUTDOWN as _,
        sqe,
        fd,
        ptr::null_mut(),
        how as u32,
        0,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_cmd_sock(
    sqe: *mut io_uring_sqe,
    cmd_op: c_int,
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_URING_CMD as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );

    *(*sqe).__liburing_anon_6.optval.as_mut() = optval as usize as _;
    (*sqe).__liburing_anon_2.__liburing_anon_1.optname = optname as _;
    (*sqe).__liburing_anon_5.optlen = optlen as _;
    (*sqe).__liburing_anon_1.__liburing_anon_1.cmd_op = cmd_op as _;
    (*sqe).__liburing_anon_2.__liburing_anon_1.level = level as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_bind(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    addr: *mut sockaddr,
    addrlen: socklen_t,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_BIND as _,
        sqe,
        fd,
        addr.cast(),
        0,
        addrlen as _,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_listen(sqe: *mut io_uring_sqe, fd: c_int, backlog: c_int) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_LISTEN as _,
        sqe,
        fd,
        ptr::null_mut(),
        backlog as _,
        0,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_send(
    sqe: *mut io_uring_sqe,
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SEND as _,
        sqe,
        sockfd,
        buf,
        len as u32,
        0,
    );
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_send_zc(
    sqe: *mut io_uring_sqe,
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    zc_flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SEND_ZC as _,
        sqe,
        sockfd,
        buf,
        len as u32,
        0,
    );
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
    (*sqe).ioprio = zc_flags as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_send_bundle(
    sqe: *mut io_uring_sqe,
    sockfd: c_int,
    len: usize,
    flags: c_int,
) {
    io_uring_prep_send(sqe, sockfd, ptr::null_mut(), len, flags);
    (*sqe).ioprio |= IORING_RECVSEND_BUNDLE as u16;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_send_set_addr(
    sqe: *mut io_uring_sqe,
    dest_addr: *const sockaddr,
    addr_len: u16,
) {
    (*sqe).__liburing_anon_1.addr2 = dest_addr as usize as u64;
    (*sqe).__liburing_anon_5.__liburing_anon_1.addr_len = addr_len;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_sendmsg(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    msg: *const msghdr,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SENDMSG as _,
        sqe,
        fd,
        msg.cast(),
        1,
        0,
    );
    (*sqe).__liburing_anon_3.msg_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_sendmsg_zc(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    msg: *const msghdr,
    flags: c_uint,
) {
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
    (*sqe).opcode = io_uring_op_IORING_OP_SENDMSG_ZC as _;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_load_sq_head(ring: *mut io_uring) -> c_uint {
    if (*ring).flags & IORING_SETUP_SQPOLL > 0 {
        return io_uring_smp_load_acquire((*ring).sq.khead);
    }

    *(*ring).sq.khead
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sq_ready(ring: *mut io_uring) -> c_uint {
    (*ring).sq.sqe_tail - io_uring_load_sq_head(ring)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sq_space_left(ring: *mut io_uring) -> c_uint {
    (*ring).sq.ring_entries - io_uring_sq_ready(ring)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_shift_from_flags(flags: c_uint) -> c_uint {
    if flags & IORING_SETUP_SQE128 > 0 {
        1
    } else {
        0
    }
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqe_shift(ring: *mut io_uring) -> c_uint {
    io_uring_sqe_shift_from_flags((*ring).flags)
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cq_eventfd_enabled(ring: *mut io_uring) -> bool {
    if (*ring).cq.kflags.is_null() {
        return true;
    }
    (*(*ring).cq.kflags & IORING_CQ_EVENTFD_DISABLED) == 0
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_cq_eventfd_toggle(ring: *mut io_uring, enabled: bool) -> c_int {
    if enabled == io_uring_cq_eventfd_enabled(ring) {
        return 0;
    }

    if (*ring).cq.kflags.is_null() {
        return -(EOPNOTSUPP as c_int);
    }

    let mut flags = *(*ring).cq.kflags;

    if enabled {
        flags &= !IORING_CQ_EVENTFD_DISABLED;
    } else {
        flags |= IORING_CQ_EVENTFD_DISABLED;
    }

    IO_URING_WRITE_ONCE((*ring).cq.kflags, flags);

    0
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_cmd_discard(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    offset: u64,
    nbytes: u64,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_URING_CMD as _,
        sqe,
        fd,
        ptr::null_mut(),
        0,
        0,
    );

    // TODO: really someday fix this
    // We need bindgen to actually evaluate this macro's value during generation.
    // No idea is hard-coding this value like this is viable in practice.
    (*sqe).__liburing_anon_1.__liburing_anon_1.cmd_op = (0x12) << 8; // BLOCK_URING_CMD_DISCARD;
    (*sqe).__liburing_anon_2.addr = offset;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = nbytes;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_linkat(
    sqe: *mut io_uring_sqe,
    olddfd: c_int,
    oldpath: *const c_char,
    newdfd: c_int,
    newpath: *const c_char,
    flags: c_int,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_LINKAT as _,
        sqe,
        olddfd,
        oldpath.cast(),
        newdfd as u32,
        newpath as usize as u64,
    );
    (*sqe).__liburing_anon_3.hardlink_flags = flags as u32;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_futex_wake(
    sqe: *mut io_uring_sqe,
    futex: *mut u32,
    val: u64,
    mask: u64,
    futex_flags: u32,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FUTEX_WAKE as _,
        sqe,
        futex_flags as _,
        futex.cast(),
        0,
        val,
    );
    (*sqe).__liburing_anon_3.futex_flags = flags;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = mask;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_waitid(
    sqe: *mut io_uring_sqe,
    idtype: idtype_t,
    id: id_t,
    infop: *mut siginfo_t,
    options: c_int,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_WAITID as _,
        sqe,
        id as _,
        ptr::null_mut(),
        idtype,
        0,
    );
    (*sqe).__liburing_anon_3.waitid_flags = flags;
    (*sqe).__liburing_anon_5.file_index = options as _;
    (*sqe).__liburing_anon_1.addr2 = infop as usize as u64;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_futex_wait(
    sqe: *mut io_uring_sqe,
    futex: *mut u32,
    val: u64,
    mask: u64,
    futex_flags: u32,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FUTEX_WAIT as _,
        sqe,
        futex_flags as _,
        futex.cast(),
        0,
        val,
    );
    (*sqe).__liburing_anon_3.futex_flags = flags;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = mask;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_futex_waitv(
    sqe: *mut io_uring_sqe,
    futex: *mut futex_waitv,
    nr_futex: u32,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_FUTEX_WAITV as _,
        sqe,
        0,
        futex.cast(),
        nr_futex,
        0,
    );
    (*sqe).__liburing_anon_3.futex_flags = flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_mkdirat(
    sqe: *mut io_uring_sqe,
    dfd: c_int,
    path: *const c_char,
    mode: mode_t,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_MKDIRAT as _,
        sqe,
        dfd,
        path.cast(),
        mode,
        0,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_msg_ring_cqe_flags(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    len: c_uint,
    data: u64,
    flags: c_uint,
    cqe_flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_MSG_RING as _,
        sqe,
        fd,
        ptr::null_mut(),
        len,
        data,
    );
    (*sqe).__liburing_anon_3.msg_ring_flags = IORING_MSG_RING_FLAGS_PASS | flags;
    (*sqe).__liburing_anon_5.file_index = cqe_flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_msg_ring(
    sqe: *mut io_uring_sqe,
    fd: c_int,
    len: c_uint,
    data: u64,
    flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_MSG_RING as _,
        sqe,
        fd,
        ptr::null_mut(),
        len,
        data,
    );
    (*sqe).__liburing_anon_3.msg_ring_flags = IORING_MSG_RING_FLAGS_PASS | flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_splice(
    sqe: *mut io_uring_sqe,
    fd_in: c_int,
    off_in: i64,
    fd_out: c_int,
    off_out: i64,
    nbytes: c_uint,
    splice_flags: c_uint,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SPLICE as _,
        sqe,
        fd_out,
        ptr::null_mut(),
        nbytes,
        off_out as u64,
    );
    (*sqe).__liburing_anon_2.splice_off_in = off_in as u64;
    (*sqe).__liburing_anon_5.splice_fd_in = fd_in;
    (*sqe).__liburing_anon_3.splice_flags = splice_flags;
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_prep_symlinkat(
    sqe: *mut io_uring_sqe,
    target: *const c_char,
    newdirfd: c_int,
    linkpath: *const c_char,
) {
    io_uring_prep_rw(
        io_uring_op_IORING_OP_SYMLINKAT as _,
        sqe,
        newdirfd,
        target.cast(),
        0,
        linkpath as usize as u64,
    );
}

#[inline]
#[no_mangle]
pub unsafe extern "C" fn io_uring_sqring_wait(ring: *mut io_uring) -> c_int {
    if (*ring).flags & IORING_SETUP_SQPOLL == 0 {
        return 0;
    }
    if io_uring_sq_space_left(ring) > 0 {
        return 0;
    }

    __io_uring_sqring_wait(ring)
}
