executable('io_uring-cp',
           'io_uring-cp.c',
           dependencies: uring)

executable('io_uring-test',
           'io_uring-test.c',
           dependencies: uring)

executable('link-cp',
           'link-cp.c',
           dependencies: uring)

if has_ucontext
    executable('ucontext-cp',
               'ucontext-cp.c',
               dependencies: uring)
endif
