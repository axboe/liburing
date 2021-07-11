executable('io_uring-cp',
           'io_uring-cp.c',
           include_directories : inc,
           link_with : liburing)

executable('io_uring-test',
           'io_uring-test.c',
           include_directories : inc,
           link_with : liburing)

executable('link-cp',
           'link-cp.c',
           include_directories : inc,
           link_with : liburing)

if has_ucontext
    executable('ucontext-cp',
               'ucontext-cp.c',
               include_directories : inc,
               link_with : liburing)
endif
