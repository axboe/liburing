example_sources = [
  'io_uring-cp.c',
  'io_uring-test.c',
  'io_uring-udp.c',
  'link-cp.c',
  'poll-bench.c',
  'send-zerocopy.c',
]

if has_ucontext
  example_sources += ['ucontext-cp.c']
endif

foreach source: example_sources
    name = source.split('.')[0]
    executable(name,
               source,
               dependencies: uring)
endforeach
