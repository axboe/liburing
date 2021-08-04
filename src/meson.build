subdir('include')

inc = include_directories(['include'])

liburing = library('uring',
                   'queue.c',
                   'register.c',
                   'setup.c',
                   'syscall.c',
                   include_directories: inc,
                   c_args: ['-DLIBURING_INTERNAL', '-fno-stack-protector'],
                   link_args: '-Wl,--version-script=' + meson.current_source_dir() + '/liburing.map',
                   link_depends: 'liburing.map',
                   version: meson.project_version(),
                   install: true)

uring = declare_dependency(link_with: liburing,
                           include_directories: inc)
