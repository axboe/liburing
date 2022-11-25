subdir('include')

liburing_includes = include_directories(['include'])
liburing_internal_includes = [liburing_includes]

liburing_sources = ['queue.c', 'register.c', 'setup.c']
liburing_c_args = ['-DLIBURING_INTERNAL', '-fno-stack-protector']
liburing_link_args = ['-Wl,--version-script=' + meson.current_source_dir() + '/liburing.map']

if nolibc
  liburing_internal_includes += include_directories(['arch'])

  liburing_sources += ['nolibc.c']
  liburing_c_args += ['-nostdlib', '-nodefaultlibs', '-ffreestanding']
  liburing_link_args += ['-nostdlib', '-nodefaultlibs']
endif

liburing = library('uring',
                   liburing_sources,
                   include_directories: liburing_internal_includes,
                   c_args: liburing_c_args,
                   link_args: liburing_link_args,
                   link_depends: 'liburing.map',
                   version: meson.project_version(),
                   install: true)

uring = declare_dependency(link_with: liburing,
                           include_directories: liburing_includes)
