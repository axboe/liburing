Name: liburing
Version: 0.1
Release: 1
Summary: Linux-native io_uring I/O access library
License: LGPL
Group:  System Environment/Libraries
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root

%description
Provides native async IO for the Linux kernel, in a fast and efficient
manner, for both buffered and O_DIRECT.

%package devel
Summary: Development files for Linux-native io_uring I/O access library
Group: Development/System
Requires: liburing
Provides: liburing.so.1

%description devel
This package provides header files to include and libraries to link with
for the Linux-native io_uring.

%prep
%setup

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT prefix=/usr libdir=/%{_libdir}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/liburing.so.*
%doc COPYING TODO

%files devel
%defattr(-,root,root)
%attr(0644,root,root) %{_includedir}/*
%attr(0755,root,root) %{_libdir}/liburing.so
%attr(0644,root,root) %{_libdir}/liburing.a

%changelog
* Tue Jan 8 2019 Jens Axboe <axboe@kernel.dk> - 0.1
- Initial version
