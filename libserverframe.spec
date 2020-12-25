%define LibserverframeDevel libserverframe-devel
%define CommitVersion %(echo $COMMIT_VERSION)

Name: libserverframe
Version: 1.1.1
Release: 1%{?dist}
Summary: mc common framework library
License: GPL
Group: Arch/Tech
URL:  http://github.com/happyfish100/libfastcommon/
Source: http://github.com/happyfish100/libfastcommon/%{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n) 

BuildRequires: libfastcommon-devel >= 1.0.45
Requires: %__cp %__mv %__chmod %__grep %__mkdir %__install %__id
Requires: libfastcommon >= 1.0.45
%description
common framework library 
commit version: %{CommitVersion}

%package devel
Summary: Development header file
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package provides the header files of libserverframe
commit version: %{CommitVersion}


%prep
%setup -q

%build
./make.sh

%install
rm -rf %{buildroot}
DESTDIR=$RPM_BUILD_ROOT ./make.sh install

%post

%preun

%postun

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/lib64/libserverframe.so*

%files devel
%defattr(-,root,root,-)
/usr/include/sf/*

%changelog
* Mon Jun 23 2014  Zaixue Liao <liaozaixue@yongche.com>
- first RPM release (1.0)
