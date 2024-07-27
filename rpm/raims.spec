Name:		raims
Version:	999.999
Vendor:	        Rai Technology, Inc
Release:	99999%{?dist}
Summary:	Cache backed pubsub

License:	ASL 2.0
URL:		https://github.com/raitechnology/%{name}
Source0:	%{name}-%{version}-99999.tar.gz
BuildRoot:	${_tmppath}
Prefix:	        /usr
BuildRequires:  gcc-c++
BuildRequires:  chrpath
BuildRequires:  raikv
BuildRequires:  raimd
BuildRequires:  openpgm_st
BuildRequires:  raids
BuildRequires:  natsmd
BuildRequires:  sassrv
BuildRequires:  h3lib
BuildRequires:  rdbparser
BuildRequires:  linecook
BuildRequires:  libdecnumber
BuildRequires:  pcre2-devel
BuildRequires:  liblzf-devel
BuildRequires:  git-core
BuildRequires:  c-ares-devel
BuildRequires:  openssl-devel
BuildRequires:  zlib-devel
Requires:       pcre2
Requires:       liblzf
Requires:       c-ares
Requires:       openssl
Requires:       h3lib
Requires:       hdrhist
Requires:       libdecnumber
Requires:       linecook
Requires:       natsmd
Requires:       openpgm_st
Requires:       raids
Requires:       raikv
Requires:       raimd
Requires:       rdbparser
Requires:       sassrv
Requires:       zlib
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Rai Multicast Services for Pub Sub

%prep
%setup -q


%define _unpackaged_files_terminate_build 0
%define _missing_doc_files_terminate_build 0
%define _missing_build_ids_terminate_build 0
%define _include_gdb_index 1

%build
make build_dir=./usr %{?_smp_mflags} dist_bins
cp -a ./include ./usr/include

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}

# in builddir
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/*
/usr/lib64/*
/usr/include/*

%post
echo "${RPM_INSTALL_PREFIX}/lib64" > /etc/ld.so.conf.d/%{name}.conf
/sbin/ldconfig

%postun
if [ $1 -eq 0 ] ; then
rm -f /etc/ld.so.conf.d/%{name}.conf
fi
/sbin/ldconfig

%changelog
* Sat Jan 01 2000 <support@raitechnology.com>
- Hello world
