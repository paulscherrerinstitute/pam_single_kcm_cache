%global _hardened_build 1
%global upstream_name pam_single_kcm_cache

Name:           pam_single_kcm_cache
Version:        0.0.2
Release:        1%{?dist}
Summary:        This PAM module enforces the use of a single KCM Kerberos credential cache by creating and populating a custom or random cache and sets as default cache for the new user session by setting the KRB5CCNAME environment variable accordingly.

Group:          Applications/System
License:        GPLv2+
URL:            https://github.com/paulscherrerinstitute/pam_single_kcm_cache
Source0:        https://github.com/paulscherrerinstitute/pam_single_kcm_cache/releases/download/v%{version}/pam_single_kcm_cache-%{version}.tar.gz

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  krb5-devel
BuildRequires:  pam-devel
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool

%description
pam_script allows you to execute scripts during authorization, password
changes and session openings or closings.

%prep
%setup -q

#generate our configure script
autoreconf -vfi

%build
%configure --libdir=/%{_lib}/security
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%doc AUTHORS COPYING ChangeLog README.md
/%{_lib}/security/*
%{_mandir}/man7/%{upstream_name}.7*

%changelog
* Fri Mar 14 2025 Konrad Bucheli <konrad.bucheli@psi.ch> - 0.0.2-1
- Release v0.0.2
- do not filter older TGTs
- use krb5_c_random_make_octets() instead of rand()

* Wed Nov 9 2022 Konrad Bucheli <konrad.bucheli@psi.ch> - 0.0.1-3
- Initial Release v0.0.1

* Wed Oct 19 2022 Konrad Bucheli <konrad.bucheli@psi.ch> - 0.0.1-1
- Initial Build
