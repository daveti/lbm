-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Format: 1.0
Source: linux-hwe
Binary: linux-source-4.13.0, linux-headers-4.13.0-37, linux-hwe-tools-4.13.0-37, linux-hwe-cloud-tools-4.13.0-37, linux-image-4.13.0-37-generic, linux-image-extra-4.13.0-37-generic, linux-headers-4.13.0-37-generic, linux-image-4.13.0-37-generic-dbgsym, linux-tools-4.13.0-37-generic, linux-cloud-tools-4.13.0-37-generic, linux-hwe-udebs-generic, linux-image-4.13.0-37-generic-lpae, linux-image-extra-4.13.0-37-generic-lpae, linux-headers-4.13.0-37-generic-lpae, linux-image-4.13.0-37-generic-lpae-dbgsym, linux-tools-4.13.0-37-generic-lpae, linux-cloud-tools-4.13.0-37-generic-lpae, linux-hwe-udebs-generic-lpae, linux-image-4.13.0-37-lowlatency, linux-image-extra-4.13.0-37-lowlatency, linux-headers-4.13.0-37-lowlatency, linux-image-4.13.0-37-lowlatency-dbgsym, linux-tools-4.13.0-37-lowlatency, linux-cloud-tools-4.13.0-37-lowlatency, linux-hwe-udebs-lowlatency
Architecture: all i386 amd64 armhf arm64 ppc64el s390x
Version: 4.13.0-37.42~16.04.1
Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>
Standards-Version: 3.9.4.0
Vcs-Git: git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/xenial -b hwe
Testsuite: autopkgtest
Build-Depends: debhelper (>= 9), dh-systemd, cpio, kernel-wedge, kmod <!stage1>, makedumpfile [amd64 i386] <!stage1>, libelf-dev <!stage1>, libnewt-dev <!stage1>, libiberty-dev <!stage1>, rsync <!stage1>, libdw-dev <!stage1>, libpci-dev <!stage1>, pkg-config <!stage1>, flex <!stage1>, bison <!stage1>, libunwind8-dev [amd64 arm64 armhf i386 ppc64el] <!stage1>, liblzma-dev <!stage1>, openssl <!stage1>, libssl-dev <!stage1>, libaudit-dev <!stage1>, bc <!stage1>, python-dev <!stage1>, gawk <!stage1>, libudev-dev <!stage1>, autoconf <!stage1>, automake <!stage1>, libtool <!stage1>, uuid-dev <!stage1>, binutils-dev <!stage1>, libnuma-dev [amd64 arm64 i386 ppc64el] <!stage1>
Build-Depends-Indep: xmlto <!stage1>, docbook-utils <!stage1>, ghostscript <!stage1>, transfig <!stage1>, bzip2 <!stage1>, sharutils <!stage1>, asciidoc <!stage1>, python-sphinx <!stage1>, python-sphinx-rtd-theme <!stage1>
Package-List:
 linux-cloud-tools-4.13.0-37-generic deb devel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-cloud-tools-4.13.0-37-generic-lpae deb devel optional arch=armhf profile=!stage1
 linux-cloud-tools-4.13.0-37-lowlatency deb devel optional arch=i386,amd64 profile=!stage1
 linux-headers-4.13.0-37 deb devel optional arch=all profile=!stage1
 linux-headers-4.13.0-37-generic deb devel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-headers-4.13.0-37-generic-lpae deb devel optional arch=armhf profile=!stage1
 linux-headers-4.13.0-37-lowlatency deb devel optional arch=i386,amd64 profile=!stage1
 linux-hwe-cloud-tools-4.13.0-37 deb devel optional arch=i386,amd64,armhf profile=!stage1
 linux-hwe-tools-4.13.0-37 deb devel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-hwe-udebs-generic udeb debian-installer optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-hwe-udebs-generic-lpae udeb debian-installer optional arch=armhf profile=!stage1
 linux-hwe-udebs-lowlatency udeb debian-installer optional arch=i386,amd64 profile=!stage1
 linux-image-4.13.0-37-generic deb kernel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-image-4.13.0-37-generic-dbgsym deb devel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-image-4.13.0-37-generic-lpae deb kernel optional arch=armhf profile=!stage1
 linux-image-4.13.0-37-generic-lpae-dbgsym deb devel optional arch=armhf profile=!stage1
 linux-image-4.13.0-37-lowlatency deb kernel optional arch=i386,amd64 profile=!stage1
 linux-image-4.13.0-37-lowlatency-dbgsym deb devel optional arch=i386,amd64 profile=!stage1
 linux-image-extra-4.13.0-37-generic deb kernel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-image-extra-4.13.0-37-generic-lpae deb kernel optional arch=armhf profile=!stage1
 linux-image-extra-4.13.0-37-lowlatency deb kernel optional arch=i386,amd64 profile=!stage1
 linux-source-4.13.0 deb devel optional arch=all profile=!stage1
 linux-tools-4.13.0-37-generic deb devel optional arch=i386,amd64,armhf,arm64,ppc64el,s390x profile=!stage1
 linux-tools-4.13.0-37-generic-lpae deb devel optional arch=armhf profile=!stage1
 linux-tools-4.13.0-37-lowlatency deb devel optional arch=i386,amd64 profile=!stage1
Checksums-Sha1:
 7e8de824d7aa8d79a5f041b719604a41862f3823 155489655 linux-hwe_4.13.0.orig.tar.gz
 465c9adab0824a2fcb57c9d592bf21e7d0ee52ec 8837829 linux-hwe_4.13.0-37.42~16.04.1.diff.gz
Checksums-Sha256:
 9511260e17e474183b9c3b2ea601d5af256dde783e14dba4031854eaa98d5089 155489655 linux-hwe_4.13.0.orig.tar.gz
 f736a1d82ff78e59d2e7eb997fe03e48932685059c7b77655d12e6efaa1685d4 8837829 linux-hwe_4.13.0-37.42~16.04.1.diff.gz
Files:
 7e0393558784f7494a50c5219eac14f1 155489655 linux-hwe_4.13.0.orig.tar.gz
 fd8615bc30e5456538b8e66bce43ea9a 8837829 linux-hwe_4.13.0-37.42~16.04.1.diff.gz

-----BEGIN PGP SIGNATURE-----

iQE4BAEBCAAiBQJaoAweGxxrbGViZXIuc291emFAY2Fub25pY2FsLmNvbQAKCRBG
qvM1cOEWK/CxB/49396H8hpadL2i3+b9KmsrlSwsZHj2sSpuJVklxJL2RK/5YM5k
w/5JGFnC6cx8fKCi9ETKiZ1925YzwQL5uizP343rYh6147TZ7g/XofLer+g4z1gn
5+dodlUc+pK6oR4t7ZFSUau1jARch/tFEeC6A7LNZTjkYonuQmyhOqReJz/XSjwo
5ZM4k4Q3m440S8QRUVjMbQlyiDQ8XsZYgG1oqMAJO/7bUH0fQ4rYJzP8Yy3wvvbp
IfnV68bQlj1jGlN8PebZeRfMVjssDdwcZK+dYTBk9T7ITzohz3//crQRns+BZfff
R5+ZXuYI5tTC14he/4NbAS9P7oUHvnlDUgBI
=Ip8l
-----END PGP SIGNATURE-----
