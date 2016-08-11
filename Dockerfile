FROM centos:centos6

# Basic yum setup
RUN yum -y update; yum clean all
RUN yum -y install epel-release; yum clean all

# Requirements for compiling python
RUN yum groupinstall -y "Development tools"
RUN yum install -y zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel

# build and install python
RUN cd /tmp \
    && curl -O https://www.python.org/ftp/python/3.5.2/Python-3.5.2.tar.xz \
    && tar xf Python-3.5.2.tar.xz && cd Python-3.5.2 \
    &&./configure --prefix=/usr/local  \
    && make \
    && make altinstall && cd /tmp \
    && rm -f Python-3.5.2.tar.xz \
    && rm -rf Python-3.5.2/

# Install openssh-server
RUN yum -y install openssh-server; yum clean all
# generate host certs
RUN service sshd start; service sshd stop
# set the worst possilble password
RUN echo "root:root" | chpasswd

# Needed to test aid-iptables integration
RUN yum -y install iptables; yum clean all

# Install pytest
RUN pip3.5 install pytest

EXPOSE 22
CMD pip3.5 install -e /aid[iptables] && /usr/sbin/sshd -D
