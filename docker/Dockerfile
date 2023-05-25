# Dockerfile for w744219971/driver-did-pdc

FROM maven:3-jdk-11 AS builder
MAINTAINER Qiangqiang Wang <744219971@qq.com>


ADD . /opt/driver-did-pdc

RUN cd /opt/driver-did-pdc && mvn clean install package -N -DskipTests

# done

EXPOSE 8080

RUN chmod a+rx /opt/driver-did-pdc/docker/run-driver-did-pdc.sh
CMD "/opt/driver-did-pdc/docker/run-driver-did-pdc.sh"