#!/usr/bin/env bash

set -e

#mvn clean package

mvn -Dtest=TestAD \
  -Dtest.ad.host="ad2019.lab.evolveum.com" \
  -Dtest.ad.port=636 \
  -Dtest.ad.connectionSecurity="ssl" \
  -Dtest.ad.baseContext="CN=Users,DC=ad2019,DC=lab,DC=evolveum,DC=com" \
  -Dtest.ad.bindDn="CN=MidPoint,CN=Users,DC=ad2019,DC=lab,DC=evolveum,DC=com" \
  -Dtest.ad.bindPassword="qwe.123" test

