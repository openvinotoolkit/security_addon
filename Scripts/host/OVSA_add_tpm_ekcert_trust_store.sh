#!/bin/bash
#
# Copyright (c) 2020-2022 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#set -e

echo
echo "Adding TPM RootCA certificates to Trust store"
echo

echo "Adding Intel EKRootPublicKey RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/EKRootPublicKey.cer ]
then
    echo "Intel EKRootPublicKey.cer RootCA certificate already exits in Trust store"
else
    echo "Downloading EKRootPublicKey.cer in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://upgrades.intel.com/content/CRL/ekcert/EKRootPublicKey.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/EKRootPublicKey.cer -out /usr/local/share/ca-certificates/EKRootPublicKey.crt
fi

echo "*******************************************************************"

echo "Adding Intel Ondie-RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OnDie_CA_RootCA_Certificate.cer ]
then
    echo "Intel OnDie_CA_RootCA_Certificate.cer already exits in Trust store"
else
    echo "Downloading OnDie_CA_RootCA_Certificate.crt in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e https_proxy=$https_proxy -P /usr/local/share/ca-certificates/ https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OnDie_CA_RootCA_Certificate.cer -out /usr/local/share/ca-certificates/OnDie_CA_RootCA_Certificate.crt
fi

echo "*******************************************************************"

echo "Adding NationZ EkRootCA.crt RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/EkRootCA.crt ]
then
    echo "NationZ EkRootCA.crt already exits in Trust store"
else
    echo "Downloading EkRootCA.crt in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.nationz.com.cn/EkRootCA/EkRootCA.crt
fi

echo "*******************************************************************"

echo "Adding Infineon 'Infineon OPTIGA(TM) ECC Root CA.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaEccRootCA.crt ]
then
    echo "Infineon 'Infineon OPTIGA(TM) ECC Root CA.crt' already exits in Trust store"
else
    echo "Downloading 'Infineon OPTIGA(TM) ECC Root CA.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaEccRootCA/OptigaEccRootCA.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaEccRootCA.crt -out /usr/local/share/ca-certificates/OptigaEccRootCA.crt
fi

echo "*******************************************************************"

echo "Adding Infineon 'Infineon_OPTIGA(TM)_ECC_Root_CA_2.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaEccRootCA2.crt ]
then
    echo "Infineon 'Infineon_OPTIGA(TM)_ECC_Root_CA_2.crt' already exits in Trust store"
else
    echo "Downloading 'Infineon_OPTIGA(TM)_ECC_Root_CA_2.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaEccRootCA2/OptigaEccRootCA2.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaEccRootCA2.crt -out /usr/local/share/ca-certificates/OptigaEccRootCA2.crt
fi

echo "*******************************************************************"

echo "Adding Infineon 'Infineon OPTIGA(TM) RSA Root CA.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaRsaRootCA.crt ]
then
    echo "Infineon 'Infineon OPTIGA(TM) RSA Root CA.crt' already exits in Trust store"
else
    echo "Downloading 'Infineon OPTIGA(TM) RSA Root CA.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaRsaRootCA/OptigaRsaRootCA.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaRsaRootCA.crt -out /usr/local/share/ca-certificates/OptigaRsaRootCA.crt
fi

echo "*******************************************************************"

echo "Adding Infineon 'Infineon_OPTIGA(TM)_RSA_Root_CA_2.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaRsaRootCA2.crt ]
then
    echo "Infineon 'Infineon_OPTIGA(TM)_RSA_Root_CA_2.crt' already exits in Trust store"
else
    echo "Downloading 'Infineon_OPTIGA(TM)_RSA_Root_CA_2.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaRsaRootCA2/OptigaRsaRootCA2.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaRsaRootCA2.crt -out /usr/local/share/ca-certificates/OptigaRsaRootCA2.crt
fi

echo "********************************************************************"

echo "Adding Infineon 'OptigaEccRootCA3.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaEccRootCA3.crt ]
then
    echo "Infineon 'OptigaEccRootCA3.crt' already exits in Trust store"
else
    echo "Downloading 'OptigaEccRootCA3.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaEccRootCA3/OptigaEccRootCA3.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaEccRootCA3.crt -out /usr/local/share/ca-certificates/OptigaEccRootCA3.crt
fi

echo "*******************************************************************"

echo "Adding Infineon 'OptigaRsaRootCA3.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/OptigaRsaRootCA3.crt ]
then
    echo "Infineon 'OptigaRsaRootCA3.crt' already exits in Trust store"
else
    echo "Downloading 'OptigaRsaRootCA3.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy -P /usr/local/share/ca-certificates/ http://pki.infineon.com/OptigaRsaRootCA3/OptigaRsaRootCA3.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/OptigaRsaRootCA3.crt -out /usr/local/share/ca-certificates/OptigaRsaRootCA3.crt
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 2111.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2111.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2111.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2111.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ http://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202111.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2111.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2111.crt'
fi

echo "*******************************************************************"


echo "Adding Nuvoton 'Nuvoton TPM Root CA 2112.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2112.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2112.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2112.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$http_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ http://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202112.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2112.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2112.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 2110.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2110.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2110.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2110.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202110.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2110.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2110.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 2012.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2012.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2012.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2012.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202012.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2012.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2012.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 2011.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2011.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2011.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2011.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202011.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2011.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2011.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 2010.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2010.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 2010.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 2010.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202010.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2010.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 2010.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 1111.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1111.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 1111.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 1111.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201111.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1111.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1111.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 1110.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1110.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 1110.cer' already exits in Trust store"
else
    echo "Downloading '-Nuvoton TPM Root CA 1110.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy  --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1110.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1110.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 1014.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1014.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 1014.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 1014.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201014.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1014.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1014.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'Nuvoton TPM Root CA 1013.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1013.cer' ]
then
    echo "Nuvoton 'Nuvoton TPM Root CA 1013.cer' already exits in Trust store"
else
    echo "Downloading 'Nuvoton TPM Root CA 1013.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201013.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1013.cer' -out /usr/local/share/ca-certificates/'Nuvoton TPM Root CA 1013.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'NTC TPM EK Root CA 02.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'NTC TPM EK Root CA 02.cer' ]
then
    echo "Nuvoton 'NTC TPM EK Root CA 02.cer' already exits in Trust store"
else
    echo "Downloading 'NTC TPM EK Root CA 02.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2002.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'NTC TPM EK Root CA 02.cer' -out /usr/local/share/ca-certificates/'NTC TPM EK Root CA 02.crt'
fi

echo "*******************************************************************"

echo "Adding Nuvoton 'NTC TPM EK Root CA 01.cer' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/'NTC TPM EK Root CA 01.cer' ]
then
    echo "Nuvoton 'NTC TPM EK Root CA 01.cer' already exits in Trust store"
else
    echo "Downloading 'NTC TPM EK Root CA 01.cer' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy --no-check-certificate -P /usr/local/share/ca-certificates/ https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2001.cer
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/'NTC TPM EK Root CA 01.cer' -out /usr/local/share/ca-certificates/'NTC TPM EK Root CA 01.crt'
fi

echo "*******************************************************************"

echo "Adding STMicro 'GlobalSign Trusted Computing CA.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/gstpmroot.crt ]
then
    echo "STMicro 'GlobalSign Trusted Computing CA.crt' already exits in Trust store"
else
    echo "Downloading 'GlobalSign Trusted Computing CA.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy -P /usr/local/share/ca-certificates/ https://secure.globalsign.com/cacert/gstpmroot.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/gstpmroot.crt -out /usr/local/share/ca-certificates/gstpmroot.crt
fi

echo "*******************************************************************"

echo "Adding STMicro 'GlobalSign Trusted Platform Module ECC Root CA.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/tpmeccroot.crt ]
then
    echo "STMicro 'GlobalSign Trusted Platform Module ECC Root CA.crt' already exits in Trust store"
else
    echo "Downloading 'GlobalSign Trusted Platform Module ECC Root CA.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy -P /usr/local/share/ca-certificates/ https://secure.globalsign.com/cacert/tpmeccroot.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/tpmeccroot.crt -out /usr/local/share/ca-certificates/tpmeccroot.crt
fi

echo "*******************************************************************"

echo "Adding STMicro 'ST TPM Root Certificate.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/stmtpmekroot.crt ]
then
    echo "STMicro 'ST TPM Root Certificate.crt' already exits in Trust store"
else
    echo "Downloading 'ST TPM Root Certificate.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy -P /usr/local/share/ca-certificates/ https://secure.globalsign.com/cacert/stmtpmekroot.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/stmtpmekroot.crt -out /usr/local/share/ca-certificates/stmtpmekroot.crt
fi

echo "*******************************************************************"

echo "Adding STMicro 'STM TPM ECC Root CA 01.crt' RootCA certificate to Trust store"
if [ -e /usr/local/share/ca-certificates/stmtpmeccroot01.crt ]
then
    echo "STMicro 'STM TPM ECC Root CA 01.crt' already exits in Trust store"
else
    echo "Downloading 'STM TPM ECC Root CA 01.crt' in /usr/local/share/ca-certificates"
    wget -e use_proxy=yes -e http_proxy=$https_proxy -P /usr/local/share/ca-certificates/ https://secure.globalsign.com/cacert/stmtpmeccroot01.crt
    echo "Converting DER format to PEM format"
    openssl x509 -inform der -in /usr/local/share/ca-certificates/stmtpmeccroot01.crt -out /usr/local/share/ca-certificates/stmtpmeccroot01.crt
fi

echo "*******************************************************************"
echo "Update CA certificates to Trust Store"
update-ca-certificates
