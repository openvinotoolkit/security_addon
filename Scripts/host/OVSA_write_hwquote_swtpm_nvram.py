#
# Copyright (c) 2020-2021 Intel Corporation
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

import json, subprocess, sys, os

NVM_SIZE_LEN=8
FIRST_CHUNK_SIZE=2040
CHUNK_SIZE=2048

config_str = '{{ "HW_Quote_MSG": "{quote_msg}",  "HW_Quote_SIG": "{quote_sig}", "HW_Quote_PCR": "{quote_pcr}", "HW_AK_Pub_Key": "{tpm_ak}", "HW_EK_Pub_Key": "{tpm_ek}", "HW_EK_Cert": "{tpm_cert}" }}'

def runcommand(cmd):
    x=subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rc = x.returncode
    stdout = x.stdout.decode('utf-8')
    stderr = x.stderr.decode('utf-8')
    return rc, stdout, stderr

def check_result(return_val,user_mesg):
    if(return_val[0]>0):
        print("\tERROR: "+ user_mesg)
        if(return_val[1]):
            print("\tstdout=" + return_val[1])
        print("\tstderr=" + return_val[2])
        exit()

def generate_AK_EK_keys():
    print("Generating EK & AK Keys")
    return_val = runcommand('tpm2_flushcontext -s')
    check_result(return_val,"Flushing tpm2 context")
    return_val  = runcommand('tpm2_createek --ek-context tpm_ek.ctx --key-algorithm rsa --public tpm_ek.pub')
    check_result(return_val,'Generating EK context')
    return_val  = runcommand('tpm2_createak --ek-context tpm_ek.ctx --ak-context tpm_ak.ctx --key-algorithm rsa --hash-algorithm sha256 --signing-algorithm rsassa --public tpm_ak.pub --private tpm_ak.priv --ak-name tpm_ak.name')
    check_result(return_val,'Generating AK context')
    return_val  = runcommand('tpm2_startauthsession --session tmp_session_ctx --policy-session')
    check_result(return_val,"Authenticating session context")
    return_val  = runcommand('tpm2_policysecret --session tmp_session_ctx --object-context e')
    check_result(return_val,'Generating policy secret')
    return_val  = runcommand('tpm2_readpublic -c tpm_ak.ctx -o tpm_ak.pub.pem -f pem')
    check_result(return_val,'Reading EK Keys in PEM Format')
    return_val  = runcommand('tpm2_readpublic -c tpm_ek.ctx -o tpm_ek.pub.pem -f pem')
    check_result(return_val,'Reading AK Keys in PEM Format')
    return_val  = runcommand('tpm2_load --parent-context tpm_ek.ctx --public tpm_ak.pub --private tpm_ak.priv --key-context tpm_ak.ctx --auth session:tmp_session_ctx')
    check_result(return_val,'Loading tpm2 context')
    print("Successfully generated AK EK keys...")
    
# READ EK Cert
# Location 1 - TPM2 NV Index 0x1c00002 is the TCG specified location for RSA-EK-certificate.
def read_SWEK_cert(port):
    print("Read SW EK Certificate from NVRAM")
    RSA_EK_CERT_NV_INDEX="0x01C00002"
    cmd="tpm2_nvreadpublic " + RSA_EK_CERT_NV_INDEX + " -T swtpm:port=" + port + " | grep size | awk '{print $2}'"
    return_val  = runcommand(cmd)
    NV_SIZE = return_val[1]
    check_result(return_val, "EK Certificate not provisioned")
    print("Read EK Certificate size from TPM2")
    if(NV_SIZE):
        cmd="tpm2_nvread --hierarchy owner --output tpm_sw_ek_cert.bin " + RSA_EK_CERT_NV_INDEX + " -T swtpm:port=" + port + " --size " + str(NV_SIZE)
        return_val = runcommand(cmd)
        check_result(return_val, 'Reading EK Certificate size from TPM2')
    else:
        print("\t NV size read is zero. Please check if EK Certificate not provisioned/use correct port number")
        exit()
    cmd="openssl x509 -inform der -in tpm_sw_ek_cert.bin -out tpm_sw_ek_cert.pem"
    return_val  = runcommand(cmd)
    check_result(return_val, 'Reading EK certificate in PEM Format')
    print("Successfully read SW EK Certificate...")

def read_HWEK_cert():
    print("Read HW EK Certificate from NVRAM")
    RSA_EK_CERT_NV_INDEX="0x01C00002"
    cmd="tpm2_nvreadpublic " + RSA_EK_CERT_NV_INDEX + " | grep size | awk '{print $2}'"
    return_val  = runcommand(cmd)
    NV_SIZE = return_val[1]
    check_result(return_val, "EK Certificate not provisioned")
    print("Read EK Certificate size from TPM2")
    if(NV_SIZE == 0):
        cmd="tpm2 getekcertificate -u tpm_ek.pub -x -X -o tpm_hw_ek_cert.bin"
        return_val = runcommand(cmd)
        check_result(return_val,'Reading EK Certificate size from TPM2')
    else:
        cmd="tpm2_nvread --hierarchy owner --output tpm_hw_ek_cert.bin " + RSA_EK_CERT_NV_INDEX + " --size " + str(NV_SIZE)
        return_val = runcommand(cmd)
        check_result(return_val,'Reading EK Certificate size from TPM2')
    cmd="openssl x509 -inform der -in tpm_hw_ek_cert.bin -out tpm_hw_ek_cert.pem"
    return_val  = runcommand(cmd)
    check_result(return_val, 'Reading EK certificate in PEM Format')
    print("Successfully read HW EK Certificate...")
    
def generate_HW_quote():
    print("Generate HW quote")
    cmd="openssl dgst -sha256 tpm_sw_ek_cert.pem | grep tpm_sw_ek_cert | awk '{print $2}'"
    return_val = runcommand(cmd)
    cert_hash=return_val[1]
    if cert_hash:
        return_val  = runcommand("tpm2_quote --key-context tpm_ak.ctx --pcr-list sha256:all --message tmp_quote_msg --signature tmp_quote_sig --hash-algorithm sha256 --pcr tmp_quote_pcr --qualification " + str(cert_hash))
        check_result(return_val,'Generating HW quote')
        print("Successfully generated quotes...")
    else:
        print("\t Hash value is zero. Please check SW EK certificate PEM file")
        exit()

def construct_json_blob():
    print('Generate Json blob')
    fd = open('tpm_ak.pub.pem', 'r')
    ak_pubpem = fd.read()
    ak_pub_pem = ak_pubpem.replace("\n", "\\n")
    fd.close()
    fd = open('tpm_ek.pub.pem', 'r')
    ek_pubpem = fd.read()
    ek_pub_pem = ek_pubpem.replace("\n", "\\n")
    fd.close()
    fd = open('tpm_hw_ek_cert.pem', 'r')
    ek_certpem = fd.read()
    ek_cert_pem = ek_certpem.replace("\n", "\\n")
    fd.close()
    return_val  = runcommand('openssl enc -in tmp_quote_msg -out tmp_quote_msg.pem -a')
    check_result(return_val, 'Reading tpm quote message in PEM Format')
    return_val  = runcommand('openssl enc -in tmp_quote_sig -out tmp_quote_sig.pem -a')
    check_result(return_val, 'Reading tpm quote signature in PEM Format')
    return_val  = runcommand('openssl enc -in tmp_quote_pcr -out tmp_quote_pcr.pem -a')
    check_result(return_val, 'Reading tpm quote pcr in PEM Format')
    fd = open('tmp_quote_msg.pem', 'r')
    tmp_qmsg = fd.read()
    tmp_quote_msg = tmp_qmsg.replace("\n", "\\n")
    fd.close()
    fd = open('tmp_quote_sig.pem', 'r')
    tmp_qsig = fd.read()
    tmp_quote_sig = tmp_qsig.replace("\n", "\\n")
    fd.close()
    fd = open('tmp_quote_pcr.pem', 'r')
    tmp_qpcr = fd.read()
    tmp_quote_pcr = tmp_qpcr.replace("\n", "\\n")
    fd.close()
    json_strg = config_str.format(quote_msg=tmp_quote_msg,quote_sig=tmp_quote_sig,quote_pcr=tmp_quote_pcr,tpm_ak=ak_pub_pem,tpm_ek=ek_pub_pem,tpm_cert=ek_cert_pem)
    tpm_json = json.loads(json_strg)
    with open("tpm_data.json", "w") as fp:
        fp.write(json.dumps(tpm_json,indent = 4))
        fp.close()
    print("Successfully generated json blob...")

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def convert_to_8byte(value):
    str_v=str(value)
    return ("0" * (8-len(str_v))) + str_v

def write_into_nvram(swtmpport):
    print('Writting json to NVRAM')
    size=os.path.getsize("tpm_data.json")
    lsize=convert_to_8byte(size)
    print("Total size to write:"+lsize)
    fd = open("chunk_len.txt", "w")
    fd.write(str(lsize))
    fd.close()
    NV_index_count=size//FIRST_CHUNK_SIZE
    with open("tpm_data.json", 'r') as fd:
        data = fd.read(FIRST_CHUNK_SIZE)
        fd.seek(0)
        with open("chunk_0.txt", "w") as fp:
            fp.write(data)
            fp.close()
        data = fd.read(FIRST_CHUNK_SIZE)
        fd.seek(FIRST_CHUNK_SIZE)
        data = fd.read()
        with open("chunk_data.txt", "a+") as fp:
            fp.write(data)
            fp.close()
    fd.close()

    fd = open("chunk_data.txt", 'r')
    json_file = fd.read()
    chunk_data = chunkstring(json_file, CHUNK_SIZE)
    fd.close()
    index=1
    for item in chunk_data:
        with open("chunk_%d.txt"%index, "w+") as fp:
            fp.write(item)
            fp.close()
        index=index+1

    datalen=0
    for i in range(0,NV_index_count+1):
        if datalen <= size+NVM_SIZE_LEN:
            cmd='tpm2_nvundefine '+str(i)+' -T swtpm:port=' + swtmpport
            return_val = runcommand(cmd)
            cmd='tpm2_nvdefine -Q '+str(i)+' -C o -s '+str(CHUNK_SIZE)+' -a "ownerread|policywrite|ownerwrite" -T swtpm:port=' + swtmpport
            #print(cmd)
            return_val = runcommand(cmd)
            check_result(return_val, 'Defining NVRAM index :'+str(i))
            if i==0:
                filename='chunk_'+str(i)+'.txt'
                filesize=os.path.getsize(filename)
                print("\tWriting file size:"+str(filesize))
                cmd='tpm2_nvwrite -Q '+str(i)+' -C o -i chunk_len.txt -T swtpm:port=' + swtmpport
                #print(cmd)
                return_val = runcommand(cmd)
                cmd='tpm2_nvwrite -Q '+str(i)+' -C o --offset '+str(NVM_SIZE_LEN)+' -i '+filename+' -T swtpm:port=' + swtmpport
                #print(cmd)
                return_val = runcommand(cmd)
                check_result(return_val, 'Writting into NVRAM index:'+str(i))
                datalen=datalen+filesize+NVM_SIZE_LEN
            else:
                filename='chunk_'+str(i)+'.txt'
                filesize=os.path.getsize(filename)
                print("\tWriting file size:"+str(filesize))
                cmd='tpm2_nvwrite -Q '+str(i)+' -C o -i '+filename+' -T swtpm:port=' + swtmpport
                #print(cmd)
                return_val = runcommand(cmd)
                check_result(return_val, 'Writting into NVRAM index:'+str(i))
                datalen=datalen+filesize
    print("Successfully Updated NV RAM...")
    print("CLEAN all files generated before re-running the script")
    cleanup()
    print("---------------------------------------------------------------------------")

def cleanup():
    result = runcommand("rm tpm_* tmp_* chunk_* tpm_data.json")
    
def main():
    if len(sys.argv) == 1:
         print('"python3 Write_HWtpm_into_NVRAM.py <SWport>" - Please provoid the SW TPM port number as input')
         exit()
    else:
        if sys.argv[1] == '-h' or sys.argv[1] == '-help' or sys.argv[1] == '-Help':
            print('"python3 Write_HWtpm_into_NVRAM.py <SWport>" - Please provoid the SW TPM port number as input')
            print('"python3 Write_HWtpm_into_NVRAM.py -clean" for deleting all generated files')
            print('"python3 Write_HWtpm_into_NVRAM.py -help" for usage info')
        elif sys.argv[1] == '-clean':
            cleanup()
        else:
            cleanup()
            generate_AK_EK_keys()
            read_SWEK_cert(sys.argv[1])
            read_HWEK_cert()
            generate_HW_quote()
            construct_json_blob()
            write_into_nvram(sys.argv[1])

main()

