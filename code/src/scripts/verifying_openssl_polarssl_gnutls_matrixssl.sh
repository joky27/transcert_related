#! /bin/bash

HOME_DIR='/home/'
ca_file=$HOME_DIR"rootCA.pem"
result_dir=$HOME_DIR"results/frankencert_10000/"
root_openssl_dir=$HOME_DIR"frankencert/root/"
leaf_openssl_dir=$HOME_DIR"frankencert/leaf/"

PEM_dir=$HOME_DIR"frankencert/output"
cd $PEM_dir

result_file=$result_dir"openssl.txt"
rm $result_file
for file in *.pem; do
   echo '-----START VERIFYING '$file >>$result_file
   root_ca_file=$root_openssl_dir$file
   leaf_file=$leaf_openssl_dir$file
   if [ ! -f "$root_ca_file" ]; then
        /home/public/ssl-1.1.1c/bin/openssl verify -verbose -CAfile $ca_file $file >>$result_file 2>>$result_file
   else
        /home/public/ssl-1.1.1c/bin/openssl verify -verbose -CAfile $root_ca_file $leaf_file >>$result_file 2>>$result_file
   fi
   #/home/public/ssl-1.1.1c/bin/openssl verify -verbose -CAfile $ca_file $file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete openssl verification"

result_file=$result_dir"polarssl.txt"
rm $result_file
for file in *.pem; do
   echo '-----START VERIFYING '$file >>$result_file
   /home/documents/mbedtls-2.16.2/programs/x509/cert_app mode='file' filename=$file  ca_file=$ca_file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete polarssl verification"

result_file=$result_dir"gnutls.txt"
rm $result_file
for file in *.pem; do
   echo '-----START VERIFYING '$file >>$result_file
   certtool --verify --load-ca-certificate=$ca_file <$file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete gnutls verification"


result_file=$result_dir"matrixssl.txt"
rm $result_file
for file in *.pem; do
   echo '-----START VERIFYING '$file >>$result_file
   /home/documents/matrixssl-4-2-1-open/matrixssl/test/certValidate -c $ca_file $file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete matrixssl verification"

