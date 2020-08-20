#! /bin/bash

HOME_DIR="/home/juliazhu/Documents/ssl_on_the_fly/"
ca_file=$HOME_DIR"rootCA_key_cert.pem"
result_dir=$HOME_DIR"testing/results/"
#result_dir=$HOME_DIR"results/"
PEM_dir=$HOME_DIR"cov_certs/certs/"
OPENSSL_ROOT_DIR=$HOME_DIR'cov_certs/root/'
OPENSSL_LEAF_DIR=$HOME_DIR'cov_certs/leaf/'
#PEM_dir=$HOME_DIR"new_seeds/unconsis/seeds/"
#OPENSSL_ROOT_DIR=$HOME_DIR'new_seeds/unconsis/leaf'
#OPENSSL_LEAF_DIR=$HOME_DIR'new_seeds/unconsis/root'
openssl_instrumented_src='/home/juliazhu/Documents/openssl-1.1.1c'
openssl_instrumented_bin='/home/juliazhu/Documents/ssl_1.1.1c/bin/openssl'
polarssl_instrumented_bin='/home/juliazhu/Documents/mbedtls-2.16.2/programs/x509/cert_app'
gnutls_instrumented_bin='/home/juliazhu/Documents/gnutls-3.6.8-build/bin/certtool'
cd $PEM_dir

echo $PEM_dir
#result_file=$result_dir'openssl.txt'
for file in *.pem; do
   result_file=$result_dir${file%.*}".txt"
   echo '-----START VERIFYING '$file >>$result_file
   root_ca_file=$OPENSSL_ROOT_DIR$file
   leaf_file=$OPENSSL_LEAF_DIR$file
   if [ ! -f "$root_ca_file" ];then
          $openssl_instrumented_bin  verify -CAfile $ca_file $file >>$result_file 2>>$result_file
   else
          $openssl_instrumented_bin  verify -CAfile $root_ca_file $leaf_file >>$result_file 2>>$result_file
   fi
   echo '-----END VERIFYING '$file>>$result_file
   #echo ' '>>$result_file
done
echo "---complete openssl verification"

#result_file=$result_dir'polarssl.txt'
for file in *.pem; do
   result_file=$result_dir${file%.*}"_polarssl.txt"
   echo '-----START VERIFYING '$file >>$result_file
   $polarssl_instrumented_bin mode='file' filename=$file ca_file=$ca_file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete polarssl verification"

#result_file=$result_dir+'gnutls.txt'
for file in *.pem; do
   result_file=$result_dir${file%.*}"_gnutls.txt"
   echo '-----START VERIFYING '$file >>$result_file
   $gnutls_instrumented_bin --verify --load_ca_certificate=$ca_file <$file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete gnutls verification"