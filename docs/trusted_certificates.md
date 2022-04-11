# Inserting Trusted Certificate into the Trust Store

All Trusted Certificates must be inserted into the Host machine Trust Store.

The `ca-certificates` package is used to insert a Trusted Certificate into the Host Machine Trust Store.

Follow below steps to insert a Trusted Certificate to the Trust Store. 

Example let's consider Trusted Certificate file as rootca.crt in PEM format.

1. Install ca-certificates package on Host machine
   ```sh
   sudo -E apt-get install -y ca-certificates
   ```

2. Copy the certificate in PEM format to location /usr/local/share/ca-certificates
   ```sh
   sudo cp rootca.crt /usr/local/share/ca-certificates
   ```
   **Note:** Certificate has to be in PEM format with *.crt extension
   
3. If certificate is in DER format, use below OpenSSL command to convert to PEM format
   ```sh
   sudo openssl x509 -inform der -outform pem -in rootca.der -out rootca.crt
   sudo cp rootca.crt /usr/local/share/ca-certificates
   ```
   
4. Install certificate into the Trust store
   ```sh
   sudo update-ca-certificates
   ```
