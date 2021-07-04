import {
  md,
  pkcs7, pki, random, cipher, util,
} from "node-forge"

it("General RSA playground", async () => {
  /**
   * We create a Certificate Authority (CA). The standard format for certificates is called X.509 and is defined in RFC5280; https://datatracker.ietf.org/doc/html/rfc5280
   *
   * The workflow is as follows:
   *
   *    1. Generate RSA public-, private key pair fo the CA,
   *    2. Create a root certificate for the CA,
   *    3. Self-sign the root certificate using the root's private key. This certificate is called a "trusted root certificate".
   */
  const caKeys = pki.rsa.generateKeyPair(4096)
  const rootPublicKey = caKeys.publicKey
  const rootPrivateKey = caKeys.privateKey
  // Create X.509-v3
  const caCertificate = pki.createCertificate()
  // set the public key of the CA to the certificate
  caCertificate.publicKey = rootPublicKey

  caCertificate.serialNumber = "01"
  caCertificate.validity.notBefore = new Date()
  caCertificate.validity.notAfter = new Date()
  caCertificate.validity.notAfter.setFullYear(caCertificate.validity.notBefore.getFullYear() + 1)
  caCertificate.setExtensions([{
    name: "basicConstraints",
    cA: true,
  }])
  var caAttributes = [{
    name: "organizationName",
    value: "Test-Organization",
  }]
  // for the CA issuer and subject are identical, since the root certificate is self-signed
  caCertificate.setIssuer(caAttributes)
  caCertificate.setSubject(caAttributes)

  // self-sign the CA's certificate
  caCertificate.sign(rootPrivateKey, md.sha256.create())

  /**
   * We describe the general certification process.
   *
   *
   * The certificate includes information about the key, information about the identity of its owner (called the subject),
   * and the digital signature of an entity that has verified the certificate's contents (called the issuer).
   *
   *
   * For the sake of simplicity we may assume the following:
   *
   *      1. We assume that the communication channels between any user and the CA is secure,
   *      2. We assume that all parties have access to the CA's public key.
   *
   * Alice wants her public key to be certified by the CA. For doing so, she creates a so called certificate signing request. The CA then creates a X.509 certificate
   * for Alice and signs it using the CA's root private key.
   *
   * This works as follows:
   *
   *      1. The CA hashes the certificate of Alice using a cryptographic one-way hash function,
   *      2. The CA encrypts the created hash using the CA's root private key (this is called the "digital signature"),
   *      3. The CA sends Alice's certificate along with the encrypted hash back to Alice.
   *
   * Alice's identity is now certifed by a trusted third party, the CA.
   *
   * Alice wants to send data to Bob.
   *
   * This works as follows:
   *
   *      1. Hash the data using a cryptographic one-way hash function,
   *      2. Encrypt the hash of the first step using the private key of Alice (digital signature),
   *      3. Attach the encrypted hash and Alice's certificate to the data.
   *
   * Send result of 3. to Bob.
   *
   * Bob verifies as follows:
   *
   *      1. Use the CA's public key to decrypt the signature of Alice's certificate (authenticity),
   *      2. Hash Alice's certificate using the same hashing algorithm as the CA,
   *      3. Compare the computed hash of 2. with the decrypted signature of 1 (integrity),
   *      4. Extract Alice's public key from Alice's certificate,
   *      5. Decrypt the signature of the data,
   *      6. Hash the data using the same hashing algorithm as used by Alice (usually this is identical as the hashing algorithm used by the CA and
   *         this algorithm is specified in the X.509 certificate),
   *      7. Compare the computed hash of 6. with the signature of 5 (integrity).
   *
   * Note: For an in-depth discussion on why we hash the data in the first place is given here: https://crypto.stackexchange.com/questions/12768/why-hash-the-message-before-signing-it-with-rsa/12769#12769
   *
   * Additional comments:
   *
   * It is standard, and highly encouraged, to use a padding scheme for the signatures.
   * This is used to randomize the encryption result. This means that if the same message is encrypted twice, two different ciphers are generated.
   * To achieve this, methods such as Probabilistic Signature Scheme (PSS) or Optimal Asymmetric Encryption Padding (OAEP) are used.
   *
   * (There is a fascinating attack published by Bleichenbacher on pkcs#1, called the Bleichenbacher padding oracle attack on pkcs#1)
   */

  // Create Alice.
  const alicesKeyPair = pki.rsa.generateKeyPair(4096)
  const alicesPrivateKey = alicesKeyPair.privateKey
  const alicesPublicey = alicesKeyPair.publicKey

  // create certificate signing request (CSR)
  const csrAlice = pki.createCertificationRequest()

  csrAlice.publicKey = alicesPublicey
  // the subject is set by Alice; the issue is now set by the CA (compare with the self-signing process given above)
  const subject = [{
    shortName: "UID",
    value: "42",
  }]
  csrAlice.setSubject(subject)
  // sign certification request using Alice's private key using SHA-256 message digest
  csrAlice.sign(alicesPrivateKey, md.sha256.create())

  /**
   * The Certificate Signing Request looks like this:
   *
   *
   Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject:
            userId                    = 42
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:aa:d1:c4:16:9a:ef:71:bb:0c:10:73:4b:f3:00:
                    97:ed:96:73:90:cd:57:8e:89:d4:4b:ed:f4:09:37:
                    78:6e:b6:bc:86:2b:ef:f7:4e:71:ab:89:6e:08:6e:
                    a7:1f:0e:11:68:da:f0:6e:0c:56:93:b3:3a:c5:11:
                    1f:b6:cc:03:12:a3:10:a1:8c:9a:84:16:c8:26:02:
                    2a:b6:4b:bc:cc:cd:8f:cb:d5:c9:d6:53:cf:6c:0f:
                    80:6c:39:b0:cb:9f:fc:61:ae:ec:8d:8d:3b:e0:c8:
                    05:d0:56:a8:11:e6:41:a3:d1:70:45:32:60:1c:72:
                    1d:d5:9e:ba:fd:0e:13:dd:e3:d4:f4:23:23:1f:ee:
                    aa:fe:f7:16:15:d6:95:47:f8:38:df:0a:2c:7b:db:
                    c4:be:05:e9:83:82:01:fc:6f:bd:40:2f:82:17:51:
                    8e:43:1c:f0:bb:cd:06:5d:49:c4:b7:ee:04:b6:24:
                    b8:b0:44:88:09:a4:c6:c4:1f:f9:52:42:9e:73:27:
                    6f:a1:6a:e6:8a:3f:c2:0a:74:21:57:41:0d:f5:2e:
                    1e:9b:64:f7:c5:2c:ac:59:64:f5:16:ec:77:6d:34:
                    33:3f:77:f5:44:cb:17:7b:bb:4a:d1:4e:2e:b0:45:
                    4c:58:ed:13:23:86:88:81:36:3a:65:25:d6:86:e3:
                    29:80:ca:88:64:94:97:b5:5c:1f:4c:65:c3:58:a5:
                    c4:5f:7c:71:a4:35:b2:48:06:ed:fd:67:16:4d:41:
                    80:40:45:54:b4:c0:72:e6:37:89:b4:67:68:2f:3d:
                    9c:28:24:4e:b4:78:e3:6d:5b:25:f3:6d:6c:1b:35:
                    64:bc:4a:44:e8:a5:3a:f4:ca:2d:1b:e6:be:cf:38:
                    1a:ac:43:23:43:6c:55:6d:2a:8a:21:c7:76:03:fb:
                    47:b5:87:24:7d:c8:34:d8:8c:39:12:ec:e0:30:0f:
                    68:6f:a3:cf:01:fc:5e:c0:43:5e:8b:e0:e9:1b:41:
                    b2:f7:ae:cb:87:50:bb:e0:34:85:d2:2a:14:2a:c2:
                    a9:fb:da:c4:80:cc:80:ad:71:62:38:49:ff:39:4c:
                    24:a5:21:04:ff:43:96:df:63:df:01:a9:bd:aa:83:
                    c3:ce:07:1e:44:1b:29:c0:a2:5f:b4:14:e4:4a:c3:
                    1e:49:d4:2c:e5:d8:4d:02:6d:46:14:d3:6d:c7:9c:
                    f5:58:27:94:73:3d:7b:12:d5:eb:e6:75:fb:b0:66:
                    a5:23:7c:84:c6:ec:68:96:f7:ce:61:38:f1:0a:e5:
                    10:b9:56:ce:b7:53:e2:ef:f2:88:47:5b:a1:c6:4b:
                    33:0b:04:1e:a0:4c:2f:f3:15:47:82:55:7c:b7:0c:
                    17:ff:59
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
         99:9a:b4:7d:e2:85:fb:61:1e:08:0d:6b:8d:10:7b:20:94:06:
         c4:4b:4f:68:0d:25:79:8c:1f:d1:e5:ac:da:c9:b3:b1:1e:0f:
         ee:ea:2d:6f:33:1f:8e:0d:da:4e:3b:75:24:d9:85:cb:09:73:
         61:86:34:b2:70:dd:96:70:e0:72:9f:52:57:02:1b:0d:58:32:
         36:ff:8f:48:00:e7:76:bd:ed:1c:04:19:f3:10:9f:7a:58:d9:
         78:8f:23:9c:fe:a4:aa:68:64:bf:5b:c1:95:6e:9c:cb:de:52:
         f3:11:d3:14:ef:c4:34:b7:91:d6:ea:5a:66:59:44:9d:63:d0:
         56:ea:c2:4e:fa:f9:84:e0:8a:34:96:ed:fe:d4:b2:54:13:3c:
         3d:7c:c9:6c:6b:65:24:75:c6:c2:0d:d1:a5:9e:94:d5:09:7a:
         83:31:e0:a4:8e:dd:42:af:d1:77:97:8b:3e:4c:a9:fd:61:2e:
         2f:7b:3d:e4:ec:73:50:9a:57:f0:ea:01:8f:c7:85:81:7f:78:
         cd:ac:2c:18:2d:4c:29:a6:0f:84:0a:57:e0:5e:39:d4:e1:77:
         73:72:c7:e6:6c:14:a6:fa:d4:44:73:cb:1c:fa:94:db:f0:67:
         73:2d:13:68:6e:1a:f7:7a:23:d5:e7:a8:d1:9a:7d:0a:80:bb:
         82:ff:38:2d:2a:16:eb:bf:d6:1a:d8:8e:0e:a8:07:50:ca:fc:
         34:1d:27:1c:ab:95:6b:c3:87:95:bb:ee:ae:aa:a4:96:ca:51:
         69:70:3a:2c:e4:c3:de:f5:49:2f:4f:d6:fb:b2:06:6f:9b:4d:
         f9:40:50:04:84:ee:c5:b3:93:13:9a:d7:32:73:6f:f3:1e:7d:
         fc:71:ee:b6:57:9c:35:35:21:61:06:df:91:14:94:2d:91:c3:
         f3:eb:00:e0:38:0a:09:2b:12:8d:91:0b:1c:52:f0:0e:6b:32:
         3a:b9:85:db:9e:e7:76:a6:15:33:c9:f1:b4:5b:21:86:18:ee:
         cc:7e:07:e8:65:ae:61:31:b3:6f:e3:55:24:a7:97:f8:40:b2:
         ae:82:b6:b5:59:57:9d:b2:37:ce:34:80:19:28:61:6c:e6:0b:
         c9:1c:4f:a7:a5:50:0c:40:99:3f:f2:0e:21:25:23:c6:86:3d:
         ce:e5:cc:ef:c2:04:6e:63:5c:37:48:83:90:04:dc:47:88:84:
         7e:f0:3c:97:c9:b1:07:35:6e:c9:90:70:85:b0:a4:c6:69:c8:
         a8:88:47:43:fe:c6:f1:01:9c:84:95:51:89:66:43:47:08:a6:
         37:af:a2:7a:e5:77:6a:81:b2:68:72:71:fa:5e:68:ed:d9:9a:
         84:36:11:78:70:ac:a2:6e
   */

  // The CA signs Alice's certificate
  const alicesCertificate = pki.createCertificate()
  alicesCertificate.setSubject(csrAlice.subject.attributes)
  // set issuer, which is the CA
  alicesCertificate.setIssuer(caAttributes)
  alicesCertificate.publicKey = csrAlice.publicKey

  alicesCertificate.serialNumber = "02"
  alicesCertificate.validity.notBefore = new Date()
  alicesCertificate.validity.notAfter = new Date()
  alicesCertificate.validity.notAfter.setFullYear(alicesCertificate.validity.notBefore.getFullYear() + 1)
  // sign certificate
  alicesCertificate.sign(rootPrivateKey, md.sha256.create())

  /**
   * Alice's certificate looks like this:
   Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer:
            organizationName          = Test-Organization
        Validity
            Not Before: Jul  2 21:39:27 2021 GMT
            Not After : Jul  2 21:39:27 2022 GMT
        Subject:
            userId                    = 42
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:ac:31:e5:bc:b3:38:a6:c9:05:c9:8f:d2:ee:e8:
                    af:9e:4e:76:06:23:62:23:f9:9c:c5:ab:cf:f0:61:
                    1f:26:15:21:6d:ac:ff:f6:67:c8:6b:43:af:1a:07:
                    35:92:80:11:c0:1e:e7:5b:ad:d2:51:dc:2f:7d:93:
                    72:93:aa:dd:c0:bc:c9:3d:3c:f2:e8:e1:25:c4:51:
                    26:8a:3c:eb:40:2e:7e:7a:65:3f:2e:78:24:ec:65:
                    9f:de:b0:82:c7:43:f9:2b:fc:7f:86:ba:61:c1:ed:
                    11:48:6e:f5:48:ad:fd:8d:ba:47:d6:8c:8a:be:06:
                    99:0f:b4:22:9e:7a:46:9a:29:55:ec:b0:fa:c3:6f:
                    68:7d:5c:77:a8:23:9e:87:61:7d:38:53:14:4d:8b:
                    83:8b:7f:ee:43:21:b2:ea:f0:3d:0e:45:ed:13:70:
                    b8:7f:a7:cc:45:83:7b:4f:11:38:d8:6f:84:9b:6b:
                    93:55:cd:4c:22:67:bd:55:1d:e5:86:ab:b9:48:6b:
                    54:6b:ea:2c:4e:01:12:1a:e1:1c:dc:53:82:c1:f0:
                    d5:39:21:3b:97:ef:99:00:ba:69:1d:d9:13:6b:08:
                    52:4b:25:b8:59:5d:7b:14:8a:42:b6:f6:59:38:04:
                    c4:c7:a0:2f:fa:ee:60:0d:ee:c9:58:e0:e4:17:09:
                    32:27:89:b3:79:a5:c1:e9:32:ee:ce:1c:9d:81:1a:
                    5b:c6:1c:3e:13:ff:70:09:c4:cd:48:70:f4:b1:1f:
                    8b:63:4f:12:b4:db:d6:8a:58:ac:b8:a7:07:37:a3:
                    27:06:a8:7b:3b:d6:a4:2f:32:0e:0a:2f:94:b5:bb:
                    19:6f:e3:11:e7:55:b5:0f:a9:fa:f7:10:bf:c8:49:
                    d0:81:12:a2:16:cd:67:6e:6e:17:24:d3:82:ad:2e:
                    6a:0a:28:55:c1:23:d2:67:29:92:bc:51:0d:5c:7b:
                    c9:bd:08:ae:ae:35:6d:e0:19:a9:52:cf:3a:8e:d5:
                    f4:5a:29:fb:c1:0d:68:1d:d7:98:29:de:00:ac:d1:
                    bb:c2:ab:c6:78:17:6d:31:94:de:6c:26:e6:36:18:
                    bf:43:b6:8a:8a:a1:e3:1b:57:05:c1:13:3e:13:9b:
                    78:95:b1:8b:41:04:2e:64:f5:32:81:40:94:8b:11:
                    b1:38:e1:3c:23:33:27:93:70:b0:6e:44:9d:73:21:
                    ee:8a:a6:64:91:2f:10:d8:77:8d:57:e5:7a:0d:3a:
                    92:4c:03:3d:d0:4b:0f:02:45:bd:95:e8:0a:80:e3:
                    d0:d5:86:41:e0:a9:6d:2a:2f:f5:9e:47:a5:db:8f:
                    e3:53:af:a4:de:c7:80:45:ce:e4:87:f7:8c:b3:e6:
                    e7:d3:0d
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         2e:97:0d:bd:ea:2d:87:63:3f:19:66:6d:de:fd:54:ee:a8:3e:
         a7:6a:bb:bd:d3:4a:74:da:b2:23:9f:75:43:3f:9d:7d:79:c4:
         f5:a9:73:c3:2e:bf:fe:73:38:c0:2a:9c:3a:74:cc:c3:0a:cb:
         ef:96:2d:ec:57:72:26:9e:13:e3:99:bd:23:6d:52:56:2a:5b:
         c4:0d:41:3a:c2:44:41:44:33:83:b5:3e:a7:05:ec:37:0a:77:
         21:a9:2b:07:bb:39:18:fc:fc:1e:08:f6:29:14:85:0a:c6:83:
         1f:e4:ca:27:3d:81:34:24:a5:d2:2c:a5:2f:1f:b0:3c:01:d4:
         d5:d7:19:6b:f7:3c:bb:22:19:78:a6:5f:1e:2e:bb:0c:fa:bb:
         0a:51:e6:67:24:1c:10:de:d8:2c:8a:f0:bb:61:c1:fd:62:d3:
         c2:dc:9e:98:66:a4:a3:a3:d0:ea:47:06:74:bd:6d:6a:78:8b:
         1c:0f:ce:64:22:86:02:be:d9:12:be:05:b0:7e:7a:c7:7f:05:
         f1:7d:c3:a5:61:03:4f:3f:ad:8a:e6:db:e7:fd:0e:64:eb:b2:
         f7:13:e7:a8:87:02:2f:31:f9:9e:01:8d:d3:d1:7a:95:7a:bd:
         35:3e:22:52:6b:b5:3d:6f:4f:15:1e:2f:e6:61:a0:85:36:60:
         bd:09:9d:f3:c1:3b:18:a0:66:9b:ca:d0:b7:4e:77:52:d4:35:
         f7:55:bf:c0:2c:7c:13:e9:72:e7:f4:e4:15:d1:62:f1:ac:42:
         17:49:b3:9d:75:27:04:9e:5a:b4:0b:8c:84:3a:1d:b4:02:46:
         9a:3a:51:5d:12:d6:1a:85:66:30:d0:cf:30:58:8b:01:31:47:
         a1:70:c2:27:df:20:42:d2:86:3b:c4:ce:d6:02:29:eb:98:d6:
         c2:34:9f:7b:eb:d6:9e:69:d4:7e:8b:6c:73:db:17:0c:38:af:
         ee:37:dc:40:35:6f:69:85:41:7a:61:73:98:e6:aa:9a:c5:c4:
         5a:37:ce:0d:72:29:32:a0:83:76:f9:ea:5c:7a:c0:9c:e7:54:
         ca:cd:a0:47:88:97:2e:d0:7d:1d:52:27:c6:73:80:35:0d:0e:
         86:20:c7:d3:c0:f0:5f:b2:35:af:d2:95:14:bc:42:14:0e:8d:
         62:50:4e:27:f1:87:92:f3:90:c7:62:61:4f:ab:9b:fd:cd:29:
         fd:6f:79:2b:58:ad:2e:74:db:d8:91:48:5a:cc:48:2a:96:d9:
         57:e7:ed:6e:aa:c1:d0:c1:b4:16:c9:5c:b9:dc:72:c1:0d:e7:
         c3:a4:9c:19:21:bc:d0:18:aa:75:15:b9:19:33:70:62:8a:c6:
         59:cc:e1:a6:8c:42:e7:28
   */

  // verify
  expect(caCertificate.verify(alicesCertificate)).toBe(true)

  // Now, we send data to Bob.
  const messageToBob = "Hello Bob, it's me, Alice!"
  // create signature by first hashing the message and the encrypting the hash using her private key.
  const hashFunction = md.sha256.create()
  hashFunction.update(messageToBob)

  // Compare the result with CyberChef https://gchq.github.io/CyberChef/, SHA-256, 64 Rounds
  const hashAsHex = hashFunction.digest().toHex()
  expect(hashAsHex).toBe("c7b7952be7e9ed52a477c494ef7b3a067ca69480be719c5bd3c2524841254bc1")

  // encrypt the signature
  const signature = alicesPrivateKey.sign(hashFunction)

  const messageRequestToBoB = {
    message: messageToBob,
    certificate: alicesCertificate,
    signature: signature,
  }

  // suppose that Bob receives the message from Alice. We perform the process as described above
  const wasCertificateIssuedByCA = caCertificate.verify(messageRequestToBoB.certificate)
  expect(wasCertificateIssuedByCA).toBe(true)
  expect(messageRequestToBoB.certificate.md.algorithm).toBe("sha256")
  const verificationHashFunction = md.sha256.create()
  verificationHashFunction.update(messageRequestToBoB.message)
  // TypeScript definitions not up-to-date
  expect(messageRequestToBoB.certificate.publicKey.verify(verificationHashFunction.digest().bytes(), signature)).toBe(true)
})

it("Dabbling around with encryption algorithms", async () => {
  /**
   * We are going to implement the RSA key generation, encryption and decryption process by hand for learning purposes.
   *
   *
   * The encryption in asymetric cryptography is based on the difficulty of the prime factorization problem.
   *
   * Let p and q be two prime numbers, then the mapping  f: pq -> n is computational easy.
   * The inverse of f, f^-1: n -> pq is called the prime factorization of n. The cryptographic security of RSA
   * is based on the difficulty of calculating f^-1.
   *
   * The prime factorization decision problem, let us call it PFDP (given an integer n, can n be expressed
   * as the product of two prime numbers?) is clearly in NP (and co-NP as well).
   * However, interestingly it has not yet been proven whether PFDP is NP-Complete. Today, it is widely suspected that
   * PFDP is a candidate for a NP-intermediate according to Laudner's Theorem under the assumption that P neq NP.
   * (compare with the complexity of the graph isomorphism problem)
   *
   * However, it is important to keep in mind that there is no valid proof that certifies that the PFDP is not polynomial-time
   * solvable (even if this is very unlikely).
   *
   * Thus, we assume that, given an integer n, it is computational infeasible to solve the prime factorization problem for n.
   *
   *
   * The RSA encryption algorithm works as follows:
   *
   *      1. Select two large primes (p,q),
   *      2. Compute n=pq,
   *      3. Compute the Euler Totient Function: Phi(n)=(p-1)(q-1) (Intuition: Since p and q are prime and n=pq,
   *         there exist (p-1)(q-1) numbers between one and n that are relatively prime to n (coprime to n)),
   *      4. Select at random an integer e, such that 1 < e < Phi(n) with gcd(e, Phi(n))=1, whereby gcd denote the greatest common
   *         divisor of e and Phi(n) (in other words: e and (p – 1)(q – 1) must be coprime),
   *         we call the integer e the public key,
   *      5. Compute an integer d, such that ed = 1 mod Phi(n). We call the integer d the private key,
   *      6. Let p be the plaintext. We encrypt p using c = p^e mod n. We call c the cipher of p,
   *      7. The decryption works as follows: p = c^d mod n.
   */

  // greatest common divisor
  let gcd = function (a, b) {
    return b ? gcd(b, a % b) : a
  }
  // extended eucledian algorithm for calculating the modular inverse
  // props https://stackoverflow.com/questions/26985808/calculating-the-modular-inverse-in-javascript/51562038
  let xgcd = function (a, b) {
    if (b === 0) {
      return [1, 0, a]
    }
    let temp = xgcd(b, a % b)
    let x = temp[0]
    let y = temp[1]
    let d = temp[2]
    return [y, x - y * Math.floor(a / b), d]
  }
  // Choose very large primes :P
  const p = 7
  const q = 3
  const n = p * q
  const phi = (p - 1) * (q - 1)

  // find e
  let e = 2
  while (e < phi) {
    if (gcd(e, phi) === 1) {
      break
    } else {
      e = e + 1
    }
  }
  // calculate d
  const d = xgcd(e, phi)
  // encryption
  const plaintext = 12
  const cipher = (plaintext ** e) % n
  // decryption
  const decryptedPlaintext = (cipher ** d[0]) % n
  expect(decryptedPlaintext).toBe(plaintext)

  /**
   * Notice that RSA encrypts messages of limited size and that RSA encryption performance is slow compared to
   * symmetric algorithms such as AES. For that reason it is well established to use hybrid cryptographic systems,
   * that is a symmetric encryption algorithm for encrypting the actual data and an asymmetric encryption algorithm for
   * ensuring data authenticity and symmetric key exchange between two entities.
   *
   * (Further notes: there is a nice concept that uses much smaller keys but providing equivalent security by exploiting
   *  the structural properties of plane curves over finite fields, called elliptic curve. https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
   */
})

it("PKCS#7 and S/MIME playground", async () => {
  /**
   * PKCS#7 is a container for X.509 public key certificates and is defined in RFC2315; https://datatracker.ietf.org/doc/html/rfc2315
   */
  // Fake CA, only used for private key; complete workflow is described above
  const rootKeyPair = pki.rsa.generateKeyPair(4096)
  const rootPrivateKey = rootKeyPair.privateKey
  const issuer = [{
    name: "organizationName",
    value: "Test-Organization",
  }]
  // we create a recipient; and sign its certificate using CA's private key.
  const alicesKeyPair = pki.rsa.generateKeyPair(4096)
  const alicesPublicKey = alicesKeyPair.publicKey
  const alicesPrivateKey = alicesKeyPair.privateKey
  const alicesCertificate = pki.createCertificate()
  const subject = [{
    shortName: "UID",
    value: "42",
  }]
  alicesCertificate.setSubject(subject)
  alicesCertificate.setIssuer(issuer)
  alicesCertificate.publicKey = alicesPublicKey
  alicesCertificate.serialNumber = "01"
  alicesCertificate.validity.notBefore = new Date()
  alicesCertificate.validity.notAfter = new Date()
  alicesCertificate.validity.notAfter.setFullYear(alicesCertificate.validity.notBefore.getFullYear() + 1)
  alicesCertificate.sign(rootPrivateKey, md.sha256.create())
  /**
   * Now, the workflow is as follows.
   *
   *      1. Create PKCS#7 EnvelopedData,
   *      2. Add CA signed X.509 certificates of the recipients (for now this is only us),
   *      3. Create AES-256 key,
   *      4. Encrypt the data using the key generated in 3.,
   *      5. Create AES-256 key,
   *      6. Encrypt the AES-256 key using the AES-256 key from 5. by adding it as content in the pkcs#7 envelope,
   *      7. The pkcs#7 envelope is encrypted using the recipients public key,
   *      8. Create PKCS#7 SignedData,
   *      9. Add Alice's CA signed certificate,
   *      10. Add the pkcs#7 envelope as content,
   *      11. Sign the content using Alice's private key.
   */
  var pkcs7Envelope = pkcs7.createEnvelopedData()
  // add a recipient; which is only Alice itself in our case
  pkcs7Envelope.addRecipient(alicesCertificate)

  // create AES-256; iv denotes the initialization vector
  var key = random.getBytesSync(32)
  var iv = random.getBytesSync(16)

  const dataToEncrypt = "Hello World!"

  var aesCipher = cipher.createCipher("AES-CBC", key)
  aesCipher.start({ iv: iv })
  aesCipher.update(util.createBuffer(dataToEncrypt))
  aesCipher.finish()

  // set AES key as content for the pkcs#7 envelope; we encrypt this using AES-256 as well
  const pkcs7ContentAsHex = util.bytesToHex(iv) + util.bytesToHex(key)
  pkcs7Envelope.content = util.createBuffer(pkcs7ContentAsHex)

  // encrypt using AES-256
  pkcs7Envelope.encrypt()

  // convert to PEM
  // TypeScript is not up-to-date
  var pkcs7EnvelopePEM = pkcs7.messageToPem(pkcs7Envelope)
  /**
   * The final PKCS#7 Envelope looks like this:
  PKCS7:
  type: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.enveloped:
    version: 0
    recipientinfo:
        version: 0
        issuer_and_serial:
          issuer: O=Test-Organization
          serial: 1
        key_enc_algor:
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
          parameter: NULL
        enc_key:
          0000 - 37 a1 55 05 14 fa ec 52-09 47 35 5b e6 88 7d   7.U....R.G5[..}
          000f - 5d 8f 80 ac 21 9b d6 89-ad 23 a9 18 49 e4 ca   ]...!....#..I..
          001e - 80 57 fd 37 14 e0 16 a4-7c c4 aa ea 9b 77 9b   .W.7....|....w.
          002d - a8 72 46 00 b6 6f 1f 1e-90 89 96 54 47 4f ba   .rF..o.....TGO.
          003c - 61 ac 23 38 89 fc da 3b-3c 7b 2f 9b f5 c1 53   a.#8...;<{/...S
          004b - 02 f2 9b 64 10 1c f6 8e-42 d8 5e 89 1e ee 97   ...d....B.^....
          005a - 68 b9 29 35 03 e1 c4 63-27 ed 36 ee fc ab 81   h.)5...c'.6....
          0069 - fe 08 ca a6 54 59 bc 5d-32 21 91 bb 14 6b e0   ....TY.]2!...k.
          0078 - 61 45 a4 32 e6 ae d3 4d-18 8c 19 84 d8 bb 09   aE.2...M.......
          0087 - 69 1f 7c 9a b6 f2 70 8c-09 07 71 fc 6e 20 58   i.|...p...q.n X
          0096 - 4e a5 0e c4 fa dd 20 1c-52 ec b4 8f 57 28 a9   N..... .R...W(.
          00a5 - 67 5b 40 bd b9 bd 41 17-36 5e 94 43 84 59 74   g[@...A.6^.C.Yt
          00b4 - 82 2f 06 2d dd 81 29 2b-15 5d 8a fc df a5 9c   ./.-..)+.].....
          00c3 - 56 ad 1f a1 d7 b8 d3 3c-c5 7a c2 c3 b4 44 bc   V......<.z...D.
          00d2 - d2 46 3f de e0 8a 3a a2-66 60 2a 20 c3 2c 87   .F?...:.f`* .,.
          00e1 - 18 a0 e3 e3 a5 3f 2e e5-ef bc 75 90 95 b5 17   .....?....u....
          00f0 - 60 a9 dd b3 b7 50 84 a6-80 65 95 97 8d 58 ee   `....P...e...X.
          00ff - 2e 62 9b f6 58 a4 26 aa-78 d2 0c eb 89 1f a5   .b..X.&.x......
          010e - f8 e4 16 3e 9e 3d da 3a-48 b3 b5 a5 70 1d c9   ...>.=.:H...p..
          011d - c5 9e 84 d4 dd 42 0d b8-61 f6 9f 30 33 f3 14   .....B..a..03..
          012c - 13 c2 11 1a 68 36 c0 dd-81 5c 1c d7 1e 0c 41   ....h6...\....A
          013b - f7 29 4c 63 e9 62 f0 e7-d9 70 f2 bb 01 38 d2   .)Lc.b...p...8.
          014a - 4b 4c 64 51 63 4f 14 74-2f 4d 92 3c 8b a1 ba   KLdQcO.t/M.<...
          0159 - 1a a0 00 f4 ea 3b 5c a3-29 2a af 24 fa 0c 54   .....;\.)*.$..T
          0168 - 0e dc 6b 9f c2 89 fa 24-de d7 8c 28 c6 64 5a   ..k....$...(.dZ
          0177 - ec eb 64 12 35 63 b4 77-7b e0 87 f6 a1 5c 49   ..d.5c.w{....\I
          0186 - 29 44 17 ec 9e 6b b9 c2-a0 a6 e3 b2 a4 8f 08   )D...k.........
          0195 - ed fe 3b bb 9a 93 82 c1-01 61 4f e4 50 7c 0f   ..;......aO.P|.
          01a4 - 64 45 a4 26 e4 a5 3e 19-a1 16 74 11 5c a5 ea   dE.&..>...t.\..
          01b3 - d0 83 0d 12 86 7d 94 a0-c2 4f aa d0 07 ff 1b   .....}...O.....
          01c2 - ae df d3 dd b6 de f0 81-99 2f 78 ae 1e f4 ef   ........./x....
          01d1 - 44 af 87 51 95 5e d7 58-51 8b 8d 83 b9 35 20   D..Q.^.XQ....5
          01e0 - ee 4d 25 0c 32 2a c1 38-13 cf a2 8c af 0c cf   .M%.2*.8.......
          01ef - ac 92 35 c6 23 ce 13 71-70 67 4a e1 dd 73 62   ..5.#..qpgJ..sb
          01fe - 70 06                                          p.
    enc_data:
      content_type: pkcs7-data (1.2.840.113549.1.7.1)
      algorithm:
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
        parameter: OCTET STRING:
          0000 - 26 51 69 bd 87 44 42 a2-12 46 18 fa 8b 49 30   &Qi..DB..F...I0
          000f - f3                                             .
      enc_data:
        0000 - 6a 55 f2 22 bc 9e d7 bb-29 dc 77 56 29 f7 a1   jU."....).wV)..
        000f - 5b 57 2c 84 b8 7d 03 29-52 e7 2d 22 2d 7e d5   [W,..}.)R.-"-~.
        001e - ed 51 d9 ce 1e 70 32 ff-67 2e 1f e0 d0 7d 89   .Q...p2.g....}.
        002d - 96 b0 85 0f d3 ba fc 1a-0d 37 6d af a3 17 0f   .........7m....
        003c - 1b 56 1c 82 f9 d9 d5 4c-ea dd d1 2f 95 25 9a   .V.....L.../.%.
        004b - aa cd 5d 94 2d 96 67 ad-9d 4a b8 cc a4 1c 3f   ..].-.g..J....?
        005a - a5 6a be 0c ba 48 f5 ac-9e ae 46 28 3f 64 60   .j...H....F(?d`
        0069 - 00 5e 43 e1 d0 31 18                           .^C..1.
   */

  // create signed part of the pkcs#7-signed mime part for multipart message
  var pkcs7SignedData = pkcs7.createSignedData()
  pkcs7SignedData.content = pkcs7EnvelopePEM
  pkcs7SignedData.addCertificate(alicesCertificate)
  pkcs7SignedData.addSigner({
    key: pki.privateKeyToPem(alicesPrivateKey),
    certificate: alicesCertificate,
    digestAlgorithm: pki.oids.sha256,
    authenticatedAttributes: [{
      type: pki.oids.contentType,
      value: pki.oids.data,
    }, {
      type: pki.oids.messageDigest,
    }, {
      type: pki.oids.signingTime,
    }],
  })
  pkcs7SignedData.sign()
  /**
   * The final pkcs#7 signed part looks like this:
  Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=Test-Organization
        Validity
            Not Before: Jul  4 18:06:32 2021 GMT
            Not After : Jul  4 18:06:32 2022 GMT
        Subject: UID=42
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:ce:4f:81:7c:00:95:fa:0a:ff:6d:7c:9b:cc:2b:
                    eb:14:e5:00:ac:56:39:e0:26:25:d4:86:48:12:16:
                    0c:f4:0c:0b:bd:98:3a:20:91:49:c7:f8:02:f8:bb:
                    50:d6:3b:67:41:3f:58:ac:e9:0c:b3:f7:cf:be:2d:
                    dd:36:d5:00:8f:e7:be:b5:99:58:99:76:1d:5f:7a:
                    aa:fa:5e:bc:a2:19:dd:d6:6a:82:b0:8e:9c:59:e7:
                    02:c1:a4:ce:e1:16:97:63:78:7e:62:66:33:48:c5:
                    60:95:49:a4:93:0a:f8:4d:4d:ca:9b:5e:dd:f3:aa:
                    78:d6:6d:a1:5d:cb:4c:6e:21:6e:e2:38:32:05:3d:
                    b2:fe:31:16:ad:fa:aa:4e:5e:f3:04:6a:a4:fd:70:
                    4c:a0:73:23:3a:5c:2f:1d:b9:66:29:b4:1b:b8:c9:
                    fa:aa:7e:d9:c9:c7:75:72:e5:48:40:17:b5:8a:e9:
                    c0:8f:ff:46:c9:90:8c:50:2e:74:5c:76:4f:ec:30:
                    c5:66:42:0c:67:d4:c9:be:60:9b:46:d4:55:9d:69:
                    a2:2c:0a:eb:0f:42:6b:2f:71:4e:b6:0c:bf:7a:de:
                    73:b3:55:b0:8f:79:45:e4:86:5f:84:99:00:94:26:
                    73:5c:3c:52:56:02:c6:4d:e1:6e:5e:84:1e:02:50:
                    b1:58:a6:7e:91:e8:60:f1:71:bf:90:42:11:6c:10:
                    8c:2c:a0:04:cb:03:c9:78:51:f2:b6:8c:43:18:b6:
                    cc:8d:51:10:a0:85:9e:fd:08:4a:2b:20:7a:40:06:
                    6c:72:4d:0e:bc:f2:ff:f4:0b:32:30:74:ac:8a:c4:
                    bb:0e:d6:af:91:9c:d8:9a:db:c8:8e:83:ae:b6:04:
                    ee:6c:b5:0b:6a:40:79:b6:ee:67:36:b2:13:92:43:
                    14:93:52:5c:57:8d:a4:71:40:62:9f:ae:c6:d1:51:
                    7a:f9:c9:0b:4a:88:ce:5c:6d:fd:d3:94:32:e0:39:
                    98:9c:c8:7c:a8:8b:0e:a8:57:a0:f0:8f:09:92:fb:
                    5b:ce:2f:d2:73:9b:f7:89:1a:c4:36:c2:0b:95:e1:
                    6e:b3:49:1e:bf:74:70:64:9f:7d:be:e8:1d:35:50:
                    00:d8:7c:c0:07:f8:0f:a4:f3:46:77:55:a6:52:c5:
                    14:fd:3f:8c:80:6e:72:76:7c:d6:2b:e4:d0:57:e9:
                    d8:70:77:f6:7f:49:64:2b:0d:10:03:d0:b0:85:6c:
                    34:b3:11:d0:f2:a6:97:22:5c:92:81:11:52:13:1a:
                    0e:02:1c:0b:13:67:8e:50:ea:86:09:22:51:07:6f:
                    3a:d6:cc:07:22:9a:b6:71:70:b9:41:9d:24:e8:eb:
                    5c:76:eb
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         9a:90:f4:cd:6e:c0:02:ca:04:a6:66:46:38:b4:9c:25:bc:2b:
         31:74:28:32:95:49:f5:e9:b8:5d:e0:3c:de:b3:38:cc:49:95:
         be:c7:8e:30:b2:83:dc:4d:fa:82:ef:42:98:d0:21:cc:98:c9:
         34:b8:18:2a:d9:c3:12:88:ab:9c:20:47:cb:61:18:fb:5b:7b:
         5c:7c:33:cd:8d:a2:03:a7:3c:a5:73:97:41:c5:77:73:ef:53:
         c0:cf:49:fd:1a:92:35:c2:96:65:8f:b6:2b:a3:93:53:75:3a:
         66:23:cf:7b:e6:94:3d:69:f5:96:1a:75:dd:6b:a7:f9:a5:da:
         18:84:4d:46:8c:a8:b9:bc:cf:f4:34:a5:c9:84:48:a7:2c:ef:
         46:a6:86:ca:f5:34:7c:6f:7a:f3:cb:af:a2:ab:7d:c5:c3:66:
         07:e6:1e:63:40:6f:c9:d0:dc:88:cb:78:35:ca:ce:38:c6:bc:
         51:f1:5f:1e:35:2e:bd:3d:53:0d:76:4f:48:8e:de:55:26:0a:
         da:d9:95:fd:bf:81:0d:c4:be:d8:a1:b0:3d:5a:e5:05:93:b2:
         37:90:75:16:c1:62:0a:81:d8:f3:dc:87:75:3b:36:57:bb:ba:
         43:ea:b0:17:50:a9:cc:08:fa:f3:b2:13:fe:f2:ac:de:c9:4c:
         b2:88:ba:7b:2e:d7:e5:9a:14:db:e9:8a:97:6b:59:70:06:39:
         9a:f4:60:5b:d4:58:4b:75:58:d8:56:3e:40:22:a3:a4:2d:d6:
         80:65:e4:23:b5:6b:01:71:cc:a0:fd:43:59:f4:f0:61:9a:29:
         ec:a9:16:01:4e:e6:0f:b8:88:8e:6e:72:25:e4:3a:03:8c:f0:
         d0:06:45:3a:11:f6:86:76:1e:0c:f0:27:4f:43:95:92:8d:0b:
         57:57:08:e3:cb:eb:2d:0d:87:20:cb:6f:bd:7e:88:b4:1f:26:
         3d:83:3d:3e:33:4f:e3:47:37:86:33:d8:21:26:6b:aa:a6:e5:
         c0:ab:5e:19:f2:cc:80:7a:a4:46:ae:44:0a:8b:ea:bc:20:a5:
         53:33:b9:d6:2e:52:5a:e3:c2:5c:b8:12:96:5e:c1:8b:5f:66:
         8e:7e:a5:b8:69:b3:c6:8d:81:09:e4:93:80:6b:f2:bf:d7:0c:
         bb:58:ec:8c:69:63:96:b6:db:f6:f6:5b:83:cb:8b:92:d9:d2:
         d8:16:e4:42:87:9f:e3:6e:2b:9d:6f:e7:2b:67:21:6b:b9:6e:
         b6:b3:fe:35:c0:9f:d5:f2:0d:2a:2c:20:c0:22:7b:a9:d5:07:
         d2:86:eb:6c:76:d7:d3:96:8e:76:f6:de:c8:62:8c:43:25:8c:
         03:79:a0:6f:a9:94:a3:2b
   */

  // validate if verything has worked as expected
})
