$params = @{
    Subject = 'CN=www.growtopia1.com,O=FenrirBots'
    DnsName = 'www.growtopia1.com', 'www.growtopia2.com', '127.0.0.1'
    CertStoreLocation = 'Cert:\LocalMachine\My'
    KeyAlgorithm = 'RSA'
    KeyLength = 2048
}
New-SelfSignedCertificate @params