
function escapeDNValue(s) {
  return s.replace(
    /(^ | $|[,\+"\\<>;\r\n=/])/,
    s => `\\${s}`
  )
}

document.addEventListener('DOMContentLoaded', () => {
  new Vue({
    el: '#app',
    data: {
      values: {
        domain: 'ambulanceservice.com.sg',
        country: 'SG',
        province: '',
        city: 'Singapore',
        organization: 'Ambulance Medical Service',
        cn: '',
        ou: '',
        email: '',
      },
      placeholders: {
        domain: '',
        country: '',
        province: '',
        city: '',
        organization: '',
        cn: 'John Smith',
        ou: 'Accounts',
        email: '@ambulanceservice.com.sg',
      },
      output: {
        private_key: '',
        public_key: '',
        csr: '',
      }
    },
    methods: {
      makeCSR() {
        // 3) with generateKeypair
        const kp = KEYUTIL.generateKeypair("RSA", 2048);
      
        this.output.private_key = KEYUTIL.getPEM(kp.prvKeyObj, "PKCS1PRV")
        this.output.public_key = KEYUTIL.getPEM(kp.pubKeyObj)
      
        const subjectString = [
          ['C', this.values.country],
          ['ST', this.values.province],
          ['L', this.values.city],
          ['O', this.values.organization],
          ['OU', this.values.ou],
          ['CN', this.values.cn],
        ]
        .concat(
          this.values.domain.split('.').map(dc => ['DC', dc])
        )
        .filter(([k, v]) => v.trim())
        .map(([k, v]) => `${k}=${escapeDNValue(v.trim())}`)
        .join(',');
      
        console.log(subjectString)
      
        const pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
          subject: {str: KJUR.asn1.x509.X500Name.ldapToOneline(subjectString)},
          sbjpubkey: kp.pubKeyObj,
          sigalg: "SHA256withRSA",
          sbjprvkey: kp.prvKeyObj
        });
        this.output.csr = pem
      },
      downloadPrivateKey() {
        download(this.output.private_key, "client.key", "application/octet-stream")
      },
    }
  })
})
