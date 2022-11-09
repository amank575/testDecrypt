const openpgp = require('openpgp');
const fs = require('fs');
const { config } = require('process');
async function decrypt() {
    const passphrase = `Password_1`;
    const encryptedData = fs.createReadStream('./data/encrypted.xlsx.pgp','binary');
    const privateKeyBlock = fs.readFileSync('./data/private_key.asc','utf8');
    const privateKey = await openpgp.readKey({ armoredKey: privateKeyBlock , config: { ignoreMalformedPackets: true}});
    await privateKey.decrypt(passphrase);

    const decrypted = await openpgp.decrypt({
        message: await openpgp.readMessage({ binaryMessage: encryptedData }),
        privateKeys: [privateKey],
        format: 'binary',
        config: { allowInsecureDecryptionWithSigningKeys: true, allowUnauthenticatedMessages: true  }
    });

    const readStream = decrypted.data;
    console.log(readStream);

}
decrypt();