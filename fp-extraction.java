import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKeyStructure;
import org.bouncycastle.openssl.PEMParser;

public class SSHKeyFingerprintExtractor {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Specify the path to your SSH key file
        String sshKeyFilePath = "/path/to/your/ssh_key.pub";

        try (BufferedReader br = new BufferedReader(new FileReader(sshKeyFilePath))) {
            PEMParser pemParser = new PEMParser(br);

            // Parse the PEM encoded SSH public key
            Object obj = pemParser.readObject();
            if (obj instanceof RSAPublicKeyStructure) {
                RSAPublicKey rsaPublicKey = ((RSAPublicKeyStructure) obj).getPublicKey();

                // Compute the SSH key fingerprint
                String fingerprint = computeFingerprint(rsaPublicKey);

                System.out.println("SSH Key Fingerprint: " + fingerprint);
            } else {
                System.err.println("Unsupported key format.");
            }
        }
    }

    public static String computeFingerprint(RSAPublicKey publicKey) {
        byte[] encodedKey = publicKey.getEncoded();
        byte[] hash = org.bouncycastle.util.SshFingerprint.computeFingerprint(encodedKey);

        StringBuilder fingerprint = new StringBuilder();
        for (byte b : hash) {
            if (fingerprint.length() > 0) {
                fingerprint.append(":");
            }
            fingerprint.append(String.format("%02X", b));
        }
        return fingerprint.toString();
    }
}
