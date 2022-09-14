import ru.CryptoPro.Crypto.CryptoProvider
import ru.CryptoPro.JCP.JCP
import ru.CryptoPro.reprov.RevCheck
import ru.CryptoPro.ssl.Provider
import ru.CryptoPro.ssl.util.TLSContext

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import java.security.KeyStore
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

class ConnectionGOST {
    boolean checkConnection = false;
    String response = null;

    boolean getCheckConnection() {
        return checkConnection;
    }

    String getResponse() {
        return this.response;
    }

    void setCheckConnection(HttpsURLConnection connection) throws Exception {
        if (connection != null) {
            checkConnection = true;
        } else {
            checkConnection = false;
        }
    }


    ConnectionGOST(String URLPathTrust, String passwordTrust, String URLConnect) {

        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        Security.addProvider(new Provider());
        Security.addProvider(new CryptoProvider());
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");

        try {
            SSLContext ctx = TLSContext.initClientSSL(
                    null,
                    URLPathTrust,
                    passwordTrust,
                    null
            );

            SSLSocketFactory factory = ctx.getSocketFactory();
            this.response = connect(factory, URLConnect);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    String connect(SSLSocketFactory factory,
                   String urlPath) throws Exception {

        URL url = new URL(urlPath);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(factory);
        setCheckConnection(connection);
        String res = printContent(connection);
        connection.disconnect();
        return res;
    }


    String printContent(HttpsURLConnection connection)
            throws Exception {
        String response = null;
        if (connection != null) {

            response = printStream(connection.getInputStream());
        }
        return response;
    }

    String printStream(InputStream inputStream) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, "utf-8"));
        StringBuilder sb = new StringBuilder();
        String input;
        while ((input = br.readLine()) != null) {
            sb.append(input);
            sb.append(System.lineSeparator());
        }
        br.close();
        return sb.toString();
    }
}

def addCert(String cer, String type, String pass, String store, String named) throws Exception {
    CertificateFactory var5 = CertificateFactory.getInstance("X509");
    Certificate var6 = var5.generateCertificate(new BufferedInputStream(new FileInputStream(cer)));
    KeyStore var7 = KeyStore.getInstance(type);
    char[] var8 = null;
    if (!"null".equalsIgnoreCase(pass)) {
        var8 = pass.toCharArray();
    }

    FileInputStream var9 = null;
    if (!"null".equalsIgnoreCase(store)) {
        var9 = new FileInputStream(store);
    }

    var7.load(var9, var8);
    var7.setCertificateEntry(named, var6);
    FileOutputStream var10 = null;
    if (!"null".equalsIgnoreCase(store)) {
        var10 = new FileOutputStream(store);
    }

    var7.store(var10, var8);
}

String cer = "/Users/knockjkeee/Downloads/cert/certnew.cer";
//String cer = "/opt/jcp/cerf/certnew.cer";
String store = "/Users/knockjkeee/Downloads/cert/store/trust.store";
//String store = "/opt/jcp/cerf/store/trust.store";
String urlPath = "https://testca.cryptopro.ru/certsrv/certcarc.asp";
String pass = "123456";

//boolean isCreate = new File(store).createNewFile();
//addCert(cer, "HDImageStore", pass, store, "Cert");

ConnectionGOST connectionGOST = new ConnectionGOST(store, pass, urlPath);
boolean checkConnected = connectionGOST.getCheckConnection();
def response = connectionGOST.getResponse();
//logger.error(response)

if (checkConnected) {
    System.out.println("Connected GOST true...");
//    logger.error("Connected GOST true...");
}
if (!checkConnected) {
    System.out.println("Connected GOST false...");
//    logger.error("Connected GOST false...");
}