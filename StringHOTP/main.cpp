#include <QCoreApplication>
#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtMath>

//If you ask for >9 digits, quint32 might overflow.
//(We can switch to quint64 if you want super long OTPs later.)

class StringHOTP {
public:
    enum HashAlgorithm {
        SHA1,
        SHA256,
        SHA512
    };

    StringHOTP(const QString &secret, HashAlgorithm algo = SHA1, int digits = 6)
        : m_secret(secret), m_algo(algo), m_digits(digits) {}

    QString generateOTP(const QString &input) {
        QByteArray inputArray = input.toUtf8();

        QCryptographicHash::Algorithm hashAlgo;
        switch (m_algo) {
            case SHA256:
                hashAlgo = QCryptographicHash::Sha256;
                break;
            case SHA512:
                hashAlgo = QCryptographicHash::Sha512;
                break;
            case SHA1:
            default:
                hashAlgo = QCryptographicHash::Sha1;
                break;
        }

        QByteArray hmac = QMessageAuthenticationCode::hash(inputArray, m_secret.toUtf8(), hashAlgo);

        int offset = hmac.at(hmac.size() - 1) & 0x0F;

        quint32 binary =
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff);

        quint32 divisor = static_cast<quint32>(qPow(10, m_digits));
        quint32 otp = binary % divisor;

        return QString("%1").arg(otp, m_digits, 10, QLatin1Char('0'));
    }

private:
    QString m_secret;
    HashAlgorithm m_algo;
    int m_digits;
};


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QString secret = "MY_SHARED_SECRET";
    QString input = "MySecondaryPassword";

    // Using SHA-1 (default)
    StringHOTP hotpSha1(secret, StringHOTP::SHA1,6);
    QString otpSha1 = hotpSha1.generateOTP(input);
    qDebug() << "SHA-1 OTP:" << otpSha1;

    // Using SHA-256 (stronger)
    StringHOTP hotpSha256(secret, StringHOTP::SHA256);
    QString otpSha256 = hotpSha256.generateOTP(input);
    qDebug() << "SHA-256 OTP:" << otpSha256;
   QString otpSha2562 = hotpSha256.generateOTP(otpSha256);

    //verify
    QString submittedOtp = otpSha256; // Simulating submitted code

    StringHOTP verifier(secret, StringHOTP::SHA256);
    QString expectedOtp = verifier.generateOTP(input);

    if (otpSha256 == expectedOtp) {
        qDebug() << "OTP valid!";
    } else {
        qDebug() << "Invalid OTP!";
    }

    return a.exec();
}
