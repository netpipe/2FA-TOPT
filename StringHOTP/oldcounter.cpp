#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

class HOTP {
public:
    HOTP(const QString &secret) : m_secret(secret) {}

    QString generateOTP(quint64 counter) {
        QByteArray counterArray(8, '\0');
        for (int i = 7; i >= 0; --i) {
            counterArray[i] = counter & 0xFF;
            counter >>= 8;
        }

        QByteArray hmac = QMessageAuthenticationCode::hash(counterArray, m_secret.toUtf8(), QCryptographicHash::Sha1);
        int offset = hmac.at(hmac.size() - 1) & 0x0F;

        quint32 binary =
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff);

        quint32 otp = binary % 1000000;  // 6-digit code
        return QString("%1").arg(otp, 6, 10, QLatin1Char('0'));
    }

private:
    QString m_secret;
};
