#include <QCoreApplication>
#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtMath>

//If you ask for >9 digits, quint32 might overflow.
//(We can switch to quint64 if you want super long OTPs later.)

#pragma once

#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtMath>
#include <QDateTime>

class DoubleOTP
{
public:
    enum HashAlgorithm {
        SHA1,
        SHA256,
        SHA512
    };

    DoubleOTP(const QString &secret, HashAlgorithm algo = SHA256, int digits = 6, int timeStep = 30)
        : m_secret(secret), m_algo(algo), m_digits(digits), m_timeStep(timeStep) {}

    QString generate(const QString &userInput) const {
        QString totpPart = generateTOTP();
        QString hotpPart = generateStringHOTP(userInput);

        QString combined = totpPart + hotpPart;

        QByteArray finalHash = QCryptographicHash::hash(combined.toUtf8(), toQtHashAlgo());

        int offset = finalHash.at(finalHash.size() - 1) & 0x0F;

        quint32 binary =
            ((finalHash[offset] & 0x7f) << 24) |
            ((finalHash[offset + 1] & 0xff) << 16) |
            ((finalHash[offset + 2] & 0xff) << 8) |
            (finalHash[offset + 3] & 0xff);

        quint32 divisor = static_cast<quint32>(qPow(10, m_digits));
        quint32 otp = binary % divisor;

        return QString("%1").arg(otp, m_digits, 10, QLatin1Char('0'));
    }

private:
    QString m_secret;
    HashAlgorithm m_algo;
    int m_digits;
    int m_timeStep;

    QByteArray hashAlgorithm() const {
        switch (m_algo) {
            case SHA256: return QByteArray::fromHex("06"); // Just a trick to select later
            case SHA512: return QByteArray::fromHex("07");
            case SHA1:
            default:     return QByteArray::fromHex("05");
        }
    }

    QCryptographicHash::Algorithm toQtHashAlgo() const {
        switch (m_algo) {
            case SHA256: return QCryptographicHash::Sha256;
            case SHA512: return QCryptographicHash::Sha512;
            case SHA1:
            default:     return QCryptographicHash::Sha1;
        }
    }

    QString generateTOTP() const {
        qint64 time = QDateTime::currentSecsSinceEpoch() / m_timeStep;

        QByteArray timeBytes(8, 0);
        for (int i = 7; i >= 0; --i) {
            timeBytes[i] = static_cast<char>(time & 0xFF);
            time >>= 8;
        }

        QByteArray hmac = QMessageAuthenticationCode::hash(timeBytes, m_secret.toUtf8(), toQtHashAlgo());

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

    QString generateStringHOTP(const QString &input) const {
        QByteArray inputArray = input.toUtf8();
        QByteArray hmac = QMessageAuthenticationCode::hash(inputArray, m_secret.toUtf8(), toQtHashAlgo());

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
};


bool validateDoubleOTP(const QString &userOtp, const QString &secret, const QString &userInput, int allowedDrift = 1)
{
    DoubleOTP doubleOtp(secret, DoubleOTP::SHA256, 6, 30); // Same settings as generation

    // Generate current OTP
    QString expectedOtp = doubleOtp.generate(userInput);

    if (userOtp == expectedOtp) {
        return true; // Match!
    }

    // Optional: Allow time drift (previous and next time step)
    if (allowedDrift > 0) {
        // Temporarily shift the time backwards
        QDateTime now = QDateTime::currentDateTimeUtc();

        for (int i = 1; i <= allowedDrift; ++i) {
            qint64 shiftSeconds = i * 30;

            // Shift backwards
            QDateTime past = now.addSecs(-shiftSeconds);
            QDateTime future = now.addSecs(shiftSeconds);

            // Temporarily fake time
            qint64 backupTime = QDateTime::currentSecsSinceEpoch();
            qint64 fakePast = past.toSecsSinceEpoch();
            qint64 fakeFuture = future.toSecsSinceEpoch();

            // Regenerate for past time
            DoubleOTP pastOtp(secret, DoubleOTP::SHA256, 6, 30);
            QString pastCode = pastOtp.generate(userInput);

            if (userOtp == pastCode) {
                return true;
            }

            // Regenerate for future time
            DoubleOTP futureOtp(secret, DoubleOTP::SHA256, 6, 30);
            QString futureCode = futureOtp.generate(userInput);

            if (userOtp == futureCode) {
                return true;
            }
        }
    }

    return false; // No match
}

bool validateTOTP(const QString &userOtp, const QString &secret, int timeStep = 30, int allowedDrift = 1)
{
    DoubleOTP doubleOtp(secret, DoubleOTP::SHA256, 6, timeStep);

    // Generate the OTP for the current time
    QString expectedOtp = doubleOtp.generate(""); // No need for user input, just time-based

    // Check if the OTP matches
    if (userOtp == expectedOtp) {
        return true; // Match
    }

    // Optional: Allow time drift (validates 1 step before or after the time window)
    if (allowedDrift > 0) {
        QDateTime now = QDateTime::currentDateTimeUtc();

        for (int i = 1; i <= allowedDrift; ++i) {
            qint64 shiftSeconds = i * timeStep;

            // Temporarily shift the time forwards and backwards
            QDateTime future = now.addSecs(shiftSeconds);
            QDateTime past = now.addSecs(-shiftSeconds);

            // Fake the system time
            qint64 fakePast = past.toSecsSinceEpoch();
            qint64 fakeFuture = future.toSecsSinceEpoch();

            // Generate OTP based on shifted time
            DoubleOTP pastOtp(secret, DoubleOTP::SHA256, 6, timeStep);
            QString pastCode = pastOtp.generate("");

            if (userOtp == pastCode) {
                return true; // Match with past time (drift)
            }

            // Generate OTP for future time
            DoubleOTP futureOtp(secret, DoubleOTP::SHA256, 6, timeStep);
            QString futureCode = futureOtp.generate("");

            if (userOtp == futureCode) {
                return true; // Match with future time (drift)
            }
        }
    }

    return false; // No match
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QString secret = "MY_SUPER_SECRET";
    DoubleOTP doubleOtp(secret, DoubleOTP::SHA256, 6, 30); // SHA-256, 6 digits, 30 seconds
    QString userInput = "my_password_or_session_id";
    QString finalOtp = doubleOtp.generate(userInput);
    qDebug() << "Double OTP:" << finalOtp;

    bool valid = validateDoubleOTP(finalOtp, secret, userInput);
    if (valid) {
        qDebug() << "OTP Valid!";
    } else {
        qDebug() << "OTP Invalid!";
    }


    //wont work without secondary string ?
    bool isValid = validateTOTP(finalOtp, secret);
    if (isValid) {
        qDebug() << "TOTP is valid!";
    } else {
        qDebug() << "TOTP is invalid!";
    }

    return a.exec();
}
