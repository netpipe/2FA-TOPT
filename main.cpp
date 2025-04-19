#include <QCoreApplication>
#include <QDebug>
#include "totp.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // Secret key (typically, you generate this and share it between server and client)
    QString sharedSecret = "JBSWY3DPEHPK3PXP"; // Example shared secret (Base32 encoded)

    // Create the TOTP instance
    TOTP totp(sharedSecret);

    // Generate the TOTP code
    QString generatedCode = totp.generateTOTP();
    qDebug() << "Generated TOTP Code: " << generatedCode;

    // Verify the TOTP code (you would typically compare the input from the user)
    bool isValid = totp.verifyTOTP(generatedCode);
    qDebug() << "TOTP verification result: " << (isValid ? "Valid" : "Invalid");

    return a.exec();
}
