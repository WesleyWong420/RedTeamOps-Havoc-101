using System.Security.Cryptography.X509Certificates;

namespace DInvoke
{
    public static class Utilities
    {
        /// <summary>
        /// Checks that a file is signed and has a valid signature.
        /// </summary>
        /// <param name="filePath">Path of file to check.</param>
        /// <returns></returns>
        public static bool FileHasValidSignature(string filePath)
        {
            X509Certificate2 fileCertificate;

            try
            {
                var signer = X509Certificate.CreateFromSignedFile(filePath);
                fileCertificate = new X509Certificate2(signer);
            }
            catch
            {
                return false;
            }

            var certificateChain = new X509Chain();
            certificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            certificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return certificateChain.Build(fileCertificate);
        }
    }
}