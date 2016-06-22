using System;
using System.Web;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices.AccountManagement;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IO;

namespace SignedJwtCreator
{
    public class JwtLogin : IHttpHandler
    {
        private string PRIVATEKEY = ConfigurationManager.AppSettings["PrivateKeyPEM"];
        private string LOGINURL = ConfigurationManager.AppSettings["LoginURL"];
        private string ISSUER = ConfigurationManager.AppSettings["Issuer"];

        public void ProcessRequest(HttpContext context)
        {
            var userInformation =
              GetUserNameAndEmailAddress(HttpContext.Current.Request.LogonUserIdentity.Name);

            var privateKey = ReadPrivateKey(PRIVATEKEY);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
          	RSAParameters p = ToRSAParameters(privateKey);
          	rsa.ImportParameters(p);

            var token = new JwtSecurityToken(issuer: ISSUER,
          	claims: new List<Claim>() {
              new Claim(ClaimTypes.Name, userInformation.Item1),
              new Claim(ClaimTypes.Email, userInformation.Item2),
              new Claim("logon", LOGINURL),
            },
          	notBefore: DateTime.UtcNow,
          	expires: DateTime.UtcNow.AddMinutes(20),
          	signingCredentials: new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha512Digest));

            var tokenHandler = new JwtSecurityTokenHandler();
            string redirectUrl = LOGINURL + tokenHandler.WriteToken(token);

            string returnTo = context.Request.QueryString["return_to"];

            if(returnTo != null) {
              redirectUrl += "&return_to=" + HttpUtility.UrlEncode(returnTo);
            }

            context.Response.Redirect(redirectUrl);
        }

        static RsaPrivateCrtKeyParameters ReadPrivateKey(string pem)
        {
        		var keyPair = (AsymmetricCipherKeyPair)(new PemReader(new StringReader(pem)).ReadObject());
        		return (RsaPrivateCrtKeyParameters)keyPair.Private;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
        	RSAParameters rp = new RSAParameters();
        	rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
        	rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
        	rp.P = privKey.P.ToByteArrayUnsigned();
        	rp.Q = privKey.Q.ToByteArrayUnsigned();
        	rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
        	rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
        	rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
        	rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
        	return rp;
        }

        private static byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
        	byte[] bs = n.ToByteArrayUnsigned();
        	if (bs.Length == size)
        		return bs;
        	if (bs.Length > size)
        		throw new ArgumentException("Specified size too small", "size");
        	byte[] padded = new byte[size];
        	Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
        	return padded;
        }


        public Tuple<string, string> GetUserNameAndEmailAddress(string username)
        {
           using (var pctx = new PrincipalContext(ContextType.Domain))
           {
               using (UserPrincipal up = UserPrincipal.FindByIdentity(pctx, username))
               {
                  string emailAddress = up != null && !String.IsNullOrEmpty(up.EmailAddress) ? up.EmailAddress.ToLower() : username.Split('\\')[1] + "@" + ISSUER;
                  string name = up != null && !String.IsNullOrEmpty(up.Name) ? up.Name : username.Split('\\')[1];

                  return new Tuple<string, string>(name, emailAddress);
               }
           }
        }

        public bool IsReusable
        {
            get
            {
                return true;
            }
        }
    }
}
