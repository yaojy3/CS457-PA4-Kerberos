/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By:
     1- Jesse Yao
           2- Emily Sutton
Submitted on:
     Insert the date of Submission here

----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs
//***********************************************************************
// pLAB-01
//***********************************************************************
void
handleErrors (char *msg)
{
  fprintf (stderr, "\n%s\n", msg);
  ERR_print_errors_fp (stderr);
  exit (-1);
}

unsigned
encrypt (uint8_t *pPlainText, unsigned plainText_len, const uint8_t *key,
         const uint8_t *iv, uint8_t *pCipherText)
{
  int status;
  unsigned len = 0, encryptedLen = 0;

  /* Create and initialise the context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    handleErrors ("encrypt: failed to creat CTX");

  // Initialise the encryption operation.
  status = EVP_EncryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    handleErrors ("encrypt: failed to EncryptInit_ex");

  // Call Encrypt Update as many times as needed (e.g. inside a loop)
  // to perform regular encryption
  status
      = EVP_EncryptUpdate (ctx, pCipherText, &len, pPlainText, plainText_len);
  if (status != 1)
    handleErrors ("encrypt: failed to EncryptFinal_ex");
  encryptedLen += len;

  // If additional ciphertext may still be generated,
  // the pCipherText pointer must be first advanced forward
  pCipherText += len;

  // Finalize the encryption.
  status - EVP_EncryptFinal_ex (ctx, pCipherText, &len);
  if (status != 1)
    handleErrors ("encrypt: failed to EncryptFinal_ex");
  encryptedLen
      += len; // len could be 0 if no additional ciphertext was generated

  /* Clean up */
  EVP_CIPHER_CTX_free (ctx);

  return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned
decrypt (uint8_t *pCipherText, unsigned cipherText_len, const uint8_t *key,
         const uint8_t *iv, uint8_t *pDecryptedText)
{
  int status;
  unsigned len = 0, decryptedLen = 0;

  /* Create and initialise the context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    handleErrors ("decrypt: failed to creat CTX");

  // Initialise the decryption operation.
  status = EVP_DecryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    handleErrors ("decrypt: failed to DecryptInit_ex");

  // Call DecryptUpdate as many times as needed (e.g. inside a loop)
  // to perform regular decryption
  status = EVP_DecryptUpdate (ctx, pDecryptedText, &len, pCipherText,
                              cipherText_len);
  if (status != 1)
    handleErrors ("decrypt: failed to DecryptUpdate");
  decryptedLen += len;

  // If additionl decrypted text may still be generated,
  // the pDecryptedText pointer must be first advanced forward
  pDecryptedText += len;

  // Finalize the decryption.
  status = EVP_DecryptFinal_ex (ctx, pDecryptedText, &len);
  if (status != 1)
    handleErrors ("decrypt: failed to DecryptFinal_ex");
  decryptedLen += len;

  /* Clean up */
  EVP_CIPHER_CTX_free (ctx);

  return decryptedLen;
}

//-----------------------------------------------------------------------------

static unsigned char
    plaintext[PLAINTEXT_LEN_MAX],  // Temporarily store plaintext
    ciphertext[CIPHER_LEN_MAX],    // Temporarily store outcome of encryption
    decryptext[DECRYPTED_LEN_MAX]; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue.
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int
encryptFile (int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
  int status;
  unsigned len = 0, encryptedLen = 0;

  // Initialize context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    handleErrors ("encrypt: failed to creat CTX");

  // Initialise the encryption operation.
  status = EVP_EncryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    handleErrors ("encrypt: failed to EncryptInit_ex");

  // Call Encrypt Update as many times as needed (e.g. inside a loop)
  // to perform regular encryption

  int num_read = 0;      // Number of bytes read
  int num_wrote = 0;     // Number of bytes written
  int num_encrypted = 0; // NUmber of bytes encrypted
  while (1)
    {
      // Read as many bytes into buffer
      num_read = read (fd_in, plaintext, PLAINTEXT_LEN_MAX);

      if (num_read == -1)
        handleErrors ("encryptFile: Failed to read plaintext\n");

      if (num_read == 0) // No more bytes to be read, reached EOF
        break;
      // Encrypt Update
      num_encrypted
          = EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, num_read);

      if (num_encrypted != 1)
        handleErrors ("encryptFile: failed to EncryptFinal_ex");
      encryptedLen += len;

      // Write completed encrypted block to fd_out
      num_wrote = write (fd_out, ciphertext, len);
      if (num_wrote == -1)
        handleErrors ("encryptFile: failed to write ciphertext");

      // Clear buffers for next encryption
      memset (plaintext, 0, PLAINTEXT_LEN_MAX);
      memset (ciphertext, 0, CIPHER_LEN_MAX);
    }

  // Finalize the encryption.
  num_encrypted = EVP_EncryptFinal_ex (ctx, ciphertext, &len);
  if (status != 1)
    handleErrors ("encrypt: failed to EncryptFinal_ex");
  encryptedLen
      += len; // len could be 0 if no additional ciphertext was generated

  num_wrote = write (fd_out, ciphertext, len);
  if (num_wrote < 0)
    handleErrors ("encryptFile: failed to write final to fd_out");
  /* Clean up */
  EVP_CIPHER_CTX_free (ctx);

  return encryptedLen;
}

//-----------------------------------------------------------------------------

int
decryptFile (int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
  int status;
  unsigned len = 0, decryptedLen = 0;

  /* Creating new context*/
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      handleErrors ("decryptFile: failed to create CTX\n");
    }

  /* Start decryption */
  status = EVP_DecryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    {
      handleErrors ("decryptFile: failed to DecryptInit_ex\n");
    }

  /* Keeping track */
  int num_read = 0;
  int num_wrote = 0;
  int num_decrypted = 0;

  /* Repeatedly call DecryptUpdate*/
  while (1)
    {
      /* reading into ciphertext from fd_in bc fd_in has ciphertext in it*/
      num_read = read (fd_in, ciphertext, CIPHER_LEN_MAX);
      if (num_read == -1)
        {
          handleErrors ("decryptFile: Failed to read to ciphertext\n");
        }

      /*Checking EOF*/
      if (num_read == 0)
        {
          break;
        }

      // check the parameters here im 90% sure they are right
      // My thinking is this is supposed to be outputting into decryptext from
      // ciphertext
      num_decrypted
          = EVP_DecryptUpdate (ctx, decryptext, &len, ciphertext, num_read);

      if (num_decrypted != 1)
        {
          handleErrors ("decryptFile: failed to DecryptUpdate\n");
        }
      decryptedLen += len;

      /* writing the decrypted text to fd_out*/
      num_wrote = write (fd_out, decryptext, len);
      if (num_wrote == -1)
        {
          handleErrors ("decryptFile: failed to write decryptext.\n");
        }

      // Clearing for next decryption
      memset (ciphertext, 0, CIPHER_LEN_MAX);
      memset (decryptext, 0, DECRYPTED_LEN_MAX);
    }

  // check parameters here too
  num_decrypted = EVP_DecryptFinal_ex (ctx, decryptext, &len);

  if (num_decrypted == -1)
    {
      handleErrors ("decryptFile: failed to DecryptFinal_ex\n");
    }
  decryptedLen += len;

  // check params
  num_wrote = write (fd_out, decryptext, len);
  if (num_wrote < 0)
    {
      handleErrors ("decryptFile: failed to write final to fd_out\n");
    }

  /*Clean up*/
  EVP_CIPHER_CTX_free (ctx);

  return decryptedLen;
}
//***********************************************************************
// pLAB-02
//***********************************************************************

EVP_PKEY *
getRSAfromFile (char *filename, int public)
{
  FILE *fp = fopen (filename, "rb");
  if (fp == NULL)
    {
      fprintf (stderr, "getRSAfromFile: Unable to open RSA key file %s \n",
               filename);
      return NULL;
    }

  EVP_PKEY *key = EVP_PKEY_new ();
  if (public)
    key = PEM_read_PUBKEY (fp, &key, NULL, NULL);
  else
    key = PEM_read_PrivateKey (fp, &key, NULL, NULL);

  fclose (fp);

  return key;
}

//-----------------------------------------------------------------------------

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the
// signature report the actual length in bytes of the result in 'sigLen'
//
// Returns:
//    1 on success, or 0 on ANY REASON OF FAILURE

int
privKeySign (uint8_t **sig, size_t *sigLen, EVP_PKEY *privKey, uint8_t *inData,
             size_t inLen)
{
  // Guard against incoming NULL pointers
  if (!privKey || !inData || !inLen)
    {
      printf (
          "\n*******************privKeySign recieved some NULL pointers\n");
      return 0;
    }

  // Create and Initialize a context for RSA private-key signing
  // me starts here
  // checking the ctx instance
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (privKey, NULL);
  if (!ctx)
    {
      EVP_PKEY_CTX_free (ctx);
      handleErrors ("Failed to make ctx instance in privKeySign");
      return 0;
    }

  // doing initial PKEY sign and checking
  int sign_init = EVP_PKEY_sign_init (ctx);
  if (sign_init == -1)
    {
      EVP_PKEY_CTX_free (ctx);
      handleErrors ("Failed to initialize the sign\n");
      return 0;
    }

  int setpad = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING);

  if (setpad <= 0)
    {
      EVP_PKEY_CTX_free (ctx);
      handleErrors ("Failed to set padding for ctx\n");
      return 0;
    }

  // Determine how big the size of the signature could be
  size_t cipherLen;

  if (EVP_PKEY_sign (ctx, NULL, sigLen, inData, inLen) <= 0)
    {
      EVP_PKEY_CTX_free (ctx);
      handleErrors ("\nFailed to retrieve signature length\n");
      return 0;
    }
  // Next allocate memory for the ciphertext
  // not sure if this should be * or ** but pointers are hard
  // not freeing in this function because I think it needs to be used in
  // pubKeyVerify

  *sig = malloc (*sigLen);

  // Now, actually sign the inData using EVP_PKEY_sign( )
  if (EVP_PKEY_sign (ctx, *sig, sigLen, inData, inLen) <= 0)
    {
      EVP_PKEY_CTX_free (ctx);
      handleErrors ("\nFailed to sign inData\n");
      return 0;
    }

  // All is good
  EVP_PKEY_CTX_free (
      ctx); // remember to do this if any failure is encountered above

  return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey'
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int
pubKeyVerify (uint8_t *sig, size_t sigLen, EVP_PKEY *pubKey, uint8_t *data,
              size_t dataLen)
{
  // Guard against incoming NULL pointers
  if (!sig || !pubKey || !data)
    {
      printf ("\n******* pkeySign received some NULL pointers\n");
      return 0;
    }

  // Create and Initialize a context for RSA public-key signature verification
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (pubKey, NULL);
  if (!ctx)
    {
      handleErrors ("Failed to make ctx instance pubKeyVerify");
      EVP_PKEY_CTX_free (ctx);
      return 0;
    }

  int verif = EVP_PKEY_verify_init (ctx);
  if (verif == -1)
    {
      handleErrors ("Failed to initialize verification");
      EVP_PKEY_CTX_free (ctx);
      return 0;
    }

  int setpad = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING);
  if (setpad == -1)
    {
      handleErrors ("Failed to set padding for ctx pubKeyVerify\n");
      EVP_PKEY_CTX_free (ctx);
      return 0;
    }

  // Verify the signature vs the incoming data using this context
  int decision = EVP_PKEY_verify (ctx, sig, sigLen, data, dataLen);

  //  free any dynamically-allocated objects
  EVP_PKEY_CTX_free (ctx);
  free (sig);

  return decision;
}

//-----------------------------------------------------------------------------

size_t
fileDigest (int fd_in, int fd_out, uint8_t *digest)
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data
// into the array 'digest' If the file descriptor 'fd_out' is > 0, also write a
// copy of the incoming data stream file to 'fd_out' Returns actual size in
// bytes of the computed digest
{
  EVP_MD_CTX *mdCtx = EVP_MD_CTX_new (); // to create new hashing context
  size_t nBytes;
  unsigned int mdLen = 0;
  // Initialize the context using EVP_DigestInit() so that it deploys
  // the HASH_ALGORITHM() hashing function

  if (mdCtx == NULL)
    return 0;

  if (EVP_DigestInit (mdCtx, HASH_ALGORITHM ()) <= 0)
    {
      EVP_MD_CTX_free (mdCtx);
      handleErrors ("Failed to init digest\n");
      // this might need to be changed to EVP_MD_CTX_free() if the other is
      // deprecated
      return mdLen;
    }

  while (1) // Loop until end-of input file
    {
      // Read a chunk of input from fd_in. Exit the loop when End-of-File is
      // reached
      nBytes = read (fd_in, digest, HASH_LEN);

      if (nBytes == -1)
        {
          EVP_MD_CTX_free (mdCtx);
          handleErrors ("failed to read fd_in");
        }

      // checking EOF
      if (nBytes == 0)
        break;

      if (EVP_DigestUpdate (mdCtx, digest, nBytes) == 0)
        {
          EVP_MD_CTX_free (mdCtx);
          handleErrors ("Digest Update failed");
        }

      // if ( fd_out > 0 ) send the above chunk of data to fd_out
      if (fd_out > 0)
        {
          if (write (fd_out, digest, nBytes) == -1)
            {
              EVP_MD_CTX_free (mdCtx);
              handleErrors ("Failed to write to fd_out");
            }
        }
    }

  //  EVP_DigestFinal( )
  if (EVP_DigestFinal (mdCtx, digest, &mdLen) == 0)
    {
      EVP_MD_CTX_free (mdCtx);
      handleErrors ("Digest Final failed");
      return 0;
    }
  EVP_MD_CTX_free (mdCtx);

  return mdLen;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void
exitError (char *errText)
{
  fprintf (stderr, "%s\n", errText);
  exit (-1);
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int
getKeyFromFile (char *keyF, myKey_t *x)
{
  int fd_key;

  fd_key = open (keyF, O_RDONLY);
  if (fd_key == -1)
    {
      fprintf (stderr, "\nCould not open key file '%s'\n", keyF);
      return 0;
    }

  // first, read the symmetric encryption key
  if (SYMMETRIC_KEY_LEN != read (fd_key, x->key, SYMMETRIC_KEY_LEN))
    {
      fprintf (stderr, "\nCould not read key from file '%s'\n", keyF);
      return 0;
    }

  // Next, read the Initialialzation Vector
  if (INITVECTOR_LEN != read (fd_key, x->iv, INITVECTOR_LEN))
    {
      fprintf (stderr, "\nCould not read the IV from file '%s'\n", keyF);
      return 0;
    }

  close (fd_key);

  return 1; //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1

size_t
MSG1_new (FILE *log, uint8_t **msg1, const char *IDa, const char *IDb,
          const Nonce_t Na)
{

  //  Check agains any NULL pointers in the arguments
  if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
      fprintf (log, "\nMSG1_new: PASSED IN NULL ARGUMENT\n");
      return 0;
    }

  size_t lenA = strlen (IDa) + 1; //  number of bytes in IDa ;
  size_t LenB = strlen (IDb) + 1; //  number of bytes in IDb ;
  size_t LenMsg1 = LENSIZE + lenA + LENSIZE + LenB
                   + NONCELEN; //  number of bytes in the completed MSG1
  size_t *lenPtr;
  uint8_t *p;

  // Allocate memory for msg1. MUST always check malloc() did not fail
  *msg1 = malloc (LenMsg1);

  if (*msg1 == NULL)
    {
      fprintf (log, "\nFailed to allocate memory to msg1\n");
      return 0;
    }

  // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
  p = *msg1;

  // use the pointer p to traverse through msg1 and fill the successive parts
  // of the msg Fill lenA
  memcpy (p, &lenA, LENSIZE);
  p += LENSIZE;

  // Fill IDa
  memcpy (p, IDa, lenA);
  p += lenA;

  // Fill LenB
  memcpy (p, &LenB, LENSIZE);
  p += LENSIZE;

  // Fill IDb
  memcpy (p, IDb, LenB);
  p += LenB;

  // Fill Na
  memcpy (p, Na, NONCELEN);
  p += NONCELEN;

  fprintf (log,
           "The following new MSG1 ( %lu bytes ) has been created by MSG1_new "
           "():\n",
           LenMsg1);
  // BIO_dumpt the completed MSG1 indented 4 spaces to the right
  BIO_dump_indent_fp (log, *msg1, LenMsg1, 4);
  fprintf (log, "\n");

  return LenMsg1;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void
MSG1_receive (FILE *log, int fd, char **IDa, char **IDb, Nonce_t Na)
{

  //  Check agains any NULL pointers in the arguments
  if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
      fprintf (log, "\nMSG1_receive: PASSED IN NULL ARGUMENT\n");
      return;
    }
  size_t LenMsg1 = 0, lenA, lenB;
  // Throughout this function, don't forget to update LenMsg1 as you receive
  // its components

  // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb
  // ||  Na

  // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa):
  if (read (fd, &lenA, LENSIZE) <= 0)
    {
      fprintf (log,
               "Unable to receive all %lu bytes of Len(IDA) "
               "in MSG1_receive() ... EXITING\n",
               LENSIZE);

      fflush (log);
      fclose (log);
      exitError ("Unable to receive all bytes lenA in MSG1_receive()");
    }

  LenMsg1 += LENSIZE; // Update Len by size of LenA

  // 2) Allocate memory for ID_A ... But on failure to allocate memory:
  *IDa = malloc (lenA);

  if (*IDa == NULL)
    {
      fprintf (log,
               "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
               "... EXITING\n",
               lenA);
      fflush (log);
      fclose (log);
      exitError ("Out of Memory allocating IDA in MSG1_receive()");
    }

  // On failure to read ID_A from the pipe
  if (read (fd, *IDa, lenA) <= 0)
    {
      fprintf (log,
               "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
               "... EXITING\n",
               lenA);
      fflush (log);
      fclose (log);
      exitError ("Out of Memory allocating IDA in MSG1_receive()");
    }

  LenMsg1 += lenA; // Update Len with size of IDa

  // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
  if (read (fd, &lenB, LENSIZE) <= 0)
    {
      fprintf (log,
               "Unable to receive all %lu bytes of Len(IDB) "
               "in MSG1_receive() ... EXITING\n",
               LENSIZE);

      fflush (log);
      fclose (log);
      exitError ("Unable to receive all bytes of LenB in MSG1_receive()");
    }

  LenMsg1 += LENSIZE; // Update Len with size of lenB

  // 4) Allocate memory for ID_B    But on failure to allocate memory:
  *IDb = malloc (lenB);

  if (*IDb == NULL)
    {
      fprintf (log,
               "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
               "... EXITING\n",
               lenB);
      fflush (log);
      fclose (log);
      exitError ("Out of Memory allocating IDB in MSG1_receive()");
    }

  // Now, read IDb ... But on failure to read ID_B from the pipe
  if (read (fd, *IDb, lenB) <= 0)
    {
      fprintf (log,
               "Unable to receive all %lu bytes of IDB in MSG1_receive() "
               "... EXITING\n",
               lenB);
      fflush (log);
      fclose (log);
      exitError ("Unable to receive all bytes of IDB in MSG1_receive()");
    }

  LenMsg1 += lenB; // Update Len by size of IDb

  // 5) Read Na   But on failure to read Na from the pipe
  if (read (fd, Na, NONCELEN) <= 0)
    {
      fprintf (log,
               "Unable to receive all %lu bytes of Na "
               "in MSG1_receive() ... EXITING\n",
               NONCELEN);

      fflush (log);
      fclose (log);
      exitError ("Unable to receive all bytes of Na in MSG1_receive()");
    }

  LenMsg1 += NONCELEN; // Final update to Len with NONCELEN

  fprintf (log,
           "MSG1 ( %lu bytes ) has been received"
           " on FD %d by MSG1_receive():\n",
           LenMsg1, fd);
  fflush (log);

  return;
}

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store
plaintext ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of
encryption decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted
text

// above arrays being static to resolve runtime stack size issue.
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char
    ciphertext2[CIPHER_LEN_MAX]; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) ||
// TktCipher All L() fields are size_t integers Set *msg2 to point at the newly
// built message Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2

size_t
MSG2_new (FILE *log, uint8_t **msg2, const myKey_t *Ka, const myKey_t *Kb,
          const myKey_t *Ks, const char *IDa, const char *IDb, Nonce_t *Na)
{
  size_t LenMsg2, LenTkt, LenUnEncr;

  //---------------------------------------------------------------------------------------
  // Construct TktPlain = { Ks  || L(IDa)  || IDa }
  // in the global scratch buffer plaintext[]
  memset (plaintext, 0,
          PLAINTEXT_LEN_MAX); // Make sure the plaintext array is empty

  uint8_t *p = plaintext; // Pointer to plaintext to traverse.

  size_t lenA = strlen (IDa) + 1;
  size_t lenB = strlen (IDb) + 1;

  memcpy (p, Ks, KEYSIZE);
  p += KEYSIZE;
  LenTkt = KEYSIZE;

  memcpy (p, &lenA, LENSIZE);
  p += LENSIZE;
  LenTkt += LENSIZE;

  memcpy (p, IDa, lenA);
  p += lenA;
  LenTkt += lenA;

  // Use that global array as a scratch buffer for building the plaintext of
  // the ticket Compute its encrypted version in the global scratch buffer
  // ciphertext[] Now, set TktCipher = encrypt( Kb , plaintext ); Store the
  // result in the global scratch buffer ciphertext[]
  size_t TicketCipher
      = encrypt (plaintext, LenTkt, Kb->key, Kb->iv, ciphertext);

  fprintf (log,
           "KDC: created this session key Ks { Key , IV } (%lu Bytes ) is:\n",
           KEYSIZE);
  BIO_dump_indent_fp (log, Ks, KEYSIZE, 4);
  fprintf (log, "\n");

  fprintf (log, "Plaintext Ticket (%lu Bytes) is\n", LenTkt);
  BIO_dump_indent_fp (log, plaintext, LenTkt, 4);
  fprintf (log, "\n");

  //---------------------------------------------------------------------------------------
  // Construct the rest of Message 2 then encrypt it using Ka
  // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }
  // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na ||
  // lenTktCipher) || TktCipher Reuse that global array plaintext[] as a
  // scratch buffer for building the plaintext of the MSG2
  memset (plaintext, 0,
          PLAINTEXT_LEN_MAX); // Make sure the plaintext array is empty

  p = plaintext; // reuse pointer

  memcpy (p, Ks, KEYSIZE);
  p += KEYSIZE;
  LenUnEncr = KEYSIZE;

  memcpy (p, &lenB, LENSIZE);
  p += LENSIZE;
  LenUnEncr += LENSIZE;

  memcpy (p, IDb, lenB);
  p += lenB;
  LenUnEncr += lenB;

  memcpy (p, Na, NONCELEN);
  p += NONCELEN;
  LenUnEncr += NONCELEN;

  memcpy (p, &TicketCipher, LENSIZE);
  p += LENSIZE;
  LenUnEncr += LENSIZE;

  memcpy (p, ciphertext, TicketCipher);
  p += TicketCipher;
  LenUnEncr += TicketCipher;

  // Now, encrypt Message 2 using Ka.
  // Use the global scratch buffer ciphertext2[] to collect the results
  LenMsg2 = encrypt (plaintext, LenUnEncr, Ka->key, Ka->iv, ciphertext2);

  // allocate memory on behalf of the caller for a copy of MSG2 ciphertext
  *msg2 = malloc (LenMsg2);
  if (*msg2 == NULL)
    {
      exit (-1);
      return 0;
    }

  // Copy the encrypted ciphertext to Caller's msg2 buffer.
  memcpy (*msg2, ciphertext2, LenMsg2);

  fprintf (log,
           "The following Encrypted MSG2 ( %lu bytes ) has been"
           " created by MSG2_new():  \n",
           LenMsg2);
  BIO_dump_indent_fp (log, *msg2, LenMsg2, 4);
  fprintf (log, "\n");

  fprintf (log,
           "This is the content of MSG2 ( %lu Bytes ) before Encryption:\n",
           LenUnEncr);
  fprintf (log, "    Ks { key + IV } (%lu Bytes) is:\n", KEYSIZE);
  BIO_dump_indent_fp (log, Ks, KEYSIZE, 4);
  fprintf (log, "\n");

  fprintf (log, "    IDb (%lu Bytes) is:\n", lenB);
  BIO_dump_indent_fp (log, IDb, lenB, 4);
  fprintf (log, "\n");

  fprintf (log, "    Na (%lu Bytes) is:\n", NONCELEN);
  BIO_dump_indent_fp (log, Na, NONCELEN, 4);
  fprintf (log, "\n");

  fprintf (log, "    Encrypted Ticket (%lu Bytes) is\n", TicketCipher);
  BIO_dump_indent_fp (log, ciphertext, TicketCipher, 4);
  fprintf (log, "\n");

  fflush (log);

  return LenMsg2;
}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void
MSG2_receive (FILE *log, int fd, const myKey_t *Ka, myKey_t *Ks, char **IDb,
              Nonce_t *Na, size_t *lenTktCipher, uint8_t **tktCipher)
{
  size_t LenMSG2, lenB;
  if (read (fd, &LenMSG2, LENSIZE) <= 0)
    {
      fprintf (log, "Failed to read in Length of MSG2\n");
      fflush (log);
      exitError ("Failed to read length of MSG2\n");
    }

  uint8_t *msg2 = malloc (LenMSG2);

  if (!msg2)
    {
      fprintf (log, "Unable to allocate memory to MSG2 buffer\n");
      fflush (log);
      exitError ("Failed to allocate memory to MSG2\n");
    }

  if (read (fd, msg2, LenMSG2) <= 0)
    {
      fprintf (log, "Failed to read MSG2\n");
      fflush (log);
      exitError ("Failed to read MSG2\n");
    }

  fprintf (log,
           "MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) "
           "Successfully\n",
           LenMSG2);

  BIO_dump_indent_fp (log, msg2, LenMSG2, 4);
  fprintf (log, "\n");

  memset (plaintext, 0,
          PLAINTEXT_LEN_MAX); // Ensure the plaintext array is empty

  size_t decrypt_len = decrypt (msg2, LenMSG2, Ka->key, Ka->iv,
                                plaintext); // Decrypted into plaintext
  if (decrypt_len == 0)
    {
      fprintf (log, "Failed to decrypt MSG2\n");
      fflush (log);
      exitError ("Failed to decrypt MSG2\n");
    }

  uint8_t *p = plaintext; // Begin moving through the plain text
  // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

  memcpy (Ks, p, KEYSIZE);
  p += KEYSIZE;

  memcpy (&lenB, p, LENSIZE);
  p += LENSIZE;
  *IDb = malloc (lenB);

  memcpy (*IDb, p, lenB);
  p += lenB;

  memcpy (*Na, p, NONCELEN);
  p += NONCELEN;

  memcpy (lenTktCipher, p, LENSIZE);
  p += LENSIZE;

  *tktCipher = malloc (*lenTktCipher);

  memcpy (*tktCipher, p, *lenTktCipher);

  memset (plaintext, 0, PLAINTEXT_LEN_MAX); // Clear the PLAINTEXT for next use

  fprintf (log,
           "Amal decrypted message 2 from the KDC into the following:\n"
           "    Ks { Key , IV } (%lu Bytes ) is:\n",
           KEYSIZE);
  BIO_dump_indent_fp (log, Ks, KEYSIZE, 4);
  fprintf (log, "\n");
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t
MSG3_new (FILE *log, uint8_t **msg3, const size_t lenTktCipher,
          const uint8_t *tktCipher, const Nonce_t *Na2)
{

  size_t LenMsg3 = LENSIZE + lenTktCipher + NONCELEN;
  *msg3 = malloc (LenMsg3);
  if (!msg3)
    {
      fprintf (log, "Failed to allocate memory for msg3");
      exitError ("Failed to allocate memory for msg3");
    }
  uint8_t *p = *msg3;

  memcpy (p, &lenTktCipher, LENSIZE);
  p += LENSIZE;

  memcpy (p, tktCipher, lenTktCipher);
  p += lenTktCipher;

  memcpy (p, Na2, NONCELEN);
  p += NONCELEN;

  fprintf (log,
           "The following MSG3 ( %lu bytes ) has been created by "
           "MSG3_new ():\n",
           LenMsg3);

  BIO_dump_indent_fp (log, *msg3, LenMsg3, 4);
  fprintf (log, "\n");
  fflush (log);

  return (LenMsg3);
}

// //-----------------------------------------------------------------------------
// // Receive Message #3 by Basim from Amal
// // Parse the incoming msg3 into its components Ks , IDa , and Na2
// // The buffers for Kb, Ks, and Na2 are pre-created by the caller
// // The value of Kb is set by the caller
// // The buffer for IDA is to be allocated here into *IDa

void
MSG3_receive (FILE *log, int fd, const myKey_t *Kb, myKey_t *Ks, char **IDa,
              Nonce_t *Na2)
{
  size_t lenTktCipher, lenA;

  if (read (fd, &lenTktCipher, LENSIZE) == -1)
    {
      fprintf (log, "\nFailed to read length of TicketCipher\n");
      exitError ("\nFailed to read length of TicketCipher\n");
    }

  memset (ciphertext, 0,
          CIPHER_LEN_MAX); // Make sure the ciphertext is cleared before read
  if (read (fd, ciphertext, lenTktCipher)
      == -1) // Use ciphertext as buffer for Ticket Cipher
    {
      fprintf (log, "Failed to read Ticket Cipher\n");
      exitError ("\nFailed to read Ticket Cipher\n");
    }

  if (read (fd, Na2, NONCELEN) == -1) // Read directly into Na2
    {
      fprintf (log, "Failed to read Na2\n");
      exitError ("\nFailed to read Na2\n");
    }

  fprintf (log,
           "The following Encrypted TktCipher ( %lu bytes ) was received by "
           "MSG3_receive()\n",
           lenTktCipher);
  BIO_dump_indent_fp (log, ciphertext, lenTktCipher, 4);
  fprintf (log, "\n");
  fflush (log);

  memset (decryptext, 0,
          DECRYPTED_LEN_MAX); // Make sure the decryptext is cleared
  size_t lenTktPlain
      = decrypt (ciphertext, lenTktCipher, Kb->key, Kb->iv, decryptext);

  fprintf (log,
           "Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n",
           lenTktPlain);
  BIO_dump_indent_fp (log, decryptext, lenTktPlain, 4);
  fprintf (log, "\n");

  // Begin parsing the plain ticket
  uint8_t *p = decryptext;

  memcpy (Ks, p, KEYSIZE);
  p += KEYSIZE;

  memcpy (&lenA, p, LENSIZE);
  p += LENSIZE;

  *IDa = malloc (lenA); // Allocate memory to IDa
  memcpy (*IDa, p, lenA);

  fflush (log);
  memset (ciphertext, 0, CIPHER_LEN_MAX);
  memset (decryptext, 0, DECRYPTED_LEN_MAX);
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t
MSG4_new (FILE *log, uint8_t **msg4, const myKey_t *Ks, Nonce_t *fNa2,
          Nonce_t *Nb)
{

  size_t LenMsg4;

  // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
  // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill
  // it in with component values
  memset (plaintext, 0, PLAINTEXT_LEN_MAX);

  uint8_t *p = plaintext;
  memcpy (p, fNa2, NONCELEN);
  p += NONCELEN;

  memcpy (p, Nb, NONCELEN);

  // Now, encrypt MSG4 plaintext using the session key Ks;
  // Use the global scratch buffer ciphertext[] to collect the result.
  // Make sure it fits.

  memset (ciphertext, 0, CIPHER_LEN_MAX);

  LenMsg4 = encrypt (plaintext, NONCELEN << 1, Ks->key, Ks->iv, ciphertext);

  // Now allocate a buffer for the caller, and copy the encrypted MSG4 to
  // it
  *msg4 = malloc (LenMsg4);

  if (!msg4)
    {
      fprintf (log, "\nFailed to allocate memory for Message 4\n");
      exitError ("\nFailed to allocate memory for Message 4\n");
    }

  memcpy (*msg4, ciphertext, LenMsg4);

  fprintf (log,
           "The following Encrypted MSG4 ( %lu bytes ) has been"
           " created by MSG4_new ():  \n",
           LenMsg4);
  BIO_dump_indent_fp (log, *msg4, LenMsg4, 4);

  return LenMsg4;
}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void
MSG4_receive (FILE *log, int fd, const myKey_t *Ks, Nonce_t *rcvd_fNa2,
              Nonce_t *Nb)
{
  size_t lenMsg4, lenPln;

  if (read (fd, &lenMsg4, LENSIZE) == -1)
    {
      fprintf (log, "\nFailed to read length of msg4");
      exitError ("\nFailed to read length of msg4");
    }

  if (read (fd, ciphertext, lenMsg4) == -1)
    {
      fprintf (log, "\nFailed to read msg4 into ciphertext\n");
      exitError ("\nFailed to read msg4 into ciphertext\n");
    }

  fprintf (log, "The following Encrypted MSG4 ( %lu bytes ) was received:\n",
           lenMsg4);

  BIO_dump_indent_fp (log, ciphertext, lenMsg4, 4);
  fprintf (log, "\n");

  lenPln = decrypt (ciphertext, lenMsg4, Ks->key, Ks->iv, decryptext);

  uint8_t *p = decryptext;

  memcpy (rcvd_fNa2, p, NONCELEN);
  p += NONCELEN;

  memcpy (Nb, p, NONCELEN);

  memset (decryptext, 0, DECRYPTED_LEN_MAX);
  memset (ciphertext, 0, CIPHER_LEN_MAX);
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t
MSG5_new (FILE *log, uint8_t **msg5, const myKey_t *Ks, Nonce_t *fNb)
{
  size_t LenMSG5cipher;

  // Construct MSG5 Plaintext  = {  f(Nb)  }
  // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make
  // sure it fits
  memset (plaintext, 0, PLAINTEXT_LEN_MAX);
  memcpy (plaintext, fNb, NONCELEN);

  // Now, encrypt( Ks , {plaintext} );
  // Use the global scratch buffer ciphertext[] to collect result. Make
  // sure it fits.
  memset (ciphertext, 0, CIPHER_LEN_MAX);
  LenMSG5cipher = encrypt (plaintext, NONCELEN, Ks->key, Ks->iv, ciphertext);

  // Now allocate a buffer for the caller, and copy the encrypted MSG5 to
  // it
  *msg5 = malloc (LenMSG5cipher);
  memcpy (*msg5, ciphertext, LenMSG5cipher);

  fprintf (log,
           "The following Encrypted MSG5 ( %lu bytes ) has been"
           " created by MSG5_new ():  \n",
           LenMSG5cipher);
  BIO_dump_indent_fp (log, *msg5, LenMSG5cipher, 4);
  fprintf (log, "\n");
  fflush (log);

  return LenMSG5cipher;
}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void
MSG5_receive (FILE *log, int fd, const myKey_t *Ks, Nonce_t *fNb)
{

  size_t LenMSG5cipher;

  // Read Len( Msg5 ) followed by reading Msg5 itself
  // Always make sure read() and write() succeed
  if (read (fd, &LenMSG5cipher, LENSIZE) == -1)
    {
      fprintf (log, "\nFailed to read length of MSG5\n");
      exitError ("\nFailed to read length of MSG5\n");
    }

  // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
  // Make sure it fits.
  memset (ciphertext, 0, CIPHER_LEN_MAX);
  if (read (fd, ciphertext, LenMSG5cipher) == -1)
    {
      fprintf (log, "\nFailed to read MSG5 to ciphertext\n");
      exitError ("\nFailed to read MSG5 to ciphertext\n");
    }

  fprintf (log,
           "The following Encrypted MSG5 ( %lu bytes ) has been received:\n",
           LenMSG5cipher);
  BIO_dump_indent_fp (log, ciphertext, LenMSG5cipher, 4);
  fprintf (log, "\n");

  // Now, Decrypt MSG5 using Ks
  // Use the global scratch buffer decryptext[] to collect the results of
  // decryption Make sure it fits
  memset (decryptext, 0, DECRYPTED_LEN_MAX);
  size_t lenPln
      = decrypt (ciphertext, LenMSG5cipher, Ks->key, Ks->iv, decryptext);

  // Parse MSG5 into its components f( Nb )
  memcpy (fNb, decryptext, lenPln);
}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void
fNonce (Nonce_t r, Nonce_t n)
{
  // Note that the nonces are store in Big-Endian byte order
  // This affects how you do arithmetice on the nonces, e.g. when you add 1
  r[0] = htonl ((ntohl (n[0]) + 1) % (1LL << 32));
}
