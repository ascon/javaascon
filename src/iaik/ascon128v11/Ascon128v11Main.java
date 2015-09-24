package iaik.ascon128v11;

import iaik.ascon128v11.Ascon128v11;

public class Ascon128v11Main {
  public final static int MAXLEN = 65536;

  public static void main(String[] args) {

    int i;
    int MLEN = 1;
    if (args.length == 1)
      MLEN = Integer.decode(args[0]);

    int alen = MAXLEN;
    int mlen = MAXLEN;
    int clen = MAXLEN + Ascon128v11.CRYPTO_ABYTES;
    byte a[] = new byte[alen];
    byte m[] = new byte[mlen];
    byte c[] = new byte[m.length + Ascon128v11.CRYPTO_ABYTES];
    byte nsec[] = new byte[Ascon128v11.CRYPTO_NSECBYTES];
    byte npub[] =
        {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
            (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
            (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
    byte k[] =
        {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
            (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

    for (i = 0; i < MLEN; ++i)
      a[i] = (byte) ('A' + i % 26);
    for (i = 0; i < MLEN; ++i)
      m[i] = (byte) ('a' + i % 26);

    for (alen = 0; alen <= MLEN; ++alen)
      for (mlen = 0; mlen <= MLEN; ++mlen) {
        Ascon128v11.print("k", k, Ascon128v11.CRYPTO_KEYBYTES, 0);
        Ascon128v11.print("n", npub, Ascon128v11.CRYPTO_NPUBBYTES, 0);
        Ascon128v11.print("a", a, alen, 0);
        Ascon128v11.print("m", m, mlen, 0);
        clen = Ascon128v11.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
        Ascon128v11.print("c", c, clen - Ascon128v11.CRYPTO_ABYTES, 0);
        Ascon128v11.print("t", c, Ascon128v11.CRYPTO_ABYTES, clen - Ascon128v11.CRYPTO_ABYTES);
        mlen = Ascon128v11.crypto_aead_decrypt(m, mlen, nsec, c, clen, a, alen, npub, k);
        if (mlen != -1) {
          Ascon128v11.print("p", m, mlen, 0);
        } else
          System.out.printf("verification failed\n");
        System.out.printf("\n");
      }
    return;
  }

}
