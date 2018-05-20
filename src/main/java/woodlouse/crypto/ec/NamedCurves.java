/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.math.BigInteger;
import java.util.HashMap;

import bouncycastle.crypto.params.ECDomainParameters;
import bouncycastle.math.ec.ECCurve;
import bouncycastle.util.encoders.Hex;

/**
 * The ECC-Brainpool "r1" curves for 224 bit and above.
 */
final class NamedCurves {

   private NamedCurves() {
      throw new AssertionError();
   }

   /*
    * Mapping from OID to ECDomain
    */
   private static final HashMap<String, ECDomain> curves = new HashMap<String, ECDomain>();

   /*
    * Mapping from key size (in bits) to ECDomain
    */
   private static final HashMap<Integer, ECDomain> bySize = new HashMap<Integer, ECDomain>();

   /**
    * Get an ECDomain by its OID.
    * 
    * @param oid
    *           the OID of the EC domain.
    * @return the ECDomain (if found), otherwise {@code null}.
    */
   static ECDomain getByOid(final String oid) {
      return curves.get(oid);
   }

   /**
    * Get an ECDomain by its key size.
    * 
    * @param keyLengthInBits
    *           requested key size in bits.
    * @return the ECDomain (if found), otherwise {@code null}.
    */
   static ECDomain getByKeySize(final int keyLengthInBits) {
      return bySize.get(Integer.valueOf(keyLengthInBits));
   }

   private static final class BrainpoolP512r1 extends ECDomain {
      private static final int KEY_LEN = 512;
      private static final String OID = "1.3.36.3.3.2.8.1.1.13 (512 bit)";

      @Override
      protected final ECDomainParameters initializeDomain() {
         final ECCurve curve = new ECCurve.Fp(new BigInteger(
               "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16), // q
               new BigInteger(
                     "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16), // a
               new BigInteger(
                     "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16)); // b

         return new ECDomainParameters(
               curve,
               curve.decodePoint(Hex
                     .decode("0481AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892")), // G
               new BigInteger(
                     "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16)); // n
      }

      @Override
      protected final String getOid() {
         return OID;
      }

      @Override
      protected final int getKeyLength() {
         return KEY_LEN;
      }
   }

   private static final class BrainpoolP384r1 extends ECDomain {
      private static final int KEY_LEN = 384;
      private static final String OID = "1.3.36.3.3.2.8.1.1.11 (384 bit)";

      @Override
      protected final ECDomainParameters initializeDomain() {
         final ECCurve curve = new ECCurve.Fp(new BigInteger(
               "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16), // q
               new BigInteger("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16), // a
               new BigInteger("4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16)); // b

         return new ECDomainParameters(
               curve,
               curve.decodePoint(Hex
                     .decode("041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315")), // G
               new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16)); // n
      }

      @Override
      protected final String getOid() {
         return OID;
      }

      @Override
      protected final int getKeyLength() {
         return KEY_LEN;
      }
   }

   private static final class BrainpoolP320r1 extends ECDomain {
      private static final int KEY_LEN = 320;
      private static final String OID = ECDomain.DEFAULT_CURVE;

      @Override
      protected final ECDomainParameters initializeDomain() {
         final ECCurve curve = new ECCurve.Fp(new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", 16), // q
               new BigInteger("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", 16), // a
               new BigInteger("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", 16)); // b

         return new ECDomainParameters(
               curve,
               curve.decodePoint(Hex
                     .decode("0443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1")), // G
               new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", 16)); // n
      }

      @Override
      protected final String getOid() {
         return OID;
      }

      @Override
      protected final int getKeyLength() {
         return KEY_LEN;
      }
   }

   private static final class BrainpoolP256r1 extends ECDomain {
      private static final int KEY_LEN = 256;
      private static final String OID = "1.3.36.3.3.2.8.1.1.7 (256 bit)";

      @Override
      protected final ECDomainParameters initializeDomain() {
         final ECCurve curve = new ECCurve.Fp(new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16), // q
               new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16), // a
               new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16)); // b

         return new ECDomainParameters(curve, curve.decodePoint(Hex
               .decode("048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997")), // G
               new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)); // n
      }

      @Override
      protected final String getOid() {
         return OID;
      }

      @Override
      protected final int getKeyLength() {
         return KEY_LEN;
      }
   }

   private static final class BrainpoolP224r1 extends ECDomain {
      private static final int KEY_LEN = 224;
      private static final String OID = "1.3.36.3.3.2.8.1.1.5 (224 bit)";

      @Override
      protected final ECDomainParameters initializeDomain() {
         final ECCurve curve = new ECCurve.Fp(new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16), // q
               new BigInteger("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", 16), // a
               new BigInteger("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", 16)); // b

         return new ECDomainParameters(curve, curve.decodePoint(Hex
               .decode("040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD")), // G
               new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16)); // n
      }

      @Override
      protected final String getOid() {
         return OID;
      }

      @Override
      protected final int getKeyLength() {
         return KEY_LEN;
      }
   }

   static {
      curves.put(BrainpoolP512r1.OID, new BrainpoolP512r1());
      curves.put(BrainpoolP384r1.OID, new BrainpoolP384r1());
      curves.put(BrainpoolP320r1.OID, new BrainpoolP320r1());
      curves.put(BrainpoolP256r1.OID, new BrainpoolP256r1());
      curves.put(BrainpoolP224r1.OID, new BrainpoolP224r1());

      bySize.put(Integer.valueOf(224), curves.get(BrainpoolP224r1.OID));
      bySize.put(Integer.valueOf(256), curves.get(BrainpoolP256r1.OID));
      bySize.put(Integer.valueOf(320), curves.get(BrainpoolP320r1.OID));
      bySize.put(Integer.valueOf(384), curves.get(BrainpoolP384r1.OID));
      bySize.put(Integer.valueOf(512), curves.get(BrainpoolP512r1.OID));
   }
}
