/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.util;

/**
 * Tooling for byte arrays.
 */
public final class ByteArrays {

   private static final byte[] EMPTY_BYTE_ARRAY = {};

   public static byte[] joinedArray(final byte[] prefix, final byte[] suffix) {
      if (prefix == null) {
         return suffix;
      }
      if (suffix == null) {
         return prefix;
      }
      final byte[] joinedArray = new byte[prefix.length + suffix.length];
      System.arraycopy(prefix, 0, joinedArray, 0, prefix.length);
      System.arraycopy(suffix, 0, joinedArray, prefix.length, suffix.length);
      return joinedArray;
   }

   /**
    * Produces a new <code>byte</code> array containing the elements between the
    * start and end indices.
    * <p>
    * The start index is inclusive, the end index exclusive. Null array input
    * produces null output.
    * </p>
    * 
    * @param array
    *           the array
    * @param startIdxInclusive
    *           the starting index. Undervalue (&lt;0) is promoted to 0,
    *           overvalue (&gt;array.length) results in an empty array.
    * @param endIdxExclusive
    *           elements up to endIndex-1 are present in the returned subarray.
    *           Undervalue (&lt; startIndex) produces empty array, overvalue
    *           (&gt;array.length) is demoted to array length.
    * @return a new array containing the elements between the start and end
    *         indices.
    */
   public static byte[] subArray(final byte[] array, int startIdxInclusive, int endIdxExclusive) {
      if (array == null) {
         return null;
      }
      if (startIdxInclusive < 0) {
         startIdxInclusive = 0;
      }
      if (endIdxExclusive > array.length) {
         endIdxExclusive = array.length;
      }
      final int newSize = endIdxExclusive - startIdxInclusive;
      if (newSize <= 0) {
         return EMPTY_BYTE_ARRAY;
      }
      final byte[] subArray = new byte[newSize];
      System.arraycopy(array, startIdxInclusive, subArray, 0, newSize);
      return subArray;
   }

   private ByteArrays() {
      throw new AssertionError();
   }
}
