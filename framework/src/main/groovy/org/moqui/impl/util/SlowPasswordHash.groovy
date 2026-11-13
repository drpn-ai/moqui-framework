/*
 * This software is in the public domain under CC0 1.0 Universal plus a
 * Grant of Patent License.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software (see the LICENSE.md file). If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
package org.moqui.impl.util

import groovy.transform.CompileStatic
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SaltedAuthenticationInfo
import org.apache.shiro.authc.credential.CredentialsMatcher
import org.apache.shiro.lang.util.ByteSource
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Slow password hash: PBKDF2-HMAC-SHA256 from the JDK (no added dependency).
 *
 * The stored hash type carries the iteration count ("PBKDF2WithHmacSHA256:600000"), so a hash stays verifiable
 * after the configured count changes, and the comparisons that re-hash a candidate with a row's own salt and
 * type (password history, "same as current", reset password) stay deterministic. Hashes are 256-bit, hex encoded.
 *
 * Plain digest types (SHA-256 etc, Shiro SimpleHash) are untouched; this class only handles its own type.
 */
@CompileStatic
class SlowPasswordHash {
    protected final static Logger logger = LoggerFactory.getLogger(SlowPasswordHash.class)

    static final String ALGORITHM = "PBKDF2WithHmacSHA256"
    static final String TYPE_PREFIX = ALGORITHM + ":"
    static final int DEFAULT_ITERATIONS = 600_000
    static final int KEY_BITS = 256

    static boolean isSlowType(String hashType) { return hashType != null && hashType.startsWith(TYPE_PREFIX) }

    static String typeFor(int iterations) {
        if (iterations < 1) throw new IllegalArgumentException("${ALGORITHM} iterations must be positive, got ${iterations}")
        return TYPE_PREFIX + iterations
    }

    static int iterationsOf(String hashType) {
        if (!isSlowType(hashType)) throw new IllegalArgumentException("Not a ${ALGORITHM} hash type: ${hashType}")
        int iterations
        try {
            iterations = Integer.parseInt(hashType.substring(TYPE_PREFIX.length()))
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Hash type ${hashType} has no valid iteration count", e)
        }
        if (iterations < 1) throw new IllegalArgumentException("Hash type ${hashType} has no valid iteration count")
        return iterations
    }

    static String hash(String source, String salt, String hashType) {
        return hash(source, salt != null ? salt.getBytes(StandardCharsets.UTF_8) : null, hashType)
    }

    /** Every password set under this type gets a fresh random salt. An empty salt only reaches here from a row
     *  whose salt was cleared while its type stayed (or a comparison against such a row); PBEKeySpec refuses an
     *  empty salt, so a fixed one is used instead of failing the password service that asked. */
    static String hash(String source, byte[] salt, String hashType) {
        if (salt == null || salt.length == 0) salt = TYPE_PREFIX.getBytes(StandardCharsets.US_ASCII)
        char[] chars = (source ?: "").toCharArray()
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterationsOf(hashType), KEY_BITS)
        try {
            byte[] key = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded()
            return key.encodeHex().toString()
        } finally {
            spec.clearPassword()
            Arrays.fill(chars, (char) 0)
        }
    }

    /** Shiro matcher for a stored hash of this type. Never throws: a malformed row is a non-match. */
    static class Matcher implements CredentialsMatcher {
        final String hashType
        Matcher(String hashType) { this.hashType = hashType }

        @Override
        boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
            try {
                String submitted = credentialString(token?.getCredentials())
                String stored = credentialString(info?.getCredentials())
                if (submitted == null || stored == null || stored.isEmpty()) return false
                byte[] salt = null
                if (info instanceof SaltedAuthenticationInfo) {
                    ByteSource saltBs = ((SaltedAuthenticationInfo) info).getCredentialsSalt()
                    if (saltBs != null) salt = saltBs.getBytes()
                }
                String computed = hash(submitted, salt, hashType)
                return MessageDigest.isEqual(computed.getBytes(StandardCharsets.US_ASCII),
                        stored.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII))
            } catch (Exception e) {
                logger.warn("Could not check a ${ALGORITHM} password hash, treating it as a non-match: ${e.toString()}")
                return false
            }
        }
    }

    static String credentialString(Object credentials) {
        if (credentials == null) return null
        if (credentials instanceof char[]) return new String((char[]) credentials)
        if (credentials instanceof byte[]) return new String((byte[]) credentials, StandardCharsets.UTF_8)
        if (credentials instanceof ByteSource) return new String(((ByteSource) credentials).getBytes(), StandardCharsets.UTF_8)
        return credentials.toString()
    }
}
