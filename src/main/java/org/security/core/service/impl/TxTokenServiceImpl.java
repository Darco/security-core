package org.security.core.service.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.security.core.service.TxTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Implementacion de algoritmos para el aseguramiento de transacciones
 *
 * @author David Ruiz Coronel
 * @since 02/09/2015
 */
public class TxTokenServiceImpl implements TxTokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TxTokenServiceImpl.class);

    private static final int P = 31;

    /**
     * @param map
     * @return
     */
    public String generateStringChain(Map<String, String> map) {
        StringBuilder builder = new StringBuilder();
        map.remove("seEncripta");
        map.remove("tipoProceso");
        for (String value : map.values()) {
            builder.append(value);
        }

        LOGGER.debug("Chain con todos los parametros: " + builder.toString());
        return builder.toString();
    }

    public String getHashCode(String text) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        LOGGER.debug("getHashCode :" + text);
        String hashedPassword = passwordEncoder.encode(text);
        return hashedPassword;
    }

//    public StrongTextEncryptor getStrongTextEncryptor(final String key) {
//        final StrongTextEncryptor textEncryptor = new StrongTextEncryptor();
//        textEncryptor.setPassword(key);
//        return textEncryptor;
//    }

//    public String encrypt(String message, String key) {
//        return this.getStrongTextEncryptor(key).encrypt(message);
//    }
//
//    public String decrypt(String encryptedMessage, String key) {
//        return this.getStrongTextEncryptor(key).decrypt(encryptedMessage);
//    }

    /**
     * Decodificador
     *
     * @param encoded
     *            Los datos codificados
     * @return Los datos decodificados
     */
    public String decode(String encoded) {
        return new String(Base64.decodeBase64(encoded.getBytes()));
    }

    /**
     * Codificador
     *
     * @param decoded
     *            Los datos decodificados
     * @return Los datos codificados
     */
    public String encode(String decoded) {
        return new String(Base64.encodeBase64(decoded.getBytes()));
    }

    /**
     * Obtencion del cifrador
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256");
    }

    /**
     * Extraccion del dato original, una vez decodificado.
     *
     * @param hash
     *            Los datos cifrados
     * @return String con los datos originales
     */
    public String getOriginal(String hash) {
        //final String begin = hash.substring(0, P);
        final String original = hash.substring(P, hash.lastIndexOf("}") + 1);
        //final String end = hash.substring(hash.lastIndexOf("}") + 1, hash.length());
        //LOGGER.debug("{} : {} : {}", begin, original, end);
        return original;
    }

    /**
     * Cifrado de datos.
     *
     * @param original
     *            Los datos a cifrar
     * @param token
     *            Los datos para cifrar
     * @return Los datos cifrados
     * @throws Exception
     *             En caso de que no existan los algoritmos
     */
    public String hash(String original, String token) throws Exception {
        String hash = null;
        try {
            final String nonHash = original + token;
            MessageDigest digest = this.getMessageDigest();
            digest.update(nonHash.getBytes());
            // hash = new BigInteger(1, digest.digest()).toString(16);
            // hash = String.format("%02X", new BigInteger(digest.digest()));
            hash = new String(Hex.encodeHex(digest.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception(e);
        }
        return hash;
    }

    public Boolean compareHashCode(String text, String hashCode) {
        LOGGER.debug("compareHashCode " + text);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        // if (passwordEncoder.matches(text, hashCode)) {
        // return true;
        // }
        // return false;
        return passwordEncoder.matches(text, hashCode);
    }

    /**
     * Validacion de la autenticidad de los datos
     *
     * @param hash
     *            Los datos codificados y cifrados
     * @param token
     *            Valor para codificar y cifrar
     * @throws Exception
     *             En caso de que la verificacion de datos falle
     */
    public void checkHash(String hash, String token) throws Exception {
        final String hash64 = this.hash64(this.unhash64(hash), token);
        if (!hash64.equals(hash)) {
            throw new Exception("Imposible verificar autenticidad de la transaccion");
        }
    }

    /**
     * Decodificacion y extraccion de datos.
     *
     * @param hash
     *            Datos codificados y cifrados
     * @return Los datos decodificados y descifrados
     */
    public String unhash64(String hash) {
        final String decoded = this.decode(hash);
        LOGGER.debug("decoded : {}", decoded);
        final String original = this.getOriginal(decoded);
        LOGGER.debug("original : {}", original);
        return original;
    }

    /**
     * Codificacion y cifrado de datos.
     *
     * @param original
     *            Los datos a codificar y cifrar
     * @param token
     *            Los datos para codificar y cifrar
     * @return Los datos codificados y cifrados
     * @throws Exception
     *             En caso de no poder codificar y/o cifrar
     */
    public String hash64(String original, String token) throws Exception {

        final String hashed = this.hash(original, token);
        LOGGER.debug("hashed : {}", hashed);
        final String insert = this.insertData(hashed, original);
        LOGGER.debug("insert : {}", insert);
        final String hashed64 = this.encode(insert);
        LOGGER.debug("hashed64 : {}", hashed64);
        return hashed64;
    }

    /**
     * Insercion de datos
     *
     * @param target
     * @param source
     * @return
     */
    public String insertData(String target, String source) {
        final StringBuilder builder = new StringBuilder(target);
        final String insert = builder.insert(P, source).toString();
        return insert;
    }
}
