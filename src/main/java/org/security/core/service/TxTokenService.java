package org.security.core.service;

/**
 * @author David Ruiz Coronel
 * @since 14/12/2015
 */
public interface TxTokenService {

    /**
     * Metodo para validar codificacion y hash
     * @param hash
     * @param token
     * @throws Exception
     */
    void checkHash(String hash, String token) throws Exception;

    /**
     * Metodo para extraer informacion codificada
     * @param hash
     * @return
     */
    String unhash64(String hash);

}
