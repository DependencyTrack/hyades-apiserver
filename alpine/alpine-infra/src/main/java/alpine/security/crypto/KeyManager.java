/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.security.crypto;

import alpine.Config;
import alpine.common.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamConstants;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Class that manages Alpine-generated default secret key.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class KeyManager {

    /**
     * Defines the type of key.
     */
    enum KeyType {
        SECRET
    }

    private static final Logger LOGGER = Logger.getLogger(KeyManager.class);
    private static final KeyManager INSTANCE = new KeyManager();
    private final Lock lock = new ReentrantLock();
    private volatile SecretKey secretKey;

    /**
     * Private constructor.
     */
    private KeyManager() {
        initialize();
    }

    /**
     * Returns an INSTANCE of the KeyManager.
     *
     * @return an instance of the KeyManager
     * @since 1.0.0
     */
    public static KeyManager getInstance() {
        return INSTANCE;
    }

    /**
     * Initializes the KeyManager
     */
    private void initialize() {
        lock.lock();
        try {
            createKeysIfNotExist();
            if (secretKey == null) {
                try {
                    if (secretKeyHasOldFormat()) {
                        loadSecretKey();
                    } else {
                        loadEncodedSecretKey();
                    }
                } catch (IOException | ClassNotFoundException e) {
                    LOGGER.error("An error occurred loading secret key", e);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Checks if the keys exists. If not, they will be created.
     */
    private void createKeysIfNotExist() {
        if (!secretKeyExists()) {
            try {
                final SecretKey secretKey = generateSecretKey();
                saveEncoded(secretKey);
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("An error occurred generating new secret key", e);
            } catch (IOException e) {
                LOGGER.error("An error occurred saving newly generated secret key", e);
            }
        }
    }

    /**
     * Generates a secret key.
     *
     * @return a SecretKey
     * @throws NoSuchAlgorithmException if the algorithm cannot be found
     * @since 1.0.0
     */
    SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        lock.lock();
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.init(256, random);
            return this.secretKey = keyGen.generateKey();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieves the path where the keys should be stored.
     * @param keyType the type of key
     * @return a File representing the path to the key
     */
    private File getKeyPath(final KeyType keyType) {
        if (keyType == KeyType.SECRET) {
            final String secretKeyPath = Config.getInstance().getProperty(Config.AlpineKey.SECRET_KEY_PATH);
            if (secretKeyPath != null) {
                return Paths.get(secretKeyPath).toFile();
            }
        }
        return new File(Config.getInstance().getDataDirectorty()
                + File.separator
                + "keys" + File.separator
                + keyType.name().toLowerCase() + ".key");
    }

    /**
     * Given the type of key, this method will return the File path to that key.
     * @param key the type of key
     * @return a File representing the path to the key
     */
    private File getKeyPath(final Key key) {
        KeyType keyType = null;
        if (key instanceof SecretKey) {
            keyType = KeyType.SECRET;
        }
        return getKeyPath(keyType);
    }

    /**
     * Saves a secret key.
     *
     * @param key the SecretKey to save
     * @throws IOException if the file cannot be written
     * @since 1.0.0
     * @deprecated Use {@link #saveEncoded(SecretKey)} instead
     */
    @Deprecated(forRemoval = true)
    void save(final SecretKey key) throws IOException {
        lock.lock();
        try {
            final File keyFile = getKeyPath(key);
            keyFile.getParentFile().mkdirs(); // make directories if they do not exist
            try (OutputStream fos = Files.newOutputStream(keyFile.toPath());
                 ObjectOutputStream oout = new ObjectOutputStream(fos)) {
                oout.writeObject(key);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Saves a secret key in encoded format.
     *
     * @param key the SecretKey to save
     * @throws IOException if the file cannot be written
     * @since 2.2.0
     */
    void saveEncoded(final SecretKey key) throws IOException {
        lock.lock();
        try {
            final File keyFile = getKeyPath(key);
            keyFile.getParentFile().mkdirs(); // make directories if they do not exist
            try (OutputStream fos = Files.newOutputStream(keyFile.toPath())) {
                fos.write(key.getEncoded());
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Loads the secret key.
     * @return a SecretKey
     * @throws IOException            if the file cannot be read
     * @throws ClassNotFoundException if deserialization of the SecretKey fails
     * @deprecated Use {@link #loadEncodedSecretKey()}
     */
    @Deprecated(forRemoval = true)
    SecretKey loadSecretKey() throws IOException, ClassNotFoundException {
        final File file = getKeyPath(KeyType.SECRET);
        SecretKey key;
        try (InputStream fis = Files.newInputStream(file.toPath());
             ObjectInputStream ois = new ObjectInputStream(fis)) {

            key = (SecretKey) ois.readObject();
        }
        return this.secretKey = key;
    }

    /**
     * Loads the encoded secret key.
     *
     * @return a SecretKey
     * @throws IOException if the file cannot be read
     * @since 2.2.0
     */
    SecretKey loadEncodedSecretKey() throws IOException {
        final File file = getKeyPath(KeyType.SECRET);
        try (InputStream fis = Files.newInputStream(file.toPath())) {
            final byte[] encodedKey = fis.readAllBytes();
            return this.secretKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        }
    }

    /**
     * Checks to see if the secret key exists.
     *
     * @return true if secret key exists, false if not
     * @since 1.0.0
     */
    boolean secretKeyExists() {
        return getKeyPath(KeyType.SECRET).exists();
    }

    /**
     * Checks if the secret key was stored in the old Java Object Serialization format.
     *
     * @return {@code true} when the old format is detected, otherwise {@code false}
     * @throws IOException When reading the secret key file could not be read
     * @since 2.2.0
     */
    boolean secretKeyHasOldFormat() throws IOException {
        try (final InputStream fis = Files.newInputStream(getKeyPath(KeyType.SECRET).toPath())) {
            return ByteBuffer.wrap(fis.readNBytes(2)).getShort() == ObjectStreamConstants.STREAM_MAGIC;
        }
    }

    /**
     * Returns the secret key.
     *
     * @return the SecretKey
     * @since 1.0.0
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

}
