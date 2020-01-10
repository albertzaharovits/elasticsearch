/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.repositories.encrypted;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.IndexCommit;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.metadata.RepositoryMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.blobstore.BlobContainer;
import org.elasticsearch.common.blobstore.BlobMetaData;
import org.elasticsearch.common.blobstore.BlobPath;
import org.elasticsearch.common.blobstore.BlobStore;
import org.elasticsearch.common.blobstore.DeleteResult;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.settings.ConsistentSettingsService;
import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.snapshots.IndexShardSnapshotStatus;
import org.elasticsearch.index.store.Store;
import org.elasticsearch.license.LicenseUtils;
import org.elasticsearch.repositories.IndexId;
import org.elasticsearch.repositories.RepositoryCleanupResult;
import org.elasticsearch.repositories.RepositoryException;
import org.elasticsearch.repositories.blobstore.BlobStoreRepository;
import org.elasticsearch.snapshots.SnapshotId;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class EncryptedRepository extends BlobStoreRepository {

    static final Logger logger = LogManager.getLogger(EncryptedRepository.class);
    static final int GCM_TAG_LENGTH_IN_BYTES = 16;
    static final int GCM_IV_LENGTH_IN_BYTES = 12;
    static final int AES_BLOCK_SIZE_IN_BYTES = 128;
    static final String DATA_ENCRYPTION_SCHEME = "AES/GCM/NoPadding";
    static final int DATA_KEY_SIZE_IN_BITS = 256;
    static final long PACKET_START_COUNTER = Long.MIN_VALUE;
    static final int MAX_PACKET_LENGTH_IN_BYTES = 1 << 20; // 1MB
    static final int PACKET_LENGTH_IN_BYTES = 64 * (1 << 10); // 64KB

    private static final String ENCRYPTION_METADATA_PREFIX = "encryption-metadata";

    private final BlobStoreRepository delegatedRepository;
    private final KeyGenerator dataEncryptionKeyGenerator;
    private final PasswordBasedEncryptor metadataEncryptor;
    private final ConsistentSettingsService consistentSettingsService;
    private final SecureRandom secureRandom;

    protected EncryptedRepository(RepositoryMetaData metadata, NamedXContentRegistry namedXContentRegistry, ClusterService clusterService,
                                  BlobStoreRepository delegatedRepository, PasswordBasedEncryptor metadataEncryptor,
                                  ConsistentSettingsService consistentSettingsService) throws NoSuchAlgorithmException {
        super(metadata, namedXContentRegistry, clusterService, delegatedRepository.basePath());
        this.delegatedRepository = delegatedRepository;
        this.dataEncryptionKeyGenerator = KeyGenerator.getInstance(EncryptedRepositoryPlugin.CIPHER_ALGO);
        this.dataEncryptionKeyGenerator.init(DATA_KEY_SIZE_IN_BITS, SecureRandom.getInstance(EncryptedRepositoryPlugin.RAND_ALGO));
        this.metadataEncryptor = metadataEncryptor;
        this.consistentSettingsService = consistentSettingsService;
        this.secureRandom = SecureRandom.getInstance(EncryptedRepositoryPlugin.RAND_ALGO);
    }

    @Override
    public void snapshotShard(Store store, MapperService mapperService, SnapshotId snapshotId, IndexId indexId,
                              IndexCommit snapshotIndexCommit, IndexShardSnapshotStatus snapshotStatus, boolean writeShardGens,
                              ActionListener<String> listener) {
        if (EncryptedRepositoryPlugin.getLicenseState().isEncryptedRepositoryAllowed()) {
            super.snapshotShard(store, mapperService, snapshotId, indexId, snapshotIndexCommit, snapshotStatus, writeShardGens, listener);
        } else {
            listener.onFailure(LicenseUtils.newComplianceException(
                    EncryptedRepositoryPlugin.REPOSITORY_TYPE_NAME + " snapshot repository"));
        }
    }

    @Override
    public void cleanup(long repositoryStateId, boolean writeShardGens, ActionListener<RepositoryCleanupResult> listener) {
        super.cleanup(repositoryStateId, writeShardGens, ActionListener.wrap(repositoryCleanupResult -> {
            EncryptedBlobContainerDecorator encryptedBlobContainer = (EncryptedBlobContainerDecorator) blobContainer();
            cleanUpOrphanedMetadataRecursively(encryptedBlobContainer);
            listener.onResponse(repositoryCleanupResult);
        }, listener::onFailure));
    }

    private void cleanUpOrphanedMetadataRecursively(EncryptedBlobContainerDecorator encryptedBlobContainer) throws IOException{
        encryptedBlobContainer.cleanUpOrphanedMetadata();
        for (BlobContainer childEncryptedBlobContainer : encryptedBlobContainer.children().values()) {
            try {
                cleanUpOrphanedMetadataRecursively((EncryptedBlobContainerDecorator) childEncryptedBlobContainer);
            } catch(IOException e) {
                logger.warn("Exception while cleaning up [" + childEncryptedBlobContainer.path() + "]", e);
            }
        }
    }

    @Override
    protected BlobStore createBlobStore() {
        return new EncryptedBlobStoreDecorator(this.delegatedRepository.blobStore(), dataEncryptionKeyGenerator, metadataEncryptor,
                secureRandom);
    }

    @Override
    protected void doStart() {
        SecureSetting<?> passwordSettingForThisRepo =
                (SecureSetting<?>) EncryptedRepositoryPlugin.ENCRYPTION_PASSWORD_SETTING.getConcreteSettingForNamespace(metadata.name());
        if (false == consistentSettingsService.isConsistent(passwordSettingForThisRepo)) {
            throw new RepositoryException(metadata.name(), "The value for the Secure setting [" + passwordSettingForThisRepo.getKey() +
                    "] does not match the master's");
        }
        this.delegatedRepository.start();
        super.doStart();
    }

    @Override
    protected void doStop() {
        super.doStop();
        this.delegatedRepository.stop();
    }

    @Override
    protected void doClose() {
        super.doClose();
        this.delegatedRepository.close();
    }

    private static class EncryptedBlobStoreDecorator implements BlobStore {

        private final BlobStore delegatedBlobStore;
        private final KeyGenerator dataEncryptionKeyGenerator;
        private final PasswordBasedEncryptor metadataEncryptor;
        private final SecureRandom secureRandom;

        EncryptedBlobStoreDecorator(BlobStore delegatedBlobStore, KeyGenerator dataEncryptionKeyGenerator,
                                    PasswordBasedEncryptor metadataEncryptor, SecureRandom secureRandom) {
            this.delegatedBlobStore = delegatedBlobStore;
            this.dataEncryptionKeyGenerator = dataEncryptionKeyGenerator;
            this.metadataEncryptor = metadataEncryptor;
            this.secureRandom = secureRandom;
        }

        @Override
        public void close() throws IOException {
            delegatedBlobStore.close();
        }

        @Override
        public BlobContainer blobContainer(BlobPath path) {
            return new EncryptedBlobContainerDecorator(delegatedBlobStore, path, dataEncryptionKeyGenerator, metadataEncryptor,
                    secureRandom);
        }
    }

    private static class EncryptedBlobContainerDecorator implements BlobContainer {

        private final BlobStore delegatedBlobStore;
        private final KeyGenerator dataEncryptionKeyGenerator;
        private final PasswordBasedEncryptor metadataEncryptor;
        private final SecureRandom secureRandom;
        private final BlobContainer delegatedBlobContainer;
        private final BlobContainer encryptionMetadataBlobContainer;

        EncryptedBlobContainerDecorator(BlobStore delegatedBlobStore, BlobPath path,
                                        KeyGenerator dataEncryptionKeyGenerator, PasswordBasedEncryptor metadataEncryptor,
                                        SecureRandom secureRandom) {
            this.delegatedBlobStore = delegatedBlobStore;
            this.dataEncryptionKeyGenerator = dataEncryptionKeyGenerator;
            this.metadataEncryptor = metadataEncryptor;
            this.secureRandom = secureRandom;
            this.delegatedBlobContainer = delegatedBlobStore.blobContainer(path);
            BlobPath encryptionMetadataBlobPath = path.prepend(ENCRYPTION_METADATA_PREFIX);
            this.encryptionMetadataBlobContainer = delegatedBlobStore.blobContainer(encryptionMetadataBlobPath);
        }

        @Override
        public BlobPath path() {
            return this.delegatedBlobContainer.path();
        }

        @Override
        public InputStream readBlob(String blobName) throws IOException {
            // read metadata
            BytesReference encryptedMetadataBytes = Streams.readFully(this.encryptionMetadataBlobContainer.readBlob(blobName));
            final byte[] decryptedMetadata;
            try {
                decryptedMetadata = metadataEncryptor.decrypt(BytesReference.toBytes(encryptedMetadataBytes));
            } catch (ExecutionException | GeneralSecurityException e) {
                throw new IOException("Exception while decrypting metadata", e);
            }
            final BlobEncryptionMetadata metadata = BlobEncryptionMetadata.deserializeMetadataFromByteArray(decryptedMetadata);
            // decrypt metadata
            SecretKey dataDecryptionKey = new SecretKeySpec(metadata.getDataEncryptionKeyMaterial(), 0,
                    metadata.getDataEncryptionKeyMaterial().length, "AES");
            // read and decrypt blob
            return new DecryptionPacketsInputStream(this.delegatedBlobContainer.readBlob(blobName), dataDecryptionKey,
                    metadata.getNonce(), metadata.getPacketLengthInBytes());
        }

        @Override
        public void writeBlob(String blobName, InputStream inputStream, long blobSize, boolean failIfAlreadyExists) throws IOException {
            SecretKey dataEncryptionKey = dataEncryptionKeyGenerator.generateKey();
            int nonce = secureRandom.nextInt();
            // this is the metadata required to decrypt back the encrypted blob
            BlobEncryptionMetadata metadata = new BlobEncryptionMetadata(dataEncryptionKey.getEncoded(), nonce, PACKET_LENGTH_IN_BYTES);
            // encrypt metadata
            final byte[] encryptedMetadata;
            try {
                encryptedMetadata = metadataEncryptor.encrypt(BlobEncryptionMetadata.serializeMetadataToByteArray(metadata));
            } catch (ExecutionException | GeneralSecurityException e) {
                throw new IOException("Exception while encrypting metadata", e);
            }
            // first write the encrypted metadata
            try (ByteArrayInputStream encryptedMetadataInputStream = new ByteArrayInputStream(encryptedMetadata)) {
                this.encryptionMetadataBlobContainer.writeBlob(blobName, encryptedMetadataInputStream, encryptedMetadata.length,
                        failIfAlreadyExists);
            }
            // afterwards write the encrypted data blob
            long encryptedBlobSize = EncryptionPacketsInputStream.getEncryptionLength(blobSize, PACKET_LENGTH_IN_BYTES);
            try (EncryptionPacketsInputStream encryptedInputStream = new EncryptionPacketsInputStream(inputStream,
                    dataEncryptionKey, nonce, PACKET_LENGTH_IN_BYTES)) {
                this.delegatedBlobContainer.writeBlob(blobName, encryptedInputStream, encryptedBlobSize, failIfAlreadyExists);
            }
        }

        @Override
        public void writeBlobAtomic(String blobName, InputStream inputStream, long blobSize, boolean failIfAlreadyExists)
                throws IOException {
            // the encrypted repository does not offer an alternative implementation for atomic writes
            // fallback to regular write
            writeBlob(blobName, inputStream, blobSize, failIfAlreadyExists);
        }

        @Override
        public DeleteResult delete() throws IOException {
            // first delete the encrypted data blob
            DeleteResult deleteResult = this.delegatedBlobContainer.delete();
            // then delete metadata
            this.encryptionMetadataBlobContainer.delete();
            return deleteResult;
        }

        @Override
        public void deleteBlobsIgnoringIfNotExists(List<String> blobNames) throws IOException {
            // first delete the encrypted data blob
            this.delegatedBlobContainer.deleteBlobsIgnoringIfNotExists(blobNames);
            // then delete metadata
            this.encryptionMetadataBlobContainer.deleteBlobsIgnoringIfNotExists(blobNames);
        }

        @Override
        public Map<String, BlobMetaData> listBlobs() throws IOException {
            // the encrypted data blob container is the source-of-truth for list operations
            // the metadata blob container mirrors its structure, but in some failure cases it might contain
            // additional orphaned metadata blobs
            // can list blobs that cannot be decrypted (because metadata is missing or corrupted)
            return this.delegatedBlobContainer.listBlobs();
        }

        @Override
        public Map<String, BlobContainer> children() throws IOException {
            // the encrypted data blob container is the source-of-truth for child container operations
            // the metadata blob container mirrors its structure, but in some failure cases it might contain
            // additional orphaned metadata blobs
            Map<String, BlobContainer> childEncryptedBlobContainers = this.delegatedBlobContainer.children();
            Map<String, BlobContainer> result = new HashMap<>(childEncryptedBlobContainers.size());
            for (Map.Entry<String, BlobContainer> encryptedBlobContainer : childEncryptedBlobContainers.entrySet()) {
                // get an encrypted blob container for each
                result.put(encryptedBlobContainer.getKey(), new EncryptedBlobContainerDecorator(this.delegatedBlobStore,
                        encryptedBlobContainer.getValue().path(), dataEncryptionKeyGenerator, metadataEncryptor, secureRandom));
            }
            return result;
        }

        @Override
        public Map<String, BlobMetaData> listBlobsByPrefix(String blobNamePrefix) throws IOException {
            // the encrypted data blob container is the source-of-truth for list operations
            // the metadata blob container mirrors its structure, but in some failure cases it might contain
            // additional orphaned metadata blobs
            // can list blobs that cannot be decrypted (because metadata is missing or corrupted)
            return this.delegatedBlobContainer.listBlobsByPrefix(blobNamePrefix);
        }

        public void cleanUpOrphanedMetadata() throws IOException{
            // delete encryption metadata blobs which don't pair with any data blobs
            Set<String> foundEncryptedBlobs = this.delegatedBlobContainer.listBlobs().keySet();
            Set<String> foundMetadataBlobs = this.encryptionMetadataBlobContainer.listBlobs().keySet();
            List<String> orphanedMetadataBlobs = new ArrayList<>(foundMetadataBlobs);
            orphanedMetadataBlobs.removeAll(foundEncryptedBlobs);
            try {
                this.encryptionMetadataBlobContainer.deleteBlobsIgnoringIfNotExists(orphanedMetadataBlobs);
            } catch (IOException e) {
                logger.warn("Exception while deleting orphaned metadata blobs " + orphanedMetadataBlobs, e);
            }
            // delete Encryption metadata blob containers which don't par with any data blob containers
            Set<String> foundEncryptedBlobContainers = this.delegatedBlobContainer.children().keySet();
            Map<String, BlobContainer> foundMetadataBlobContainers = this.encryptionMetadataBlobContainer.children();
            for (Map.Entry<String, BlobContainer> metadataBlobContainer : foundMetadataBlobContainers.entrySet()) {
                if (false == foundEncryptedBlobContainers.contains(metadataBlobContainer.getKey())) {
                    try {
                        metadataBlobContainer.getValue().delete();
                    } catch (IOException e) {
                        logger.warn("Exception while deleting orphaned metadata blob container [" + metadataBlobContainer + "]", e);
                    }
                }
            }
        }
    }

}
