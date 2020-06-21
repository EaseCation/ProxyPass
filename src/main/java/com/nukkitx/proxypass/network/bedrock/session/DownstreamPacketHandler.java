package com.nukkitx.proxypass.network.bedrock.session;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.SignedJWT;
import com.nukkitx.nbt.NbtUtils;
import com.nukkitx.nbt.stream.LittleEndianDataOutputStream;
import com.nukkitx.nbt.stream.NBTInputStream;
import com.nukkitx.nbt.stream.NBTOutputStream;
import com.nukkitx.nbt.tag.CompoundTag;
import com.nukkitx.nbt.tag.ListTag;
import com.nukkitx.nbt.tag.Tag;
import com.nukkitx.network.VarInts;
import com.nukkitx.protocol.bedrock.BedrockClientSession;
import com.nukkitx.protocol.bedrock.data.ContainerId;
import com.nukkitx.protocol.bedrock.data.ItemData;
import com.nukkitx.protocol.bedrock.handler.BedrockPacketHandler;
import com.nukkitx.protocol.bedrock.packet.*;
import com.nukkitx.protocol.bedrock.util.EncryptionUtils;
import com.nukkitx.proxypass.ProxyPass;
import com.nukkitx.proxypass.network.bedrock.util.BlockPaletteUtils;
import com.nukkitx.proxypass.network.bedrock.util.RecipeUtils;
import com.nukkitx.proxypass.util.BitArray;
import com.nukkitx.proxypass.util.BitArrayVersion;
import com.nukkitx.proxypass.util.NibbleArray;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntList;
import it.unimi.dsi.fastutil.longs.Long2ObjectMap;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.log4j.Log4j2;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

@Log4j2
@RequiredArgsConstructor
public class DownstreamPacketHandler implements BedrockPacketHandler {
    private final BedrockClientSession session;
    private final ProxyPlayerSession player;
    private final ProxyPass proxy;

    private final Map<Integer, Integer> legacyToRuntimeId = new HashMap<>();
    //private final Map<Integer, Integer> runtimeIdToLegacy = new HashMap<>();
    private final Map<Integer, CompoundTag> runtimeIdToState = new HashMap<>();
    private final AtomicInteger runtimeIdAllocator = new AtomicInteger(0);

    public boolean handle(ServerToClientHandshakePacket packet) {
        try {
            SignedJWT saltJwt = SignedJWT.parse(packet.getJwt());
            URI x5u = saltJwt.getHeader().getX509CertURL();
            ECPublicKey serverKey = EncryptionUtils.generateKey(x5u.toASCIIString());
            SecretKey key = EncryptionUtils.getSecretKey(this.player.getProxyKeyPair().getPrivate(), serverKey,
                    Base64.getDecoder().decode(saltJwt.getJWTClaimsSet().getStringClaim("salt")));
            session.enableEncryption(key);
        } catch (ParseException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        ClientToServerHandshakePacket clientToServerHandshake = new ClientToServerHandshakePacket();
        session.sendPacketImmediately(clientToServerHandshake);
        return true;
    }

    public boolean handle(AvailableEntityIdentifiersPacket packet) {
        proxy.saveNBT("entity_identifiers", packet.getTag());
        return false;
    }

    public boolean handle(BiomeDefinitionListPacket packet) {
        proxy.saveNBT("biome_definitions", packet.getTag());
        return false;
    }

    public boolean handle(StartGamePacket packet) {
        ListTag<CompoundTag> tag = packet.getBlockPalette();
        player.log(tag::toString);
        List<CompoundTag> palette = tag.getValue();
        for (CompoundTag state : palette) {
            int runtimeId = runtimeIdAllocator.getAndIncrement();
            runtimeIdToState.put(runtimeId, state);
            if (state.contains("LegacyStates")) { // Nukkit
                List<CompoundTag> legacyStates = state.getList("LegacyStates", CompoundTag.class);

                //CompoundTag firstState = legacyStates.get(0);
                //runtimeIdToLegacy.put(runtimeId, firstState.getInt("id") << 6 | firstState.getShort("val"));

                for (CompoundTag legacyState : legacyStates) {
                    int legacyId = legacyState.getInt("id") << 6 | legacyState.getShort("val");
                    legacyToRuntimeId.put(legacyId, runtimeId);
                }
            }
        }

        Map<String, Integer> legacyBlocks = new HashMap<>();
        for (CompoundTag entry : tag.getValue()) {
            legacyBlocks.putIfAbsent(entry.getCompound("block").getString("name"), (int) entry.getShort("id"));
        }

        proxy.saveJson("legacy_block_ids_unsorted.json", legacyBlocks);
        proxy.saveJson("legacy_block_ids.json", sortMap(legacyBlocks));
        palette = new ArrayList<>(palette);
        proxy.saveNBT("runtime_block_states_unsorted", new ListTag<>("", CompoundTag.class, palette));
        palette.sort(Comparator.comparingInt(value -> value.getShort("id")));
        proxy.saveNBT("runtime_block_states", new ListTag<>("", CompoundTag.class, palette));
        BlockPaletteUtils.convertToJson(proxy, palette);

        List<DataEntry> itemData = new ArrayList<>();
        LinkedHashMap<String, Integer> legacyItems = new LinkedHashMap<>();

        for (StartGamePacket.ItemEntry entry : packet.getItemEntries()) {
            itemData.add(new DataEntry(entry.getIdentifier(), entry.getId()));
            if (entry.getId() > 255) {
                legacyItems.putIfAbsent(entry.getIdentifier(), (int) entry.getId());
            }
        }

        proxy.saveJson("legacy_item_ids_unsorted.json", legacyItems);
        proxy.saveJson("legacy_item_ids.json", sortMap(legacyItems));
        proxy.saveJson("runtime_item_states.json", itemData);

        return false;
    }

    @Override
    public boolean handle(CraftingDataPacket packet) {
        RecipeUtils.writeRecipes(packet, this.proxy);

        return false;
    }

    @Override
    public boolean handle(DisconnectPacket packet) {
        this.session.disconnect();
        // Let the client see the reason too.
        return false;
    }

    @Override
    public boolean handle(InventoryContentPacket packet) {
        if (packet.getContainerId() == ContainerId.CREATIVE) {
            List<CreativeItemEntry> entries = new ArrayList<>();
            for (ItemData data : packet.getContents()) {
                int id = data.getId();
                Integer damage = data.getDamage() == 0 ? null : (int) data.getDamage();

                CompoundTag tag = data.getTag();
                String tagData = null;
                if (tag != null) {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    try (NBTOutputStream stream = new NBTOutputStream(new LittleEndianDataOutputStream(byteArrayOutputStream))) {
                        stream.write(tag);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    tagData = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
                }
                entries.add(new CreativeItemEntry(id, damage, tagData));
            }

            CreativeItems items = new CreativeItems(entries);

            proxy.saveJson("creative_items.json", items);
        }
        return false;
    }

    @Override
    public boolean handle(LevelChunkPacket packet) {
        if (proxy.getConfiguration().isCheckChunkData()) {
            int chunkX = packet.getChunkX();
            int chunkZ = packet.getChunkZ();
            byte[] payload = packet.getData();
            if (payload.length > 0) {
                player.log(() -> chunkX + "," + chunkZ + " | payload: " + payload.length + ", cache: " + packet.isCachingEnabled());
                ByteBuf data = Unpooled.wrappedBuffer(packet.getData());

                try {
                    if (!packet.isCachingEnabled()) {
                        int subChunksLength = packet.getSubChunksLength();
                        for (int i = 0; i < subChunksLength; i++) {
                            int f_i = i;

                            int subChunkVersion = data.readByte();
                            player.log(() -> chunkX + "," + chunkZ + " | subChunkVersion: " + subChunkVersion + " - " + f_i);
                            switch (subChunkVersion) {
                                case 0:
                                case 2:
                                case 3:
                                case 4:
                                case 5:
                                case 6:
                                case 7:
                                    byte[] ids = new byte[16 * 16 * 16];
                                    data.readBytes(ids);

                                    byte[] vals = new byte[16 * 16 * 16 / 2];
                                    data.readBytes(vals);
                                    NibbleArray meta = new NibbleArray(vals);

                                    for (int j = 0; j < 16 * 16 * 16; j++) {
                                        int f_j = j;

                                        int id = ids[j];
                                        int val = meta.get(j);

                                        if (!legacyToRuntimeId.containsKey(id << 6 | val)) {
                                            player.log(() -> chunkX + "," + chunkZ + " | Unknown legacy block!!! " + id + ":" + val + " - "  + f_i + " " + f_j);
                                        }
                                    }
                                    break;
                                case 1:
                                case 8:
                                    int storageCount;
                                    if (subChunkVersion == 1) {
                                        storageCount = 1;
                                    } else {
                                        storageCount = data.readByte();
                                    }
                                    if (proxy.getConfiguration().isNukkit() && storageCount != 2) {
                                        player.log(() -> chunkX + "," + chunkZ + " | StorageCount is not 2? got: " + storageCount);
                                    }

                                    for (int j = 0; j < storageCount; j++) {
                                        int f_j = j;

                                        byte header = data.readByte();
                                        if ((header & 1) != 1) {
                                            player.log(() -> chunkX + "," + chunkZ + " | Not runtime!!! " + f_i + " " + f_j);
                                        }

                                        int bit = header >> 1;
                                        BitArrayVersion version = BitArrayVersion.get(bit, true);

                                        int expectedWordCount = version.getWordsForSize(16 * 16 * 16);
                                        int[] words = new int[expectedWordCount];
                                        for (int k = 0; k < expectedWordCount; k++) {
                                            int value = data.readIntLE();
                                            words[k] = value;
                                        }

                                        int paletteSize = VarInts.readInt(data);
                                        IntList palette = new IntArrayList();
                                        for (int l = 0; l < paletteSize; l++) {
                                            int runtimeId = VarInts.readInt(data);
                                            palette.add(runtimeId);
                                            if (!runtimeIdToState.containsKey(runtimeId)) {
                                                player.log(() -> chunkX + "," + chunkZ + " | Unknown runtimeID!!! " + runtimeId + " - "  + f_i + " " + f_j);
                                            }
                                        }

                                        BitArray section = version.createPalette(16 * 16 * 16, words);
                                        for (int k = 0; k < 16 * 16 * 16; k++) {
                                            int f_k = k;

                                            int index = section.get(k);
                                            if (palette.getInt(index) == -1) {
                                                player.log(() -> chunkX + "," + chunkZ + " | Unknown paletteIndex!!! " + index + " - "  + f_i + " " + f_j + " " + f_k);
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    player.log(() -> chunkX + "," + chunkZ + " | Unknown subChunkVersion!!! " + subChunkVersion);
                                    break;
                            }
                        }

                        byte[] biome = new byte[16 * 16];
                        data.readBytes(biome);

                        if (!data.isReadable()) {
                            player.log(() -> chunkX + "," + chunkZ + " | (uncache) Payload is empty!");
                            data.release();
                            return false;
                        }
                    }

                    int borderBlocksLength = data.readByte(); //Border block entry format: 1 byte (4 bits X, 4 bits Z). These are however useless since they crash the regular client.
                    if (borderBlocksLength != 0) {
                        player.log(() -> chunkX + "," + chunkZ + " | The length of border block array is not 0? got: " + borderBlocksLength);
                    }

                    if (data.isReadable()) {
                        int b = data.readByte();
                        while (b == 0 && data.isReadable()) { //TODO: Nukkit...
                            player.log(() -> chunkX + "," + chunkZ + " | skip 1 byte...");
                            b = data.readByte();
                        }
                        if (b != 0) {
                            data.readerIndex(data.readerIndex() - 1);
                        }

                        if (data.isReadable()) {
                            List<Tag<?>> tiles = new ArrayList<>();
                            try (NBTInputStream reader = NbtUtils.createNetworkReader(new ByteBufInputStream(data))) {
                                while (data.isReadable()) {
                                    tiles.add(reader.readTag());
                                }
                            } catch (Exception e) {
                                player.log(() -> chunkX + "," + chunkZ + " | tile ERROR!!! " + e);
                            }
                            player.log(() -> chunkX + "," + chunkZ + " | tiles: " + tiles.size() + "\n" + tiles);
                        }
                    }
                } catch (Exception e) {
                    player.log(() -> chunkX + "," + chunkZ + " | ERROR!!! " + e);
                }

                data.release();
            } else {
                player.log(() -> chunkX + "," + chunkZ + " | Payload is empty! cache: " + packet.isCachingEnabled());
            }
        }
        return false;
    }

    @Override
    public boolean handle(ClientCacheMissResponsePacket packet) {
        if (proxy.getConfiguration().isCheckChunkData()) {
            Long2ObjectMap<byte[]> blobs = packet.getBlobs();
            blobs.forEach((hash, blob) -> {
                if (blob.length != 16 * 16) { //biome
                    ByteBuf data = Unpooled.wrappedBuffer(blob);
                    try {
                        int subChunkVersion = data.readByte();
                        player.log(() -> hash + " | subChunkVersion: " + subChunkVersion);
                        switch (subChunkVersion) {
                            case 0:
                            case 2:
                            case 3:
                            case 4:
                            case 5:
                            case 6:
                            case 7:
                                byte[] ids = new byte[16 * 16 * 16];
                                data.readBytes(ids);

                                byte[] vals = new byte[16 * 16 * 16 / 2];
                                data.readBytes(vals);
                                NibbleArray meta = new NibbleArray(vals);

                                for (int j = 0; j < 16 * 16 * 16; j++) {
                                    int f_j = j;

                                    int id = ids[j];
                                    int val = meta.get(j);

                                    if (!legacyToRuntimeId.containsKey(id << 6 | val)) {
                                        player.log(() -> hash + " | Unknown legacy block!!! " + id + ":" + val + " - "  + f_j);
                                    }
                                }
                                break;
                            case 1:
                            case 8:
                                int storageCount;
                                if (subChunkVersion == 1) {
                                    storageCount = 1;
                                } else {
                                    storageCount = data.readByte();
                                }
                                if (proxy.getConfiguration().isNukkit() && storageCount != 2) {
                                    player.log(() -> hash + " | StorageCount is not 2? got: " + storageCount);
                                }

                                for (int j = 0; j < storageCount; j++) {
                                    int f_j = j;

                                    byte header = data.readByte();
                                    if ((header & 1) != 0) {
                                        player.log(() -> hash + " | Runtime!!! " + f_j);
                                    }

                                    int bit = header >> 1;
                                    BitArrayVersion version = BitArrayVersion.get(bit, true);

                                    int expectedWordCount = version.getWordsForSize(16 * 16 * 16);
                                    int[] words = new int[expectedWordCount];
                                    for (int k = 0; k < expectedWordCount; k++) {
                                        int value = data.readIntLE();
                                        words[k] = value;
                                    }

                                    int paletteSize = VarInts.readInt(data);
                                    List<Object> palette = new ArrayList<>();
                                    for (int l = 0; l < paletteSize; l++) {
                                        /*if (proxy.getConfiguration().isNukkit()) {
                                            int runtimeId = VarInts.readInt(data);
                                            palette.add(runtimeId);
                                            if (!runtimeIdToState.containsKey(runtimeId)) {
                                                player.log(() -> hash + " | Unknown runtimeID!!! " + runtimeId + " - "  + f_j);
                                            }
                                        } else {*/
                                            try (NBTInputStream reader = NbtUtils.createNetworkReader(new ByteBufInputStream(data))) {
                                                Tag<?> tag = reader.readTag();
                                                //TODO: check
                                                palette.add(tag);
                                            } catch (Exception e) {
                                                player.log(() -> hash + " | state ERROR!!! " + e);
                                            }
                                        //}
                                    }
                                    player.log(() -> hash + " | states " + f_j + " - " + palette);

                                    BitArray section = version.createPalette(16 * 16 * 16, words);
                                    for (int k = 0; k < 16 * 16 * 16; k++) {
                                        int f_k = k;

                                        int index = section.get(k);
                                        if (palette.get(index) == null) {
                                            player.log(() -> hash + " | Unknown paletteIndex!!! " + index + " - "  + f_j + " " + f_k);
                                        }
                                    }
                                }
                                break;
                            default:
                                player.log(() -> hash + " | Unknown subChunkVersion!!! " + subChunkVersion);
                                break;
                        }
                    } catch (Exception e) {
                        player.log(() -> "ERROR!!! " + e);
                    }
                    data.release();
                }
            });
        }
        return false;
    }

    private static Map<String, Integer> sortMap(Map<String, Integer> map) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(map.entrySet());
        entries.sort(Map.Entry.comparingByValue());

        Map<String, Integer> sortedMap = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> entry : entries) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }
        return sortedMap;
    }

    @Value
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class CreativeItemEntry {
        private final int id;
        private final Integer damage;
        @JsonProperty("nbt_b64")
        private final String nbt;
    }

    @Value
    private static class CreativeItems {
        private final List<CreativeItemEntry> items;
    }

    @Value
    private static class RuntimeEntry {
        private static final Comparator<RuntimeEntry> COMPARATOR = Comparator.comparingInt(RuntimeEntry::getId)
                .thenComparingInt(RuntimeEntry::getData);

        private final String name;
        private final int id;
        private final int data;
    }

    @Value
    private static class DataEntry {
        private final String name;
        private final int id;
    }
}
