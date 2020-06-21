package com.nukkitx.proxypass.util;

public class NibbleArray implements Cloneable {

    private final byte[] data;

    public NibbleArray(int length) {
        data = new byte[length / 2];
    }

    public NibbleArray(byte[] array) {
        data = array;
    }

    public byte get(int index) {
        byte val = data[index / 2];
        if ((index & 1) == 0) {
            return (byte) (val & 0x0f);
        } else {
            return (byte) ((val & 0xf0) >>> 4);
        }
    }

    public void set(int index, byte value) {
        value &= 0xf;
        int half = index / 2;
        byte previous = data[half];
        if ((index & 1) == 0) {
            data[half] = (byte) (previous & 0xf0 | value);
        } else {
            data[half] = (byte) (previous & 0x0f | value << 4);
        }
    }

    public void fill(byte value) {
        value &= 0xf;
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((value << 4) | value);
        }
    }

    public void copyFrom(byte[] bytes) {
        System.arraycopy(bytes, 0, data, 0, data.length);
    }

    public void copyFrom(NibbleArray array) {
        copyFrom(array.data);
    }

    public byte[] getData() {
        return data;
    }

    public NibbleArray copy() {
        return new NibbleArray(getData().clone());
    }
}
