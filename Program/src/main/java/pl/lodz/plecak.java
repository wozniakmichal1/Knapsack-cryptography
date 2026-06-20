/**
 * Autorzy:
 * Piotr Matuszczyk
 * Michał Woźniak
 */
package pl.lodz;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class plecak {

    private int vectorLenght, blockSizeInBytes;
    private BigInteger[] privateVector, publicVector;
    private BigInteger mulW, modM;
    private byte[] msg;
    BigInteger[] cypher;

    public BigInteger getMulW() {
        return this.mulW;
    }

    public BigInteger getModM() {
        return this.modM;
    }

    public BigInteger[] getPublicVector() {
        return this.publicVector;
    }

    plecak(int n, byte[] msg) {
        this.msg = msg;
        this.vectorLenght = n;
        this.blockSizeInBytes = this.vectorLenght / 8;
        privateVector = new BigInteger[vectorLenght];
        publicVector = new BigInteger[vectorLenght];
        BigInteger sum = BigInteger.ZERO;
        SecureRandom random = new SecureRandom();
        BigInteger randomValue;
        for (int i = 0; i < vectorLenght; i++) {
            do {
                randomValue = new BigInteger(i * 2 + 1, random);
            } while (randomValue.compareTo(sum) <= 0);
            sum = sum.add(randomValue);
            privateVector[i] = randomValue;
        }
        this.modM = sum.nextProbablePrime();
        this.mulW = mulVal(random);
        for (int i = 0; i < vectorLenght; i++) {
            publicVector[i] = privateVector[i].multiply(mulW).mod(modM);
        }
    }

    plecak(int n, String msg) {
        this(n, msg.getBytes(StandardCharsets.UTF_8));
    }

    plecak(BigInteger[] public_vector, BigInteger[] cypher, BigInteger mulW, BigInteger modM) {
        this.vectorLenght = public_vector.length;
        this.blockSizeInBytes = this.vectorLenght / 8;
        this.mulW = mulW;
        this.modM = modM;
        this.cypher = cypher;
        this.publicVector = public_vector;
        this.privateVector = new BigInteger[public_vector.length];
        BigInteger InverseMul = mulW.modInverse(modM);
        for (int i = 0; i < public_vector.length; i++) {
            privateVector[i] = public_vector[i].multiply(InverseMul).mod(modM);
        }
    }

    private BigInteger mulVal(SecureRandom random) {
        BigInteger halfMod = this.modM.divide(BigInteger.valueOf(2));
        BigInteger mul;
        do {
            mul = new BigInteger(this.modM.bitLength(), random);
        } while (mul.compareTo(modM) >= 0 ||
                mul.compareTo(halfMod) <= 0 ||
                !mul.gcd(this.modM).equals(BigInteger.ONE));
        return mul;
    }

    /**
     * Dodaje padding PKCS#5 zadanej tablicy bajtów
     * 
     * @param arr tablica bajtów
     * @return tablica bajtów, zwiększona o padding (rozmiar większy od min 1 do max
     *         8)
     */
    private byte[] addPaddingToBytesArr(byte[] arr) {
        int blockSize = this.vectorLenght / 8;

        int paddingCount = blockSize - arr.length % blockSize;
        if (paddingCount == 0) {
            paddingCount = blockSize;
        }

        int paddArrLen = arr.length + paddingCount;

        byte[] paddArr = Arrays.copyOf(arr, paddArrLen);
        for (int i = arr.length; i < paddArrLen; i++) {
            paddArr[i] = (byte) paddingCount;
        }

        return paddArr;
    }

    /**
     * Usuwa padding PKCS#5 z tablicy bajów
     * 
     * @param arr tablica bajtów
     * @return tablica bajtów, zmniejszona o padding (rozmiar mniejszy od min 1 do
     *         max 8)
     */
    private byte[] removePaddingFromByteArr(byte[] arr) {
        int paddCount = arr[arr.length - 1] & 0xFF;
        return Arrays.copyOf(arr, arr.length - paddCount);
    }

    public BigInteger[] encrypt() {
        byte[] paddMsg = addPaddingToBytesArr(this.msg);
        int numberBlocks = paddMsg.length / blockSizeInBytes;
        BigInteger[] encrypted = new BigInteger[numberBlocks];
        for (int blockIndex = 0; blockIndex < numberBlocks; blockIndex++) {
            BigInteger blockSum = BigInteger.ZERO;
            for (int msgIndex = 0; msgIndex < blockSizeInBytes; msgIndex++) {
                byte currByte = paddMsg[blockIndex * blockSizeInBytes + msgIndex];
                for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
                    if ((currByte & (1 << (7 - bitIndex))) != 0) {
                        blockSum = blockSum.add(publicVector[msgIndex * 8 + bitIndex]);
                    }
                }
            }
            encrypted[blockIndex] = blockSum;
        }
        this.cypher = encrypted;
        return encrypted;
    }

    public byte[] decrypt() {
        int blocks = cypher.length;
        BigInteger inverseMulW = this.mulW.modInverse(this.modM);
        byte[] res = new byte[cypher.length * blockSizeInBytes];
        for (int i = 0; i < blocks; i++) {
            BigInteger decrypted = cypher[i].multiply(inverseMulW).mod(this.modM);
            for (int j = 0; j < blockSizeInBytes; j++) {
                int byteVal = 0;
                for (int k = 0; k < 8; k++) {
                    byteVal >>>= 1;
                    if (privateVector[vectorLenght - 1 - (k + j * 8)].compareTo(decrypted) <= 0) {
                        decrypted = decrypted.subtract(privateVector[vectorLenght - 1 - (k + j * 8)]);
                        byteVal |= 0b10000000;
                    }
                }
                res[i * blockSizeInBytes + (blockSizeInBytes - 1 - j)] = (byte) byteVal;
            }
        }
        return removePaddingFromByteArr(res);
    }
}
