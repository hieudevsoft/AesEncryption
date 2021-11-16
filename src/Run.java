import util.Constants;
import util.Extensions;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Run {
    public static void main(String[] args) {
        long timeStart = System.currentTimeMillis();
        int [] output = Extensions.EncryptionAes(Constants.states,Constants.keys1, 4, 6,12);
        long time = System.currentTimeMillis()-timeStart;
        System.out.printf("%s","Output: ");
        Extensions.showMatrix(output);
        System.out.println();
        System.out.println("Time Encryption: " + (float)time/1000);
        timeStart = System.currentTimeMillis();
        System.out.printf("%s","Input: ");
        Extensions.showMatrix(Extensions.InvAes(Arrays.stream(output).boxed().collect(Collectors.toList()), Constants.keys1, 4, 6,12));
        time = System.currentTimeMillis()-timeStart;
        System.out.println();
        System.out.println("Time Decryption: " + (float)time/1000);

    }
}
