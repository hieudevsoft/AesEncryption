import util.Constants;
import util.Extensions;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Run {
    public static void main(String[] args) {
        long timeStart = System.currentTimeMillis();
        int [] output = Extensions.EncryptionAes(Constants.states, Constants.keys, 4, 10);
        long time = System.currentTimeMillis()-timeStart;
        Extensions.showMatrix(output);
        System.out.println("Time Encryption: " + (float)time/1000);
        timeStart = System.currentTimeMillis();
        Extensions.showMatrix(Extensions.InvAes(Arrays.stream(output).boxed().collect(Collectors.toList()), Constants.keys, 4, 10));
        time = System.currentTimeMillis()-timeStart;
        System.out.println("Time Decryption: " + (float)time/1000);

    }
}
