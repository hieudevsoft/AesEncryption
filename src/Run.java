import core.AES;
import core.AesHelper;
import util.Constants;
import core.Extensions;
import util.Encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.IllegalFormatException;
import java.util.Scanner;
import java.util.stream.Collectors;

public class Run {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int option = 1;
        while (true) {
            if(option>=1 && option<=6){
                AesHelper.showMenuOption();
            }
            try{
                option = sc.nextInt();
                sc.nextLine();
            }catch (Exception e){
                option = -1;
                sc.nextLine();
            }
            switch (option) {
                case 1:
                    Encryption.ECBEncryptionWithKey(sc);
                    break;
                case 2:
                    Encryption.BCBEncryptionWithKey(sc);
                    break;
                case 3:
                    Encryption.ECBEncryptionWithRandomKey(sc);
                    break;
                case 4:
                    Encryption.BCBEncryptionWithRandomKey(sc);
                    break;
                case 5:
                    Encryption.diffBit();
                    break;
                case 6:
                    break;
                default: {
                    System.out.println("Vui lòng nhập đúng lựa chọn .");
                    System.out.print("Chọn lại: ");
                }
            }
            System.out.println();
            if(option==6){
                System.out.println("BYE!");
                break;
            }
        }

    }


}
