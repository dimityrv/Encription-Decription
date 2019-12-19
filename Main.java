package encryptdecrypt;
import java.io.*;
import java.util.Scanner;

public class Main {
    public static void main(String[] args){

        CipherMachine machine = new CipherMachine();
        try {
            machine.caseSeter(args);
            machine.runCipherMechanism(args);
        } catch (MissingDataExemption e){
            System.out.println(e.getMessage());
        } catch (IOException e){
            System.out.println(e.getMessage());
        }
    }
}
class MissingDataExemption extends Exception{

    public MissingDataExemption(String message){
        super(message);
    }
}
class CipherMachine {
    //fields
    private ModeManagerInterface modeManagerInterface;
    private CipherMachineInterface cipherMachineInterface;
    private ArgsParserInterface argsParserInterface;
    private FileReaderInterface fileReaderInterface;
    private FileWriterInterface fileWriterInterface;
    // fields setters
    private void setModeManagerInterface(ModeManagerInterface modeManagerInterface) {
        this.modeManagerInterface = modeManagerInterface;
    }
    private void setCipherMachineInterface(CipherMachineInterface cipherMachineInterface) {
        this.cipherMachineInterface = cipherMachineInterface;
    }
    private void setFileReaderInterface(FileReaderInterface fileReaderInterface) {
        this.fileReaderInterface = fileReaderInterface;
    }
    private void setFileWriterInterface(FileWriterInterface fileWriterInterface) {
        this.fileWriterInterface = fileWriterInterface;
    }
    //constructor
    public CipherMachine() {
        this.argsParserInterface = new ArgsParser();
    }
    //Interfaces setters
    public void setCaseModeManagerInterface(String mode) {
        switch (mode){
            case "mode":
                setModeManagerInterface(new ModeReturner());
                break;
            case "in":
                setModeManagerInterface(new InPathReturner());
                break;
            case "out":
                setModeManagerInterface(new OutPathReturner());
                break;
            case "data":
                setModeManagerInterface(new DataReturner());
                break;
            case "key":
                setModeManagerInterface(new KeyReturner());
                break;
            case "alg":
                setModeManagerInterface(new AlgorithmReturner());
        }
    }


    void caseSeter(String[] args) throws MissingDataExemption{
        String [][] argsSorted;
        String mode;
        String in;
        String out;
        String data;
        String key;
        String alg;

        argsSorted = argsParserInterface.argsParser(args);
        modeManagerInterface = new ModeReturner();
        mode = modeManagerInterface.getMode(argsSorted);
        modeManagerInterface = new InPathReturner();
        in = modeManagerInterface.getMode(argsSorted);
        modeManagerInterface = new OutPathReturner();
        out = modeManagerInterface.getMode(argsSorted);
        modeManagerInterface = new DataReturner();
        data = modeManagerInterface.getMode(argsSorted);
        modeManagerInterface = new KeyReturner();
        key = modeManagerInterface.getMode(argsSorted);
        modeManagerInterface = new AlgorithmReturner();
        alg = modeManagerInterface.getMode(argsSorted);
        if (mode == null) setCipherMachineInterface(new EncryptUni());
        if (mode == "enc" && (alg == "unicode" || alg == null)) setCipherMachineInterface(new EncryptUni());
        if (mode == "dec" && (alg == "unicode" || alg == null)) setCipherMachineInterface(new DecryptUni());
        if (mode == "enc" && alg == "shift") setCipherMachineInterface(new EncryptShift());
        if (mode == "dec" && alg == "shift") setCipherMachineInterface(new DecryptShift());
        if (in != null) {
            setFileReaderInterface(new ReaderFromPath());
            setModeManagerInterface(new InPathReturner());
        }
        if (data != null) {
            setFileReaderInterface(new ReaderFromData());
            setModeManagerInterface(new DataReturner());
        }
        if (in == null && data == null) setFileReaderInterface(new ReaderFromSysIn());
        if (out != null) setFileWriterInterface(new WriteToPath());
        if (out == null) setFileWriterInterface(new WritetoSysIn());
        if (key == null) throw new MissingDataExemption("Brakuje klucza!");

    }
    void runCipherMechanism(String[] args) throws IOException{
        String[][] argsSorted = argsParserInterface.argsParser(args);
        String msgToProcces = fileReaderInterface.readerMachine(modeManagerInterface.getMode(argsSorted));
        setCaseModeManagerInterface("key");
        String proccesedMsg = cipherMachineInterface.getCipherMsg(msgToProcces,Integer.parseInt(modeManagerInterface.getMode(argsSorted)));
        setCaseModeManagerInterface("out");
        fileWriterInterface.writeToFile(modeManagerInterface.getMode(argsSorted),proccesedMsg);
    }
}
/*
 * ModeManager Interface with classes implementing interface
 */
interface ModeManagerInterface{
    String getMode (String[][] argumentsSorted);
    public enum Mode{
        MODE ("-mode"),IN("-in"),OUT("-out"),DATA("-data"),KEY("-key"),ALG("-alg");
        private final String text;
        Mode (String text){
            this.text = text;
        }

        @Override
        public String toString() {
            return this.text;
        }
    }
} // Implements and share enums with all possible modes, need to be updated if necessary.
class ModeReturner implements ModeManagerInterface{
    Mode key = Mode.MODE;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
class InPathReturner implements ModeManagerInterface{
    Mode key = Mode.IN;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
class OutPathReturner implements ModeManagerInterface{
    Mode key = Mode.OUT;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
class DataReturner implements ModeManagerInterface{
    Mode key = Mode.DATA;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
class KeyReturner implements ModeManagerInterface{
    Mode key = Mode.KEY;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
class AlgorithmReturner implements ModeManagerInterface{
    Mode key = Mode.ALG;
    @Override
    public String getMode(String[][] argumentsSorted) {
        String out;
        for (int i = 0; i < argumentsSorted.length; i++) {
            if (argumentsSorted[i][0].equals(key.toString())) {
                return argumentsSorted[i][1];
            }
        }
        return null;
    }
}
/*
 * Cipher Interface with classes implementing interface
 */
interface CipherMachineInterface{
    String getCipherMsg (String rawMsg, int key);
}
class EncryptUni implements CipherMachineInterface{
    @Override
    public String getCipherMsg(String rawMsg, int key) {
        char[] arrayIn = rawMsg.toCharArray();
        int[] arrayInInt = new int[arrayIn.length];
        char[] arrayOut = new char[arrayIn.length];
        for (int x = 0; x < arrayIn.length; x++){
            arrayInInt[x] = arrayIn[x];
            arrayInInt[x] += key;
            arrayOut[x] = (char) arrayInInt[x];
        }
        return new String(arrayOut);
    }
}
class DecryptUni implements CipherMachineInterface{
    @Override
    public String getCipherMsg(String rawMsg, int key) {
        char[] arrayIn = rawMsg.toCharArray();
        int[] arrayInInt = new int[arrayIn.length];
        char[] arrayOut = new char[arrayIn.length];
        for (int x = 0; x < arrayIn.length; x++){
            arrayInInt[x] = arrayIn[x];
            arrayInInt[x] -= key;
            arrayOut[x] = (char) arrayInInt[x];
        }
        return new String(arrayOut);
    }
}
class EncryptShift implements CipherMachineInterface{
    @Override
    public String getCipherMsg(String rawMsg, int key) {
        int multiplicator = key / 26;
        key -= (multiplicator * 26);
        char[] msgchar = rawMsg.toCharArray();
        int[] msgInt = new int[msgchar.length];
        for (int x = 0; x < msgchar.length; x++) {
            msgInt[x] = msgchar[x];
        }
        for (int x = 0; x < msgInt.length; x++) {
            if (msgInt[x] >= 65 && msgInt[x] <= 90){
                msgInt[x] += key;
                if (!(msgInt[x] >= 65 && msgInt[x] <= 90)) msgInt[x] -= 26;
            } else if (msgInt[x] >= 97 && msgInt[x] <= 122) {
                msgInt[x] += key;
                if (!(msgInt[x] >= 97 && msgInt[x] <= 122)) msgInt[x] -= 26;
            }
        }
        for (int x = 0; x < msgchar.length; x++) {
            msgchar[x] = (char) msgInt[x];
        }
        return new String(msgchar);
    }
}
class DecryptShift implements CipherMachineInterface{
    @Override
    public String getCipherMsg(String rawMsg, int key) {
        int multiplicator = key / 26;
        key -= (multiplicator * 26);
        char[] msgchar = rawMsg.toCharArray();
        int[] msgInt = new int[msgchar.length];
        for (int x = 0; x < msgchar.length; x++) {
            msgInt[x] = msgchar[x];
        }
        for (int x = 0; x < msgInt.length; x++) {
            if (msgInt[x] >= 65 && msgInt[x] <= 90){
                msgInt[x] -= key;
                if (!(msgInt[x] >= 65 && msgInt[x] <= 90)) msgInt[x] += 26;
            } else if (msgInt[x] >= 97 && msgInt[x] <= 122) {
                msgInt[x] -= key;
                if (!(msgInt[x] >= 97 && msgInt[x] <= 122)) msgInt[x] += 26;
            }
        }
        for (int x = 0; x < msgchar.length; x++) {
            msgchar[x] = (char) msgInt[x];
        }
        return new String(msgchar);
    }
}
/*
 * ArgsParser Interface with classes implementing interface
 */
interface ArgsParserInterface{
    // String[] possibleArgs = {"-in", "-out", "-mode", "-key", "-data", "-alg"};
    String[][] argsParser(String[] args);
}
class ArgsParser implements ArgsParserInterface{
    @Override
    public String[][] argsParser(String[] args) {
        // String[] from Eums !!!!
        String[] possibleArguments;
        possibleArguments = new String[ModeManagerInterface.Mode.values().length];
        for (ModeManagerInterface.Mode x: ModeManagerInterface.Mode.values()) possibleArguments[x.ordinal()] = x.toString();
        // String[] from Eums !!!!
        int argsNumber = 0;
        for (int i = 0; i < args.length; i++) {
            for (int j = 0; j < possibleArguments.length; j++) {
                if (args[i].equals(possibleArguments[j])) argsNumber++;
            }
        }
        String[][] out = new String[argsNumber][2];
        int tmp = 0;
        for (int i = 0; i < args.length; i++) {
            for (int j = 0; j < possibleArguments.length; j++) {
                if (args[i].equals(possibleArguments[j])) {
                    out[tmp][0] = args[i];
                    for (int x = 0; x < possibleArguments.length; x++){
                        if (args[i+1].equals(possibleArguments[x])) {
                            out[tmp][1] = null;
                            break;
                        } else out[tmp][1] = args[i+1];
                    }
                    tmp++;
                }
            }
        }
        return out;
    }
}
/*
 * FileReader Interface with classes implementing interface
 */
interface FileReaderInterface {
    String readerMachine (String path) throws FileNotFoundException;
}
class ReaderFromPath implements FileReaderInterface{

    @Override
    public String readerMachine(String path) throws FileNotFoundException {
        try {
            String input;
            File file = new File(path);
            Scanner sc = new Scanner(file);
            input = sc.nextLine();
            file.delete();
            sc.close();
            return input;
        } catch (FileNotFoundException e){
            System.out.println("File not found in path...");
        }
        return null;
    }
}
class ReaderFromData implements FileReaderInterface{
    @Override
    public String readerMachine(String data){
        return data;
    }
}
class ReaderFromSysIn implements FileReaderInterface{
    @Override
    public String readerMachine(String path){
        Scanner sc = new Scanner(System.in);
        return sc.nextLine();
    }
}
/*
 * FileWriter Interface with classes implementing interface
 */
interface FileWriterInterface{
    void writeToFile(String path, String msg);
}
class WriteToPath implements FileWriterInterface{
    @Override
    public void writeToFile(String path, String msg) {
        try (Writer wr = new FileWriter(path)){
            wr.write(msg);
        } catch (IOException e){
            System.out.printf(e.getMessage());
        }
    }
}
class WritetoSysIn implements FileWriterInterface{
    @Override
    public void writeToFile(String path, String msg) {
        System.out.println(msg);
    }
}
