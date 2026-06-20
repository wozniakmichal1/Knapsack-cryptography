/**
 * Autorzy:
 * Piotr Matuszczyk
 * Michał Woźniak
 */
package pl.lodz;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.stream.Collectors;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;

public class HelloController {

    private byte[] currentInputData;
    private byte[] currentOutputData;

    @FXML
    private RadioButton cypherRadio;

    @FXML
    private RadioButton decypherRadio;

    @FXML
    private TextField vectorLengthInput;

    @FXML
    private TextField publicVectorInput;

    @FXML
    private TextField mulInput;

    @FXML
    private TextField modInput;

    @FXML
    private TextArea plaintextInput;

    @FXML
    private TextArea cyphertextInput;

    @FXML
    private RadioButton keyboardInput;

    @FXML
    private RadioButton fileInputData;

    @FXML
    private Button loadPlaintextFileButton;

    @FXML
    private Button loadCypherFileButton;

    @FXML
    private Label statusLabel;

    @FXML
    public void initialize() {
        setStatus("Gotowy.", false);
    }

    @FXML
    void DoOperation() {
        try {
            if (keyboardInput.isSelected()) {
                doKeyboardOperation();
            } else if (fileInputData.isSelected()) {
                doFileOperation();
            }
        } catch (IllegalArgumentException e) {
            showAlert(Alert.AlertType.ERROR, "Błąd parametrów", e.getMessage());
            setStatus("Błąd: " + e.getMessage(), true);
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Nieoczekiwany błąd", e.getMessage());
            setStatus("Błąd: " + e.getMessage(), true);
        }
    }

    private void doKeyboardOperation() {
        if (cypherRadio.isSelected()) {
            int n = parseVectorLength();
            String msg = plaintextInput.getText();
            if (msg.isBlank()) {
                showAlert(Alert.AlertType.WARNING, "Brak danych", "Wprowadź tekst do zaszyfrowania.");
                return;
            }
            plecak p = new plecak(n, msg);
            BigInteger[] cypher = p.encrypt();

            publicVectorInput.setText(bigIntArrayToString(p.getPublicVector()));
            mulInput.setText(p.getMulW().toString());
            modInput.setText(p.getModM().toString());

            String cypherText = Arrays.stream(cypher)
                    .map(BigInteger::toString)
                    .collect(Collectors.joining(","));
            cyphertextInput.setText(cypherText);
            setStatus("Szyfrowanie zakończone pomyślnie.", false);

        } else if (decypherRadio.isSelected()) {
            BigInteger[] publicVector = parsePublicVector();
            BigInteger mul = parseMul();
            BigInteger mod = parseMod();
            BigInteger[] cypher = parseCypher();

            plecak p = new plecak(publicVector, cypher, mul, mod);
            byte[] decrypted = p.decrypt();
            plaintextInput.setText(new String(decrypted, java.nio.charset.StandardCharsets.UTF_8));
            setStatus("Deszyfrowanie zakończone pomyślnie.", false);
        }
    }

    private void doFileOperation() {
        if (currentInputData == null) {
            showAlert(Alert.AlertType.WARNING, "Brak pliku", "Najpierw wczytaj plik.");
            return;
        }

        if (cypherRadio.isSelected()) {
            int n = parseVectorLength();
            plecak p = new plecak(n, currentInputData);
            BigInteger[] cypher = p.encrypt();
            currentInputData = null;

            publicVectorInput.setText(bigIntArrayToString(p.getPublicVector()));
            mulInput.setText(p.getMulW().toString());
            modInput.setText(p.getModM().toString());

            String cypherStr = Arrays.stream(cypher)
                    .map(BigInteger::toString)
                    .collect(Collectors.joining(","));
            currentOutputData = cypherStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            cyphertextInput.setText("Plik zaszyfrowany. Możesz go teraz zapisać.");
            setStatus("Plik zaszyfrowany pomyślnie.", false);

        } else if (decypherRadio.isSelected()) {
            BigInteger[] publicVector = parsePublicVector();
            BigInteger mul = parseMul();
            BigInteger mod = parseMod();

            String cypherStr = new String(currentInputData, java.nio.charset.StandardCharsets.UTF_8);
            BigInteger[] cypher = Arrays.stream(cypherStr.split(","))
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);
            currentInputData = null;

            plecak p = new plecak(publicVector, cypher, mul, mod);
            currentOutputData = p.decrypt();
            plaintextInput.setText("Plik odszyfrowany. Możesz go teraz zapisać.");
            setStatus("Plik odszyfrowany pomyślnie.", false);
        }
    }

    @FXML
    void InputDataChange() {
        boolean isKeyboard = keyboardInput.isSelected();
        boolean isCypher = cypherRadio.isSelected();

        plaintextInput.setDisable(!isKeyboard || !isCypher);
        cyphertextInput.setDisable(!isKeyboard);

        loadPlaintextFileButton.setDisable(isKeyboard || !isCypher);
        loadCypherFileButton.setDisable(isKeyboard || isCypher);

        if (isKeyboard && !isCypher) {
            cyphertextInput.setDisable(false);
            plaintextInput.setDisable(true);
        }
    }

    @FXML
    void LoadFileOperation(MouseEvent event) throws IOException {
        File plik = openFileDialog("Wybierz plik do zaszyfrowania");
        if (plik != null) {
            currentInputData = Files.readAllBytes(plik.toPath());
            plaintextInput.setText("Załadowano plik: " + plik.getName());
            cyphertextInput.clear();
            setStatus("Plik do zaszyfrowania wczytany: " + plik.getName(), false);
        }
    }

    @FXML
    void LoadCypherOperation(MouseEvent event) throws IOException {
        File plik = openFileDialog("Wybierz plik do odszyfrowania");
        if (plik != null) {
            currentInputData = Files.readAllBytes(plik.toPath());
            cyphertextInput.setText("Załadowano plik: " + plik.getName());
            plaintextInput.clear();
            setStatus("Plik szyfrogramu wczytany: " + plik.getName(), false);
        }
    }

    @FXML
    void SaveFile(MouseEvent event) throws IOException {
        if (keyboardInput.isSelected()) {
            saveTextFileDialog(plaintextInput.getText());
        } else {
            saveBinaryFileDialog(currentOutputData);
        }
    }

    @FXML
    void SaveCypher(MouseEvent event) throws IOException {
        if (keyboardInput.isSelected()) {
            saveTextFileDialog(cyphertextInput.getText());
        } else {
            saveBinaryFileDialog(currentOutputData);
        }
    }

    @FXML
    void SaveKey(MouseEvent event) throws IOException {
        String content = publicVectorInput.getText() + "\n"
                + mulInput.getText() + "\n"
                + modInput.getText();
        saveTextFileDialog(content);
        setStatus("Klucz publiczny zapisany.", false);
    }

    @FXML
    void LoadPublicKey(MouseEvent event) throws IOException {
        File plik = openFileDialog("Wczytaj klucz publiczny");
        if (plik == null) return;

        String[] lines = Files.readString(plik.toPath()).split("\n");
        if (lines.length < 3) {
            showAlert(Alert.AlertType.ERROR, "Nieprawidłowy format", "Plik klucza powinien zawierać 3 linie: wektor, mul, mod.");
            return;
        }

        publicVectorInput.setText(lines[0].trim());
        mulInput.setText(lines[1].trim());
        modInput.setText(lines[2].trim());
        setStatus("Klucz publiczny wczytany z pliku: " + plik.getName(), false);
    }

    private int parseVectorLength() {
        String text = vectorLengthInput.getText().trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Podaj długość wektora n.");
        }
        int n;
        try {
            n = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Długość wektora musi być liczbą całkowitą.");
        }
        if (n <= 0 || n % 8 != 0) {
            throw new IllegalArgumentException("Długość wektora n musi być dodatnią wielokrotnością 8 (np. 64, 128).");
        }
        return n;
    }

    private BigInteger[] parsePublicVector() {
        String text = publicVectorInput.getText().trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Wektor publiczny jest wymagany do deszyfrowania.");
        }
        try {
            return Arrays.stream(text.split(","))
                    .map(String::trim)
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Nieprawidłowy format wektora publicznego.");
        }
    }

    private BigInteger parseMul() {
        String text = mulInput.getText().trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Mnożnik (mul) jest wymagany.");
        }
        try {
            return new BigInteger(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Nieprawidłowa wartość mnożnika (mul).");
        }
    }

    private BigInteger parseMod() {
        String text = modInput.getText().trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Moduł (mod) jest wymagany.");
        }
        try {
            return new BigInteger(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Nieprawidłowa wartość modułu (mod).");
        }
    }

    private BigInteger[] parseCypher() {
        String text = cyphertextInput.getText().trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Szyfrogram jest wymagany do deszyfrowania.");
        }
        try {
            return Arrays.stream(text.split(","))
                    .map(String::trim)
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Nieprawidłowy format szyfrogramu.");
        }
    }

    private String bigIntArrayToString(BigInteger[] arr) {
        return Arrays.stream(arr)
                .map(BigInteger::toString)
                .collect(Collectors.joining(","));
    }

    private File openFileDialog(String title) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        return fileChooser.showOpenDialog(null);
    }

    private void saveTextFileDialog(String content) throws IOException {
        if (content == null || content.isBlank()) {
            showAlert(Alert.AlertType.WARNING, "Brak danych", "Brak danych do zapisania.");
            return;
        }
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik");
        File plik = fileChooser.showSaveDialog(null);
        if (plik != null) {
            Files.write(plik.toPath(), content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            setStatus("Zapisano plik: " + plik.getName(), false);
        }
    }

    private void saveBinaryFileDialog(byte[] content) throws IOException {
        if (content == null) {
            showAlert(Alert.AlertType.ERROR, "Brak danych", "Brak danych do zapisania. Wykonaj najpierw operację.");
            return;
        }
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik");
        File plik = fileChooser.showSaveDialog(null);
        if (plik != null) {
            Files.write(plik.toPath(), content);
            setStatus("Zapisano plik: " + plik.getName(), false);
        }
    }

    private void showAlert(Alert.AlertType type, String header, String content) {
        Alert alert = new Alert(type, content);
        alert.setHeaderText(header);
        alert.showAndWait();
    }

    private void setStatus(String message, boolean isError) {
        statusLabel.setText(message);
        statusLabel.setStyle(isError
                ? "-fx-text-fill: #cc0000; -fx-font-style: italic;"
                : "-fx-text-fill: #006600; -fx-font-style: italic;");
    }
}