module pl.lodz {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;

    opens pl.lodz to javafx.fxml;
    exports pl.lodz;
}
