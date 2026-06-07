import QtQuick 2.15

Item {
    id: root
    property string title: "No data yet"
    property string message: "Run analysis to populate this view."
    property string actionLabel: ""
    property string accent: "#62f3ff"
    property bool showMark: false
    signal action()

    Column {
        anchors.centerIn: parent
        width: Math.min(parent.width - 48, 420)
        spacing: 10

        Rectangle {
            visible: root.showMark
            width: 76
            height: 76
            radius: 38
            color: Qt.rgba(0.38, 0.95, 1.0, 0.08)
            border.color: root.accent
            border.width: 1
            anchors.horizontalCenter: parent.horizontalCenter

            Text {
                anchors.centerIn: parent
                text: "NX"
                color: root.accent
                font.pixelSize: 20
                font.weight: Font.Black
            }
        }

        Text {
            width: parent.width
            text: root.title
            color: "#f4f8ff"
            font.pixelSize: 18
            font.weight: Font.Black
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        Text {
            width: parent.width
            text: root.message
            color: "#91a3ca"
            font.pixelSize: 12
            lineHeight: 1.18
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        NeonButton {
            visible: root.actionLabel.length > 0
            label: root.actionLabel
            accent: root.accent
            primary: true
            anchors.horizontalCenter: parent.horizontalCenter
            onClicked: root.action()
        }
    }
}
