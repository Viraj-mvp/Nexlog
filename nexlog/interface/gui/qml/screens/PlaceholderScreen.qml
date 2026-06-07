import QtQuick 2.15

Item {
    property string title: "NexLog"
    property string subtitle: "This module will be upgraded after the dashboard showcase."

    Rectangle {
        anchors.fill: parent
        anchors.margins: 26
        radius: 30
        color: "#12130f"
        border.color: "#3a3120"

        Column {
            anchors.centerIn: parent
            spacing: 16
            Text {
                text: title
                color: "#fff1cf"
                font.pixelSize: 38
                font.weight: Font.Black
                anchors.horizontalCenter: parent.horizontalCenter
            }
            Text {
                text: subtitle
                color: "#b2a48d"
                font.pixelSize: 16
                width: 520
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }
}
