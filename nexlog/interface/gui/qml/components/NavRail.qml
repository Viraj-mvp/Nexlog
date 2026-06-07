import QtQuick 2.15

Rectangle {
    id: root
    property string activeScreen: "dashboard"
    signal selected(string screen)

    color: "#0d1020"
    radius: 26
    border.color: "#23345f"
    border.width: 1

    Column {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 12

        Repeater {
            model: [
                { key: "dashboard", label: "Dashboard" },
                { key: "findings", label: "Findings" },
                { key: "timeline", label: "Timeline" },
                { key: "graph", label: "Attack Graph" },
                { key: "ai", label: "AI Query" },
                { key: "mitre", label: "MITRE" },
                { key: "tools", label: "Tools" }
            ]

            delegate: Rectangle {
                id: item
                required property var modelData
                width: parent.width
                height: 48
                radius: 16
                color: root.activeScreen === modelData.key ? "#172756" : "transparent"
                border.color: root.activeScreen === modelData.key ? "#5ee7ff" : "transparent"
                border.width: 1
                scale: mouse.containsMouse ? 1.025 : 1.0

                Behavior on scale { NumberAnimation { duration: 130; easing.type: Easing.OutCubic } }
                Behavior on color { ColorAnimation { duration: 180 } }

                Rectangle {
                    width: 4
                    height: 24
                    radius: 2
                    color: "#8a5cff"
                    opacity: root.activeScreen === modelData.key ? 1 : 0
                    anchors.left: parent.left
                    anchors.leftMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                }

                Text {
                    text: modelData.label
                    color: root.activeScreen === modelData.key ? "#eaf7ff" : "#8998bb"
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.left: parent.left
                    anchors.leftMargin: 26
                    font.pixelSize: 14
                    font.weight: Font.DemiBold
                }

                MouseArea {
                    id: mouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.selected(modelData.key)
                }
            }
        }
    }
}
