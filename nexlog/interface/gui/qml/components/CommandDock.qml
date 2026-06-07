import QtQuick 2.15

Rectangle {
    id: root
    property string activeScreen: "dashboard"
    property var bridge
    signal selected(string screen)

    width: 88
    radius: 30
    color: "#0b1023"
    border.color: "#293c70"
    border.width: 1
    clip: true

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#121b3e" }
            GradientStop { position: 0.55; color: "#0b1023" }
            GradientStop { position: 1.0; color: "#070b18" }
        }
        opacity: 0.92
    }

    Column {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 11

        Image {
            source: iconPath
            width: 54
            height: 54
            fillMode: Image.PreserveAspectFit
            anchors.horizontalCenter: parent.horizontalCenter
        }

        Repeater {
            model: [
                { key: "dashboard", icon: "D", label: "Dashboard" },
                { key: "findings", icon: "F", label: "Findings" },
                { key: "timeline", icon: "T", label: "Timeline" },
                { key: "graph", icon: "G", label: "Attack Graph" },
                { key: "ai", icon: "AI", label: "AI Query" },
                { key: "mitre", icon: "M", label: "MITRE" },
                { key: "tools", icon: "X", label: "Tools" }
            ]
            delegate: Rectangle {
                id: nav
                required property var modelData
                width: parent.width
                height: 58
                radius: 20
                color: root.activeScreen === modelData.key ? "#192a5a" : (navMouse.containsMouse ? "#121d3f" : "transparent")
                border.color: root.activeScreen === modelData.key ? "#62f3ff" : "transparent"
                border.width: 1
                scale: navMouse.containsMouse ? 1.045 : 1.0
                Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }
                Behavior on color { ColorAnimation { duration: 160 } }

                Rectangle {
                    width: 4
                    height: 26
                    radius: 2
                    color: "#ffb74d"
                    opacity: root.activeScreen === modelData.key ? 1 : 0
                    anchors.left: parent.left
                    anchors.leftMargin: 3
                    anchors.verticalCenter: parent.verticalCenter
                }

                Text {
                    text: modelData.icon
                    color: root.activeScreen === modelData.key ? "#f4fbff" : "#91a3ca"
                    font.pixelSize: modelData.icon.length > 1 ? 14 : 18
                    font.weight: Font.Black
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.top: parent.top
                    anchors.topMargin: 10
                }

                Text {
                    text: modelData.label
                    color: root.activeScreen === modelData.key ? "#62f3ff" : "#7485aa"
                    font.pixelSize: 9
                    font.weight: Font.Bold
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 8
                    width: parent.width - 8
                    elide: Text.ElideRight
                    horizontalAlignment: Text.AlignHCenter
                }

                MouseArea {
                    id: navMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.selected(modelData.key)
                }
            }
        }

        Item { width: 1; height: 1 }
    }

    Rectangle {
        width: 66
        height: 54
        radius: 17
        color: bridge && bridge.busy ? "#18365c" : "#10182f"
        border.color: bridge && bridge.busy ? "#62f3ff" : "#26375f"
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 14

        Column {
            anchors.centerIn: parent
            width: parent.width - 8
            spacing: 1
            Text {
                text: bridge && bridge.busy ? "RUNNING" : "MADE BY"
                color: bridge && bridge.busy ? "#62f3ff" : "#7df9c7"
                font.pixelSize: 8
                font.weight: Font.Black
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
            }
            Text {
                text: bridge && bridge.busy ? "NexLog" : "Viraj"
                color: "#f4fbff"
                font.pixelSize: 10
                font.weight: Font.Black
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
            }
            Text {
                text: bridge && bridge.busy ? "active" : "Solanki"
                color: "#91a3ca"
                font.pixelSize: 8
                font.weight: Font.Bold
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
            }
        }
    }
}
