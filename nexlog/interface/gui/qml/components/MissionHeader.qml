import QtQuick 2.15

Rectangle {
    id: root
    property var bridge
    property string title: "Dashboard"
    property string activeScreen: "dashboard"
    property string query: searchInput.text
    signal analyse()
    signal refresh()
    signal exportPdf()
    signal performance()
    signal options()
    signal searchChanged(string text)

    height: 92
    radius: 30
    color: "#0f1732"
    border.color: "#273b70"
    clip: false

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#1a2350" }
            GradientStop { position: 0.48; color: "#0f1732" }
            GradientStop { position: 1.0; color: "#0a1022" }
        }
        opacity: 0.86
    }

    Rectangle {
        id: searchBox
        height: 44
        radius: 18
        color: "#0a1023"
        border.color: searchInput.activeFocus ? "#62f3ff" : "#26375f"
        anchors.left: parent.left
        anchors.leftMargin: 34
        anchors.right: actions.left
        anchors.rightMargin: 16
        anchors.verticalCenter: parent.verticalCenter
        visible: width > 190

        Text {
            visible: !searchInput.text.length
            text: "Search case, finding, source..."
            color: "#596987"
            font.pixelSize: 13
            anchors.left: parent.left
            anchors.leftMargin: 16
            anchors.verticalCenter: parent.verticalCenter
        }

        TextInput {
            id: searchInput
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            color: "#eaf7ff"
            selectionColor: "#284c82"
            selectedTextColor: "#ffffff"
            font.pixelSize: 13
            verticalAlignment: TextInput.AlignVCenter
            clip: true
            onTextChanged: root.searchChanged(text)
        }
    }

    Row {
        id: actions
        anchors.right: parent.right
        anchors.rightMargin: 18
        anchors.verticalCenter: parent.verticalCenter
        spacing: 10

        NeonButton {
            label: bridge && bridge.busy ? "Analysing" : "Analyse"
            primary: true
            accent: bridge && bridge.busy ? "#ff4d7d" : "#62f3ff"
            enabled: true
            onClicked: root.analyse()
        }
        NeonButton {
            label: "Refresh"
            accent: "#ffb74d"
            compact: parent.width < 500
            onClicked: root.refresh()
        }
        NeonButton {
            label: "Export"
            accent: "#7df9c7"
            onClicked: root.exportPdf()
        }
        NeonButton {
            id: perfButton
            label: "⚙"
            accent: "#ffd166"
            compact: true
            width: 48
            onClicked: perfMenu.visible = !perfMenu.visible
        }
        NeonButton {
            label: "Options"
            accent: "#a88cff"
            onClicked: root.options()
        }
    }

    Rectangle {
        id: perfMenu
        visible: false
        z: 20
        width: 190
        height: 134
        radius: 18
        color: "#ee101735"
        border.color: "#ffd166"
        anchors.right: parent.right
        anchors.rightMargin: 132
        anchors.top: parent.bottom
        anchors.topMargin: 8

        Column {
            anchors.fill: parent
            anchors.margins: 10
            spacing: 8
            PerfChoice { label: "⚙  Adaptive"; mode: "adaptive" }
            PerfChoice { label: "⚡  Performance"; mode: "performance" }
            PerfChoice { label: "🛡  Conservative"; mode: "conservative" }
        }
    }

    component PerfChoice: Rectangle {
        property string label: ""
        property string mode: "adaptive"
        width: parent.width
        height: 32
        radius: 12
        color: bridge && bridge.hardwareMode === mode ? "#263b6d" : (choiceMouse.containsMouse ? "#1b2854" : "#0d142b")
        border.color: bridge && bridge.hardwareMode === mode ? "#ffd166" : "#26375f"
        Text {
            anchors.centerIn: parent
            text: label
            color: "#eaf7ff"
            font.pixelSize: 12
            font.weight: Font.Bold
        }
        MouseArea {
            id: choiceMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                if (bridge) {
                    if (bridge.busy) {
                        warning.visible = true
                    } else {
                        bridge.setHardwareMode(mode)
                        perfMenu.visible = false
                    }
                }
            }
        }
    }

    Rectangle {
        id: warning
        visible: false
        z: 21
        width: 330
        height: 56
        radius: 18
        color: "#ee241527"
        border.color: "#ff4d7d"
        anchors.right: parent.right
        anchors.rightMargin: 132
        anchors.top: perfMenu.bottom
        anchors.topMargin: 8
        Text {
            anchors.fill: parent
            anchors.margins: 12
            text: "Performance profile is locked during analysis. Cancel or wait for completion first."
            color: "#ffdce6"
            font.pixelSize: 12
            font.weight: Font.Bold
            wrapMode: Text.WordWrap
            verticalAlignment: Text.AlignVCenter
        }
        MouseArea {
            anchors.fill: parent
            onClicked: warning.visible = false
        }
    }
}
