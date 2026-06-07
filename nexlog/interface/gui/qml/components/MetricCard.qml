import QtQuick 2.15

Rectangle {
    id: root
    property string label: ""
    property string value: "0"
    property string accent: "#5ee7ff"
    property int delay: 0

    radius: 24
    color: "#11162b"
    border.color: Qt.rgba(0.37, 0.91, 1.0, 0.22)
    border.width: 1
    opacity: 0
    y: 18

    SequentialAnimation on opacity {
        running: true
        PauseAnimation { duration: root.delay }
        NumberAnimation { to: 1; duration: 420; easing.type: Easing.OutCubic }
    }
    SequentialAnimation on y {
        running: true
        PauseAnimation { duration: root.delay }
        NumberAnimation { to: 0; duration: 520; easing.type: Easing.OutBack }
    }

    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        height: 2
        radius: 2
        color: root.accent
        opacity: 0.75
    }

    Column {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 10

        Text {
            text: root.label
            color: "#8fa0c6"
            font.pixelSize: 13
            font.letterSpacing: 1.2
        }
        Text {
            text: root.value
            color: "#eef7ff"
            font.pixelSize: 34
            font.weight: Font.Black
        }
        Rectangle {
            width: parent.width * 0.62
            height: 5
            radius: 3
            color: root.accent
            opacity: 0.58
        }
    }
}
