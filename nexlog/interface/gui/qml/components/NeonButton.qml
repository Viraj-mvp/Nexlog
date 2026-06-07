import QtQuick 2.15

Rectangle {
    id: root
    property string label: "Action"
    property string detail: ""
    property string accent: "#62f3ff"
    property bool primary: false
    property bool compact: false
    signal clicked()

    width: compact ? 96 : (primary ? 154 : 124)
    height: compact ? 38 : 44
    radius: height / 2
    color: primary ? accent : (mouse.containsMouse ? "#182348" : "#0d142b")
    border.color: primary ? accent : Qt.rgba(0.38, 0.95, 1.0, mouse.containsMouse ? 0.85 : 0.32)
    border.width: primary ? 0 : 1
    opacity: enabled ? 1.0 : 0.42
    scale: mouse.containsMouse && enabled ? 1.035 : 1.0

    Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }
    Behavior on color { ColorAnimation { duration: 160 } }
    Behavior on border.color { ColorAnimation { duration: 160 } }

    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        color: root.accent
        opacity: root.primary ? 0.22 : (mouse.containsMouse ? 0.12 : 0.0)
    }

    Text {
        anchors.centerIn: parent
        text: root.label
        color: root.primary ? "#06111d" : "#eaf7ff"
        font.pixelSize: root.compact ? 12 : 13
        font.weight: Font.Black
        elide: Text.ElideRight
        width: parent.width - 18
        horizontalAlignment: Text.AlignHCenter
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        enabled: root.enabled
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
