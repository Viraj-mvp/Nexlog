import QtQuick 2.15

Rectangle {
    id: root
    property string title: ""
    property string subtitle: ""
    property string accent: "#62f3ff"
    property int revealDelay: 0
    default property alias content: body.data

    radius: 28
    color: "#10162b"
    border.color: Qt.rgba(0.38, 0.95, 1.0, 0.20)
    border.width: 1
    clip: true
    opacity: 0
    y: 16

    SequentialAnimation on opacity {
        running: true
        PauseAnimation { duration: root.revealDelay }
        NumberAnimation { to: 1; duration: 340; easing.type: Easing.OutCubic }
    }

    SequentialAnimation on y {
        running: true
        PauseAnimation { duration: root.revealDelay }
        NumberAnimation { to: 0; duration: 420; easing.type: Easing.OutCubic }
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#18204a" }
            GradientStop { position: 0.52; color: "#10162b" }
            GradientStop { position: 1.0; color: "#0a1022" }
        }
        opacity: 0.72
    }

    Rectangle {
        x: parent.width - 180
        y: -90
        width: 240
        height: 180
        radius: 120
        color: root.accent
        opacity: 0.075
    }

    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        height: 2
        color: root.accent
        opacity: 0.68
    }

    Text {
        id: titleText
        text: root.title
        visible: text.length > 0
        color: "#f4f8ff"
        font.pixelSize: 18
        font.weight: Font.Black
        anchors.left: parent.left
        anchors.leftMargin: 22
        anchors.top: parent.top
        anchors.topMargin: 18
        anchors.right: parent.right
        anchors.rightMargin: 22
        elide: Text.ElideRight
    }

    Text {
        id: subText
        text: root.subtitle
        visible: text.length > 0
        color: "#8fa2c9"
        font.pixelSize: 12
        anchors.left: titleText.left
        anchors.right: titleText.right
        anchors.top: titleText.bottom
        anchors.topMargin: 4
        elide: Text.ElideRight
    }

    Item {
        id: body
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: subText.visible ? subText.bottom : titleText.bottom
        anchors.topMargin: root.title.length > 0 ? 16 : 0
        anchors.bottom: parent.bottom
        anchors.margins: 22
    }
}
