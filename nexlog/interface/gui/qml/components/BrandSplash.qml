import QtQuick 2.15

Item {
    id: root
    property string logoSource: ""
    property bool reducedMotion: false
    property string statusText: "Initializing parser"
    signal finished()

    Rectangle {
        anchors.fill: parent
        color: "#070806"
        opacity: 0.96
    }

    Rectangle {
        id: bloom
        width: Math.min(parent.width, parent.height) * 0.72
        height: width
        radius: width / 2
        anchors.centerIn: parent
        opacity: reducedMotion ? 0.18 : 0.34
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#55ffb347" }
            GradientStop { position: 0.42; color: "#2235f0de" }
            GradientStop { position: 1.0; color: "#00000000" }
        }
        scale: 0.82
        SequentialAnimation on scale {
            running: !root.reducedMotion
            loops: Animation.Infinite
            NumberAnimation { to: 1.05; duration: 1600; easing.type: Easing.InOutSine }
            NumberAnimation { to: 0.88; duration: 1600; easing.type: Easing.InOutSine }
        }
    }

    Image {
        id: logo
        source: root.logoSource
        anchors.centerIn: parent
        width: Math.min(parent.width * 0.46, 520)
        height: width
        fillMode: Image.PreserveAspectFit
        opacity: 0
        scale: 0.92
    }

    Rectangle {
        id: sweep
        width: parent.width * 0.24
        height: 3
        radius: 2
        y: parent.height * 0.72
        x: -width
        opacity: reducedMotion ? 0 : 0.9
        gradient: Gradient {
            GradientStop { position: 0; color: "#00ffb347" }
            GradientStop { position: 0.5; color: "#ffffb347" }
            GradientStop { position: 1; color: "#0023d7c8" }
        }
    }

    Text {
        id: status
        text: root.statusText
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: logo.bottom
        anchors.topMargin: 18
        color: "#d8c6a1"
        font.pixelSize: 16
        font.weight: Font.DemiBold
        opacity: 0
    }

    SequentialAnimation {
        id: intro
        running: true
        ParallelAnimation {
            NumberAnimation { target: logo; property: "opacity"; to: 1; duration: root.reducedMotion ? 140 : 520; easing.type: Easing.OutCubic }
            NumberAnimation { target: logo; property: "scale"; to: 1.0; duration: root.reducedMotion ? 140 : 620; easing.type: Easing.OutBack }
            NumberAnimation { target: status; property: "opacity"; to: 1; duration: root.reducedMotion ? 120 : 460 }
        }
        NumberAnimation { target: sweep; property: "x"; to: root.width + sweep.width; duration: root.reducedMotion ? 1 : 950; easing.type: Easing.InOutCubic }
        PauseAnimation { duration: root.reducedMotion ? 120 : 780 }
        ParallelAnimation {
            NumberAnimation { target: root; property: "opacity"; to: 0; duration: root.reducedMotion ? 160 : 520; easing.type: Easing.InOutCubic }
            NumberAnimation { target: logo; property: "scale"; to: 1.06; duration: root.reducedMotion ? 160 : 520; easing.type: Easing.InOutCubic }
        }
        ScriptAction { script: root.finished() }
    }
}
