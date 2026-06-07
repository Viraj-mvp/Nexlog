import QtQuick 2.15

Item {
    id: root
    focus: true
    property var bridge
    property string globalQuery: ""
    property var graph: ({ nodes: [], edges: [], stats: {}, meta: {} })
    property var hitNodes: []
    property var selectedNode: ({})
    property var hoveredNode: ({})
    property string graphQuery: ""
    property string kindFilter: "all"
    property bool storyVisible: false
    property real zoom: 0.82
    property real panX: 0
    property real panY: 0
    property real orbitX: -0.28
    property real orbitY: 0.42
    property bool labelsVisible: true
    property bool trailsVisible: false
    property bool perspectiveMode: true
    property bool animating: false
    property bool inspectorVisible: true
    property bool inspectorCompact: false
    property string graphMode: "compact"
    property bool optionsVisible: false
    property real inspectorX: Math.max(22, width - 360)
    property real inspectorY: 96
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})
    property int keyboardNodeIndex: -1
    property string _cameraKey: ""
    property bool _paintPending: false
    property string graphState: "empty"
    property string graphIssue: ""

    function refresh() {
        if (bridge) {
            var snapshot = bridge.graphSnapshot()
            graph = normalizeGraphPayload(snapshot)
        }
        updateGraphState()
        invalidateGraphCache()
        requestGraphPaint()
    }

    function requestGraphPaint() {
        if (_paintPending) return
        clampCamera()
        _paintPending = true
        paintDebounce.start()
    }

    function invalidateGraphCache() {
        if (graphCanvas) {
            graphCanvas.cacheKey = ""
            graphCanvas.projectedCache = ({})
        }
        hitNodes = []
        hoveredNode = ({})
        keyboardNodeIndex = -1
        if (selectedNode && selectedNode.id) {
            var keepSelected = false
            var nodes = graph.nodes || []
            for (var i = 0; i < nodes.length; i++) {
                if (nodes[i].id === selectedNode.id) {
                    keepSelected = true
                    break
                }
            }
            if (!keepSelected) selectedNode = ({})
        }
    }

    function isFiniteNumber(value) {
        return typeof value === "number" && isFinite(value)
    }

    function normalizeGraphPayload(payload) {
        var normalized = payload
        var malformed = false
        var issue = ""
        if (!normalized || typeof normalized !== "object") {
            normalized = {}
            malformed = true
            issue = "Graph payload was not an object."
        }
        var rawNodes = normalized.nodes
        var rawEdges = normalized.edges
        if (!rawNodes || !rawNodes.length) rawNodes = []
        if (!rawEdges || !rawEdges.length) rawEdges = []
        if (typeof rawNodes.filter !== "function") {
            rawNodes = []
            malformed = true
            issue = "Graph nodes were not readable."
        }
        if (typeof rawEdges.filter !== "function") {
            rawEdges = []
            malformed = true
            issue = "Graph edges were not readable."
        }
        var ids = {}
        var cleanNodes = []
        for (var i = 0; i < rawNodes.length; i++) {
            var node = rawNodes[i]
            if (!node || typeof node !== "object" || !node.id) {
                malformed = true
                continue
            }
            node.id = "" + node.id
            node.kind = node.kind || "rule"
            node.label = node.label || node.id
            node.severity = node.severity || "INFO"
            node.weight = Math.max(1, Number(node.weight || 1))
            node.risk = Math.max(0, Number(node.risk || 0))
            if (!node.tactics || typeof node.tactics.join !== "function") node.tactics = []
            if (node.pos && (!isFiniteNumber(Number(node.pos.x)) || !isFiniteNumber(Number(node.pos.y)) || !isFiniteNumber(Number(node.pos.z)))) {
                node.pos = null
                malformed = true
            }
            ids[node.id] = true
            cleanNodes.push(node)
        }
        var cleanEdges = []
        for (var e = 0; e < rawEdges.length; e++) {
            var edge = rawEdges[e]
            if (!edge || typeof edge !== "object" || !edge.from || !edge.to) {
                malformed = true
                continue
            }
            edge.from = "" + edge.from
            edge.to = "" + edge.to
            if (!ids[edge.from] || !ids[edge.to]) {
                malformed = true
                continue
            }
            edge.severity = edge.severity || "INFO"
            edge.relation = edge.relation || "related"
            edge.weight = Math.max(1, Number(edge.weight || 1))
            edge.risk = Math.max(0, Number(edge.risk || 0))
            if (edge.weight_norm === undefined) edge.weight_norm = Math.min(1, edge.weight / 6)
            cleanEdges.push(edge)
        }
        normalized.nodes = cleanNodes
        normalized.edges = cleanEdges
        normalized.stats = normalized.stats || {}
        normalized.meta = normalized.meta || {}
        normalized.meta.malformed = malformed
        normalized.meta.dangling_edges_removed = Math.max(0, rawEdges.length - cleanEdges.length)
        if (!issue && malformed) issue = "Graph data was repaired before rendering."
        graphIssue = issue
        return normalized
    }

    function updateGraphState() {
        var meta = graph.meta || {}
        if (meta.malformed) graphState = "malformed"
        else if (!(graph.nodes || []).length) graphState = "empty"
        else if (meta.reduced) graphState = "reduced"
        else graphState = "loaded"
    }

    function clampCamera() {
        zoom = Math.max(0.58, Math.min(2.35, zoom))
        panX = Math.max(-graphShell.width * 0.9, Math.min(graphShell.width * 0.9, panX))
        panY = Math.max(-graphShell.height * 0.9, Math.min(graphShell.height * 0.9, panY))
        orbitX = Math.max(-1.05, Math.min(1.05, orbitX))
        if (orbitY > Math.PI * 2 || orbitY < -Math.PI * 2) orbitY = orbitY % (Math.PI * 2)
    }

    function rotateGraph(deltaYaw, deltaPitch, immediate) {
        perspectiveMode = true
        orbitY += deltaYaw
        orbitX += deltaPitch
        clampCamera()
        if (immediate) {
            _paintPending = false
            graphCanvas.requestPaint()
        } else {
            requestGraphPaint()
        }
    }

    function panGraph(deltaX, deltaY, immediate) {
        panX += deltaX
        panY += deltaY
        clampCamera()
        if (immediate) {
            _paintPending = false
            graphCanvas.requestPaint()
        } else {
            requestGraphPaint()
        }
    }

    function sevColor(sev) {
        if (sev === "CRITICAL") return "#ff4d7d"
        if (sev === "HIGH") return "#ff9f43"
        if (sev === "MEDIUM") return "#ffd166"
        if (sev === "LOW") return "#5ee7ff"
        return "#93a4c7"
    }

    function kindColor(kind, sev) {
        if (kind === "source") return "#ff4d7d"
        if (kind === "category") return "#5ee7ff"
        if (kind === "rule") return "#8a5cff"
        if (kind === "technique") return "#7df9c7"
        return sevColor(sev)
    }

    function kindDepth(kind) {
        if (kind === "source") return 0.92
        if (kind === "category") return 0.62
        if (kind === "rule") return 0.34
        if (kind === "technique") return 0.12
        return 0.45
    }

    function kindTitle(kind) {
        if (kind === "source") return "Attacker / Source"
        if (kind === "category") return "Attack Stage"
        if (kind === "rule") return "Detection Rule"
        if (kind === "technique") return "MITRE Technique"
        return "Node"
    }

    function rgba(hex, alpha) {
        if (!hex || hex[0] !== "#") return hex
        var r = parseInt(hex.slice(1, 3), 16)
        var g = parseInt(hex.slice(3, 5), 16)
        var b = parseInt(hex.slice(5, 7), 16)
        return "rgba(" + r + "," + g + "," + b + "," + alpha + ")"
    }

    function fitView() {
        zoom = 0.82
        panX = 0
        panY = 0
        orbitX = -0.28
        orbitY = 0.42
        requestGraphPaint()
    }

    function activeQuery() {
        return ((graphQuery || globalQuery || "") + "").toLowerCase()
    }

    function nodeMatches(node) {
        if (kindFilter !== "all" && (node.kind || "rule") !== kindFilter) return false
        var q = activeQuery()
        if (!q) return true
        var hay = [node.id, node.label, node.kind, node.severity, (node.tactics || []).join(" ")].join(" ").toLowerCase()
        return hay.indexOf(q) >= 0
    }

    function filteredNodeIds() {
        var ids = {}
        var nodes = (graph.nodes || []).filter(function(node) { return nodeMatches(node) })
        nodes.sort(function(a, b) {
            var ka = {"source": 0, "category": 1, "rule": 2, "technique": 3}[a.kind || "rule"] || 9
            var kb = {"source": 0, "category": 1, "rule": 2, "technique": 3}[b.kind || "rule"] || 9
            return (ka - kb) || ((b.risk || 0) - (a.risk || 0)) || ((b.weight || 0) - (a.weight || 0))
        })
        var limit = visibleNodeLimit()
        if (activeQuery() || kindFilter !== "all") limit = Math.max(limit, Math.min(edgeNodeLimit(), 90))
        for (var i = 0; i < Math.min(nodes.length, limit); i++) {
            ids[nodes[i].id] = true
        }
        var edges = graph.edges || []
        for (var e = 0; e < edges.length; e++) {
            if ((activeQuery() || kindFilter !== "all") && (ids[edges[e].from] || ids[edges[e].to])) {
                ids[edges[e].from] = true
                ids[edges[e].to] = true
            }
        }
        return ids
    }

    function hardwareMode() {
        return bridge ? (bridge.hardwareMode || "adaptive") : "adaptive"
    }

    function baseNodeLimit() {
        if (hardwareMode() === "performance") return 420
        if (hardwareMode() === "conservative") return 36
        return 160
    }

    function edgeNodeLimit() {
        return Math.max(baseNodeLimit(), Math.floor(baseNodeLimit() * 1.3))
    }

    function visibleNodeLimit() {
        var base = baseNodeLimit()
        if (graphMode === "full") {
            if (hardwareMode() === "performance") return 2000
            if (hardwareMode() === "conservative") return Math.min(260, Math.max(80, base * 4))
            return Math.min(1100, Math.max(420, base * 4))
        }
        if (graphMode === "balanced") {
            if (hardwareMode() === "performance") return Math.min(980, Math.max(480, Math.floor(base * 2.1)))
            if (hardwareMode() === "conservative") return Math.min(180, Math.max(72, Math.floor(base * 1.6)))
            return Math.min(560, Math.max(240, Math.floor(base * 1.9)))
        }
        return base
    }

    function visibleEdgeLimit() {
        var nodeLimit = visibleNodeLimit()
        if (graphMode === "full") {
            if (hardwareMode() === "performance") return 5000
            if (hardwareMode() === "conservative") return Math.min(650, Math.max(220, nodeLimit * 2))
            return Math.min(2600, Math.max(980, nodeLimit * 2))
        }
        if (graphMode === "balanced") {
            if (hardwareMode() === "performance") return Math.min(2400, Math.max(1100, nodeLimit * 2))
            if (hardwareMode() === "conservative") return Math.min(420, Math.max(170, nodeLimit * 2))
            return Math.min(1450, Math.max(620, nodeLimit * 2))
        }
        return Math.max(120, Math.min(900, nodeLimit * 2))
    }

    function attackStory() {
        var chains = graph.chains || []
        if (!chains.length) return "No correlated attack chains are available yet. Analyse richer evidence or lower the severity filter to build a story."
        var lines = []
        for (var i = 0; i < Math.min(5, chains.length); i++) {
            var c = chains[i]
            lines.push((i + 1) + ". " + (c.chain_name || (c.categories || []).join(" -> ") || "Attack chain") + " | findings " + (c.finding_count || 0) + " | risk " + (c.max_risk_score || 0))
        }
        return lines.join("\n")
    }

    function selectNearest(mx, my) {
        var best = null
        var bestD = 999999
        for (var i = 0; i < hitNodes.length; i++) {
            var h = hitNodes[i]
            var dx = mx - h.x
            var dy = my - h.y
            var d = Math.sqrt(dx * dx + dy * dy)
            if (d < bestD && d <= h.r + 12) {
                bestD = d
                best = h.node
            }
        }
        selectedNode = best || ({})
        if (selectedNode && selectedNode.id) {
            for (var i = 0; i < hitNodes.length; i++) {
                if (hitNodes[i].node && hitNodes[i].node.id === selectedNode.id) {
                    keyboardNodeIndex = i
                    break
                }
            }
        }
        inspectorPulse.restart()
        requestGraphPaint()
    }

    function updateHover(mx, my) {
        var best = null
        var bestD = 999999
        for (var i = 0; i < hitNodes.length; i++) {
            var h = hitNodes[i]
            var dx = mx - h.x
            var dy = my - h.y
            var d = Math.sqrt(dx * dx + dy * dy)
            if (d < bestD && d <= h.r + 10) {
                bestD = d
                best = h.node
            }
        }
        hoveredNode = best || ({})
    }

    function focusRelativeNode(step) {
        if (!hitNodes.length) return
        if (keyboardNodeIndex < 0 || keyboardNodeIndex >= hitNodes.length) {
            keyboardNodeIndex = 0
        } else {
            keyboardNodeIndex = (keyboardNodeIndex + step + hitNodes.length) % hitNodes.length
        }
        selectedNode = hitNodes[keyboardNodeIndex].node || ({})
        inspectorVisible = true
        inspectorPulse.restart()
        requestGraphPaint()
    }

    Component.onCompleted: refresh()

    Keys.onLeftPressed: function(event) { root.focusRelativeNode(-1); event.accepted = true }
    Keys.onRightPressed: function(event) { root.focusRelativeNode(1); event.accepted = true }
    Keys.onUpPressed: function(event) { root.focusRelativeNode(-1); event.accepted = true }
    Keys.onDownPressed: function(event) { root.focusRelativeNode(1); event.accepted = true }

    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onGraphChanged(data) {
            graph = normalizeGraphPayload(data)
            updateGraphState()
            invalidateGraphCache()
            requestGraphPaint()
        }
        function onLastAnalysisChanged() { lastAnalysis = bridge.lastAnalysisSummary }
        function onAnalysisComplete(summary) {
            lastAnalysis = summary
            refresh()
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#090d1b"
    }

    Rectangle {
        id: graphShell
        anchors.fill: parent
        anchors.margins: 26
        radius: 30
        color: "#0b1024"
        border.color: "#263f78"
        clip: true

        Rectangle {
            x: parent.width * 0.55
            y: -140
            width: 520
            height: 420
            radius: 240
            color: "#5ee7ff"
            opacity: 0.08
        }

        Canvas {
            id: graphCanvas
            anchors.fill: parent
            anchors.margins: 18
            property real phase: 0
            property string cacheKey: ""
            property var projectedCache: ({})

            function layerX(kind, width) {
                if (kind === "source") return width * 0.14
                if (kind === "category") return width * 0.40
                if (kind === "rule") return width * 0.66
                if (kind === "technique") return width * 0.88
                return width * 0.5
            }

            function projected(node, indexByKind, countByKind, width, height) {
                var kind = node.kind || "rule"
                var idx = indexByKind[node.id] || 0
                var total = Math.max(1, countByKind[kind] || 1)
                var rowsPerColumn = Math.max(3, Math.floor((height - 210) / 74))
                var column = Math.floor(idx / rowsPerColumn)
                var row = idx % rowsPerColumn
                var columnsInLayer = Math.max(1, Math.ceil(total / rowsPerColumn))
                var rowGap = Math.min(112, Math.max(64, (height - 210) / Math.max(1, Math.min(total, rowsPerColumn))))
                var z = kindDepth(kind)
                var layerSpread = Math.min(150, Math.max(0, (columnsInLayer - 1) * 42))
                var wave = Math.sin((idx + 1) * 1.7) * Math.min(18, rowGap * 0.18)
                var hasPos = node.pos && node.pos.x !== undefined && node.pos.y !== undefined && node.pos.z !== undefined
                var baseX = hasPos ? Number(node.pos.x) : (layerX(kind, width) - width / 2 + (column * 42 - layerSpread / 2))
                var baseY = hasPos ? Number(node.pos.y) : (height * 0.18 + (row + 0.5) * rowGap - height / 2 + wave)
                var baseZ = hasPos ? Number(node.pos.z) : ((z - 0.5) * 720 + (column - columnsInLayer / 2) * 58)
                if (selectedNode && selectedNode.id === node.id) {
                    baseY -= 18
                    baseZ += 90
                } else if (hoveredNode && hoveredNode.id === node.id) {
                    baseY -= 10
                    baseZ += 55
                }
                var yaw = perspectiveMode ? root.orbitY : 0
                var pitch = perspectiveMode ? root.orbitX : 0
                var cosY = Math.cos(yaw)
                var sinY = Math.sin(yaw)
                var cosX = Math.cos(pitch)
                var sinX = Math.sin(pitch)
                var rx = baseX * cosY + baseZ * sinY
                var rz = -baseX * sinY + baseZ * cosY
                var ry = baseY * cosX - rz * sinX
                var rz2 = baseY * sinX + rz * cosX
                var depthScale = perspectiveMode ? Math.max(0.48, Math.min(1.34, 1.0 + rz2 / 920)) : 1.0
                var x = width / 2 + rx * zoom * depthScale + panX
                var y = height / 2 + ry * zoom * depthScale + panY
                return { x: x, y: y, z: rz2, scale: depthScale }
            }

            function isVisible(pos, radius) {
                var margin = Math.max(40, radius + 20)
                return !(pos.x < -margin || pos.x > width + margin || pos.y < -margin || pos.y > height + margin)
            }

            onPaint: {
                var ctx = getContext("2d")
                ctx.reset()
                var allowed = root.filteredNodeIds()
                var allNodes = graph.nodes || []
                var allEdges = graph.edges || []
                var nodes = allNodes.filter(function(node) { return allowed[node.id] })
                var edges = allEdges.filter(function(edge) { return allowed[edge.from] && allowed[edge.to] })
                var edgeCap = root.visibleEdgeLimit()
                if (edges.length > edgeCap) edges = edges.slice(0, edgeCap)
                var stats = graph.stats || {}
                var countByKind = { source: 0, category: 0, rule: 0, technique: 0 }
                var indexByKind = {}
                var seenByKind = { source: 0, category: 0, rule: 0, technique: 0 }
                var positions = {}
                var hits = []
                var cameraKey = [
                    width, height,
                    root.zoom.toFixed(4),
                    root.panX.toFixed(1), root.panY.toFixed(1),
                    root.orbitX.toFixed(4), root.orbitY.toFixed(4),
                    root.perspectiveMode ? "3d" : "2d",
                    selectedNode && selectedNode.id ? selectedNode.id : "",
                    hoveredNode && hoveredNode.id ? hoveredNode.id : ""
                ].join("|")
                if (cacheKey !== cameraKey) {
                    cacheKey = cameraKey
                    projectedCache = {}
                }

                for (var i = 0; i < nodes.length; i++) {
                    var k = nodes[i].kind || "rule"
                    countByKind[k] = (countByKind[k] || 0) + 1
                }
                for (var j = 0; j < nodes.length; j++) {
                    var kj = nodes[j].kind || "rule"
                    indexByKind[nodes[j].id] = seenByKind[kj] || 0
                    seenByKind[kj] = (seenByKind[kj] || 0) + 1
                }

                var bg = ctx.createLinearGradient(0, 0, width, height)
                bg.addColorStop(0, "#091022")
                bg.addColorStop(0.55, "#0e1734")
                bg.addColorStop(1, "#070b18")
                ctx.fillStyle = bg
                ctx.fillRect(0, 0, width, height)

                ctx.save()
                ctx.translate(width / 2, height * 0.68)
                ctx.scale(1, 0.34)
                ctx.strokeStyle = "rgba(94,231,255,0.08)"
                ctx.lineWidth = 1
                for (var gx = -width; gx <= width; gx += 54) {
                    ctx.beginPath(); ctx.moveTo(gx, -height); ctx.lineTo(gx, height); ctx.stroke()
                }
                for (var gy = -height; gy <= height; gy += 54) {
                    ctx.beginPath(); ctx.moveTo(-width, gy); ctx.lineTo(width, gy); ctx.stroke()
                }
                ctx.restore()

                if (perspectiveMode) {
                    ctx.save()
                    ctx.translate(width / 2 + panX * 0.16, height * 0.22 + panY * 0.08)
                    ctx.strokeStyle = "rgba(125,249,199,0.08)"
                    ctx.lineWidth = 1
                    for (var dz = -5; dz <= 5; dz++) {
                        var offset = dz * 58 * zoom
                        ctx.beginPath()
                        ctx.moveTo(-width * 0.42 + offset * 0.38, -18 + offset * 0.08)
                        ctx.lineTo(width * 0.42 + offset * 0.38, 70 + offset * 0.08)
                        ctx.stroke()
                    }
                    ctx.restore()
                }

                var layerLabels = [
                    { kind: "source", label: "SOURCE" },
                    { kind: "category", label: "STAGE" },
                    { kind: "rule", label: "RULE" },
                    { kind: "technique", label: "MITRE" }
                ]
                for (var l = 0; l < layerLabels.length; l++) {
                    var lx = projected({ id: "layer:" + layerLabels[l].kind, kind: layerLabels[l].kind }, {}, {}, width, height).x
                    ctx.strokeStyle = "rgba(94,231,255,0.16)"
                    ctx.setLineDash([6, 10])
                    ctx.beginPath(); ctx.moveTo(lx, 78); ctx.lineTo(lx, height - 54); ctx.stroke()
                    ctx.setLineDash([])
                    ctx.fillStyle = "rgba(220,232,255,0.55)"
                    ctx.font = "bold 11px sans-serif"
                    ctx.fillText(layerLabels[l].label, lx - 24, 54)
                }

                for (var p = 0; p < nodes.length; p++) {
                    var nodeForPos = nodes[p]
                    var sig = [
                        nodeForPos.id,
                        nodeForPos.kind || "rule",
                        indexByKind[nodeForPos.id] || 0,
                        countByKind[nodeForPos.kind || "rule"] || 0,
                        nodeForPos.pos ? (nodeForPos.pos.x + "," + nodeForPos.pos.y + "," + nodeForPos.pos.z) : "nopos"
                    ].join("|")
                    var cached = projectedCache[nodeForPos.id]
                    if (cached && cached.sig === sig) {
                        positions[nodeForPos.id] = cached.pos
                    } else {
                        var projectedPos = projected(nodeForPos, indexByKind, countByKind, width, height)
                        positions[nodeForPos.id] = projectedPos
                        projectedCache[nodeForPos.id] = { sig: sig, pos: projectedPos }
                    }
                }

                edges.sort(function(a, b) {
                    var aa = positions[a.from] || { z: 0 }
                    var ab = positions[a.to] || { z: 0 }
                    var ba = positions[b.from] || { z: 0 }
                    var bb = positions[b.to] || { z: 0 }
                    return ((aa.z + ab.z) / 2) - ((ba.z + bb.z) / 2)
                })
                for (var e = 0; e < edges.length; e++) {
                    var edge = edges[e]
                    var a = positions[edge.from]
                    var b = positions[edge.to]
                    if (!a || !b) continue
                    if (!isVisible(a, 20) && !isVisible(b, 20)) continue
                    var col = sevColor(edge.severity || "INFO")
                    var selectedPath = selectedNode && selectedNode.id && (edge.from === selectedNode.id || edge.to === selectedNode.id)
                    var weightNorm = edge.weight_norm !== undefined ? edge.weight_norm : Math.min(1, (edge.weight || 1) / 6)
                    var alpha = selectedPath ? 0.92 : Math.max(0.16, Math.min(0.82, 0.18 + weightNorm * 0.5 + (edge.relation === "chain" ? 0.16 : 0)))
                    ctx.lineWidth = Math.min(6, 1.0 + (edge.weight || 1) * 0.38) * ((a.scale + b.scale) / 2)
                    if (selectedPath) ctx.lineWidth += 2.2
                    ctx.strokeStyle = rgba(col, alpha)
                    ctx.beginPath()
                    var cx = (a.x + b.x) / 2
                    var depthBend = Math.max(-88, Math.min(88, ((a.z + b.z) / 2) * 0.08))
                    var cy = (a.y + b.y) / 2 - 32 - depthBend
                    ctx.moveTo(a.x, a.y)
                    ctx.quadraticCurveTo(cx, cy, b.x, b.y)
                    ctx.stroke()

                    if (trailsVisible && root.animating && edges.length <= edgeCap * 0.75) {
                        var t = (phase + e * 0.047) % 1
                        var qx1 = a.x + (cx - a.x) * t
                        var qy1 = a.y + (cy - a.y) * t
                        var qx2 = cx + (b.x - cx) * t
                        var qy2 = cy + (b.y - cy) * t
                        var px = qx1 + (qx2 - qx1) * t
                        var py = qy1 + (qy2 - qy1) * t
                        ctx.fillStyle = "#eaf7ff"
                        ctx.globalAlpha = edge.relation === "chain" ? 0.9 : 0.55
                        ctx.beginPath(); ctx.arc(px, py, 2.4, 0, Math.PI * 2); ctx.fill()
                        ctx.globalAlpha = 1
                    }
                }

                var ordered = nodes.slice().sort(function(a, b) {
                    var pa = positions[a.id] || { z: 0 }
                    var pb = positions[b.id] || { z: 0 }
                    return pa.z - pb.z
                })
                var highDensity = ordered.length > 950
                for (var n = 0; n < ordered.length; n++) {
                    var node = ordered[n]
                    var pos = positions[node.id]
                    if (!pos) continue
                    if (!isVisible(pos, 26)) continue
                    var radius = (6 + Math.min(8, node.weight || 1) + Math.min(4, (node.risk || 0) * 0.55)) * pos.scale
                    if (highDensity) radius = Math.max(3.2, radius * 0.78)
                    var selected = selectedNode && selectedNode.id === node.id
                    var hovered = hoveredNode && hoveredNode.id === node.id
                    var color = kindColor(node.kind, node.severity)
                    var searched = root.activeQuery() && root.nodeMatches(node)

                    ctx.fillStyle = searched ? color + "44" : color + "22"
                    ctx.beginPath(); ctx.arc(pos.x, pos.y + 8, radius * 1.95, 0, Math.PI * 2); ctx.fill()
                    ctx.fillStyle = color
                    ctx.beginPath(); ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2); ctx.fill()
                    ctx.strokeStyle = selected ? "#ffffff" : (hovered ? "#f2fcff" : (searched ? "#ffb74d" : "rgba(255,255,255,0.48)"))
                    ctx.lineWidth = selected ? 3 : (hovered ? 2.2 : (searched ? 2 : 1))
                    ctx.beginPath(); ctx.arc(pos.x, pos.y, radius + 2, 0, Math.PI * 2); ctx.stroke()

                    if (node.kind === "source") {
                        ctx.fillStyle = "rgba(9,13,27,0.65)"
                        ctx.beginPath(); ctx.arc(pos.x, pos.y, radius * 0.42, 0, Math.PI * 2); ctx.fill()
                    } else if (node.kind === "technique") {
                        ctx.strokeStyle = "rgba(9,13,27,0.7)"
                        ctx.lineWidth = 3
                        ctx.beginPath(); ctx.moveTo(pos.x - radius * 0.45, pos.y); ctx.lineTo(pos.x + radius * 0.45, pos.y); ctx.stroke()
                    }

                    var labelStride = highDensity ? 8 : (ordered.length > 420 ? 4 : 3)
                    var showLabel = labelsVisible && (selected || hovered || root.graphMode === "compact" || n % labelStride === 0)
                    if ((showLabel && root.zoom >= 0.72) || selected || hovered) {
                        var label = (node.label || node.id || "").slice(0, selected ? 34 : 18)
                        ctx.font = (selected ? "bold " : "") + Math.round(9 * pos.scale + 2) + "px sans-serif"
                        var tw = ctx.measureText(label).width + 18
                        ctx.fillStyle = "rgba(8,13,28,0.78)"
                        ctx.fillRect(pos.x + radius + 7, pos.y - 13, tw, 24)
                        ctx.strokeStyle = color + "88"
                        ctx.strokeRect(pos.x + radius + 7, pos.y - 13, tw, 24)
                        ctx.fillStyle = "#eaf3ff"
                        ctx.fillText(label, pos.x + radius + 16, pos.y + 4)
                    }
                    hits.push({ x: pos.x, y: pos.y, r: radius, node: node })
                }

                root.hitNodes = hits
                ctx.fillStyle = "rgba(234,243,255,0.68)"
                ctx.font = "12px sans-serif"
                var reducedLabel = (graph.meta && graph.meta.reduced) ? "  |  reduced mode" : ""
                ctx.fillText(
                    root.graphMode.toUpperCase() + " | " + nodes.length + " visible / " + (stats.node_count || nodes.length) + " nodes  |  " +
                    edges.length + " visible / " + (stats.edge_count || edges.length) + " edges  |  " +
                    (stats.chain_count || 0) + " chains  |  max risk " +
                    (stats.max_risk || 0) + reducedLabel,
                    20,
                    height - 18
                )
            }

            Timer {
                interval: 42
                running: root.animating
                         && root.visible
                         && (!bridge || (!bridge.reducedMotion && !bridge.busy))
                         && ((graph.nodes || []).length <= root.visibleNodeLimit())
                repeat: true
                onTriggered: {
                    graphCanvas.phase = (graphCanvas.phase + 0.012) % 1
                    root.orbitY += 0.004
                    root.requestGraphPaint()
                }
            }

            onWidthChanged: root.requestGraphPaint()
            onHeightChanged: root.requestGraphPaint()
            Component.onCompleted: root.requestGraphPaint()
        }

        Timer {
            id: paintDebounce
            interval: 16
            running: false
            repeat: false
            onTriggered: {
                root._paintPending = false
                graphCanvas.requestPaint()
            }
        }

        MouseArea {
            id: dragArea
            anchors.fill: graphCanvas
            hoverEnabled: true
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            property real lastX: 0
            property real lastY: 0
            property string dragMode: ""
            property bool moved: false

            onPressed: function(mouse) {
                lastX = mouse.x
                lastY = mouse.y
                moved = false
                if (mouse.button === Qt.RightButton) {
                    dragMode = "pan"
                } else if (root.perspectiveMode && !(mouse.modifiers & Qt.ShiftModifier)) {
                    dragMode = "rotate"
                } else {
                    dragMode = "pan"
                }
                root.updateHover(mouse.x, mouse.y)
            }
            onPositionChanged: function(mouse) {
                if (dragMode === "rotate") {
                    root.rotateGraph((mouse.x - lastX) * 0.014, (mouse.y - lastY) * 0.01, true)
                    moved = true
                    lastX = mouse.x
                    lastY = mouse.y
                } else if (dragMode === "pan") {
                    var dx = mouse.x - lastX
                    var dy = mouse.y - lastY
                    root.panGraph(dx, dy, true)
                    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) moved = true
                    lastX = mouse.x
                    lastY = mouse.y
                } else {
                    root.updateHover(mouse.x, mouse.y)
                }
            }
            onReleased: function(mouse) {
                if (!moved) root.selectNearest(mouse.x, mouse.y)
                dragMode = ""
            }
            onExited: root.hoveredNode = ({})
            onWheel: function(wheel) {
                if (wheel.modifiers & Qt.ShiftModifier) {
                    root.rotateGraph(wheel.angleDelta.y > 0 ? 0.24 : -0.24, 0, true)
                } else {
                    root.zoom = Math.max(0.58, Math.min(2.35, root.zoom + (wheel.angleDelta.y > 0 ? 0.08 : -0.08)))
                    root.clampCamera()
                    graphCanvas.requestPaint()
                }
            }
        }

        GraphButton {
            id: optionsButton
            x: 22
            y: 20
            z: 6
            width: 132
            label: root.optionsVisible ? "Close Options" : "Graph Options"
            accent: "#ffd166"
            onClicked: root.optionsVisible = !root.optionsVisible
        }

        Row {
            id: quick3dToolbar
            z: 6
            spacing: 8
            anchors.left: optionsButton.right
            anchors.leftMargin: 12
            anchors.top: parent.top
            anchors.topMargin: 20

            GraphButton { label: "Fit"; width: 54; accent: "#7df9c7"; onClicked: root.fitView() }
            GraphButton { label: "<"; width: 42; accent: "#62f3ff"; onClicked: root.rotateGraph(-0.5, 0, true) }
            GraphButton { label: ">"; width: 42; accent: "#62f3ff"; onClicked: root.rotateGraph(0.5, 0, true) }
            GraphButton { label: perspectiveMode ? "3D" : "2D"; width: 52; accent: perspectiveMode ? "#ffb74d" : "#93a4c7"; onClicked: { perspectiveMode = !perspectiveMode; root.requestGraphPaint() } }
            GraphButton { label: "0"; width: 42; accent: "#ffd166"; onClicked: root.fitView() }
        }

        Rectangle {
            id: graphOptions
            visible: root.optionsVisible
            z: 7
            x: 22
            y: optionsButton.y + optionsButton.height + 12
            width: Math.min(390, graphShell.width - 44)
            height: Math.min(620, graphShell.height - y - 26)
            radius: 24
            color: "#ee101735"
            border.color: "#ffd166"
            clip: true

            Flickable {
                anchors.fill: parent
                anchors.margins: 16
                contentWidth: width
                contentHeight: optionsColumn.childrenRect.height
                clip: true

                Column {
                    id: optionsColumn
                    width: parent.width
                    spacing: 12

                    Text {
                        text: "ATTACK GRAPH OPTIONS"
                        color: "#ffd166"
                        font.pixelSize: 12
                        font.letterSpacing: 1.6
                        font.weight: Font.Black
                    }

                    OptionGroup {
                        title: "View"
                        Flow {
                            width: parent.width
                            spacing: 8
                            GraphButton { label: "Fit"; onClicked: root.fitView() }
                            GraphButton { label: "+"; width: 44; onClicked: { root.zoom = Math.min(1.85, root.zoom + 0.12); root.requestGraphPaint() } }
                            GraphButton { label: "-"; width: 44; onClicked: { root.zoom = Math.max(0.62, root.zoom - 0.12); root.requestGraphPaint() } }
                            GraphButton { label: "Rotate L"; width: 82; accent: "#62f3ff"; onClicked: root.rotateGraph(-0.5, 0, true) }
                            GraphButton { label: "Rotate R"; width: 82; accent: "#62f3ff"; onClicked: root.rotateGraph(0.5, 0, true) }
                            GraphButton { label: "Reset 3D"; width: 86; accent: "#ffb74d"; onClicked: root.fitView() }
                            GraphButton { label: labelsVisible ? "Labels" : "Labels Off"; width: 104; accent: "#8a5cff"; onClicked: { labelsVisible = !labelsVisible; root.requestGraphPaint() } }
                            GraphButton { label: trailsVisible ? "Trails" : "Trails Off"; width: 94; accent: trailsVisible ? "#ffb74d" : "#93a4c7"; onClicked: { trailsVisible = !trailsVisible; root.requestGraphPaint() } }
                            GraphButton { label: perspectiveMode ? "3D View" : "2D View"; width: 94; accent: "#7df9c7"; onClicked: { perspectiveMode = !perspectiveMode; root.requestGraphPaint() } }
                            GraphButton { label: animating ? "Pause" : "Animate"; width: 88; accent: "#ffd166"; onClicked: animating = !animating }
                        }
                    }

                    OptionGroup {
                        title: "Density"
                        Flow {
                            width: parent.width
                            spacing: 8
                            GraphButton { label: "Compact"; width: 82; accent: graphMode === "compact" ? "#ffb74d" : "#5ee7ff"; onClicked: { graphMode = "compact"; root.fitView() } }
                            GraphButton { label: "Balanced"; width: 88; accent: graphMode === "balanced" ? "#ffb74d" : "#5ee7ff"; onClicked: { graphMode = "balanced"; root.fitView() } }
                            GraphButton { label: "Full"; width: 58; accent: graphMode === "full" ? "#ffb74d" : "#5ee7ff"; onClicked: { graphMode = "full"; root.fitView() } }
                            GraphButton { label: "All Logs"; width: 88; accent: "#ffd166"; onClicked: { bridge.showAllLogs(); root.refresh() } }
                            GraphButton { label: "Refresh"; width: 88; accent: "#93a4c7"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                        }
                    }

                    OptionGroup {
                        title: "Search And Filters"
                        Column {
                            width: parent.width
                            spacing: 8
                            Rectangle {
                                width: parent.width
                                height: 36
                                radius: 14
                                color: "#aa0a1023"
                                border.color: graphSearch.activeFocus ? "#62f3ff" : "#24345f"
                                Text {
                                    visible: !graphSearch.text.length
                                    text: "Search node, rule, source, technique..."
                                    color: "#667696"
                                    font.pixelSize: 12
                                    anchors.left: parent.left
                                    anchors.leftMargin: 12
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                                TextInput {
                                    id: graphSearch
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 12
                                    color: "#eaf7ff"
                                    selectionColor: "#284c82"
                                    font.pixelSize: 12
                                    verticalAlignment: TextInput.AlignVCenter
                                    onTextChanged: { root.graphQuery = text; root.requestGraphPaint() }
                                }
                            }
                            Flow {
                                width: parent.width
                                spacing: 8
                                Repeater {
                                    model: [
                                        { key: "all", label: "All" },
                                        { key: "source", label: "Source" },
                                        { key: "category", label: "Stage" },
                                        { key: "rule", label: "Rule" },
                                        { key: "technique", label: "MITRE" }
                                    ]
                                    delegate: GraphButton {
                                        required property var modelData
                                        width: modelData.key === "technique" ? 72 : 66
                                        label: modelData.label
                                        accent: root.kindFilter === modelData.key ? "#ffb74d" : "#7df9c7"
                                        onClicked: { root.kindFilter = modelData.key; root.requestGraphPaint() }
                                    }
                                }
                            }
                        }
                    }

                    OptionGroup {
                        title: "Story And Export"
                        Flow {
                            width: parent.width
                            spacing: 8
                            GraphButton { label: storyVisible ? "Hide Story" : "Story"; width: 92; accent: "#ff4d7d"; onClicked: storyVisible = !storyVisible }
                            GraphButton { label: "PNG"; width: 62; accent: "#ff9f43"; onClicked: bridge.exportGraph("png") }
                            GraphButton { label: "GraphML"; width: 82; accent: "#62f3ff"; onClicked: bridge.exportGraph("graphml") }
                        }
                    }
                }
            }
        }

        Rectangle {
            width: 260
            height: graph.meta && graph.meta.reduced ? 66 : 52
            radius: 18
            color: "#aa0a1023"
            border.color: "#24345f"
            anchors.right: inspector.right
            anchors.top: parent.top
            anchors.topMargin: 20

            Text {
                text: (graph.stats ? (graph.stats.node_count || 0) : 0) + " nodes / " +
                      (graph.stats ? (graph.stats.edge_count || 0) : 0) + " edges"
                color: "#f4f8ff"
                font.pixelSize: 15
                font.weight: Font.Bold
                x: 16
                y: 9
            }
            Text {
                text: "Last: " + (lastAnalysis.message || "No analysis yet")
                color: "#8fa0c6"
                font.pixelSize: 11
                x: 16
                y: 30
                width: parent.width - 32
                elide: Text.ElideRight
            }
            Text {
                visible: graph.meta && graph.meta.reduced
                text: "Reduced mode for stability"
                color: "#ffcf70"
                font.pixelSize: 10
                x: 16
                y: 46
            }
        }

        Rectangle {
            id: legend
            width: 520
            height: 38
            radius: 18
            color: "#aa0a1023"
            border.color: "#24345f"
            anchors.left: parent.left
            anchors.leftMargin: 22
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 20

            Row {
                anchors.centerIn: parent
                spacing: 16
                LegendDot { label: "Source"; colorValue: "#ff4d7d" }
                LegendDot { label: "Stage"; colorValue: "#5ee7ff" }
                LegendDot { label: "Rule"; colorValue: "#8a5cff" }
                LegendDot { label: "MITRE"; colorValue: "#7df9c7" }
                Text { text: "Left-drag orbit | Right/Shift-drag pan | Wheel zoom | Shift-wheel rotate"; color: "#8fa0c6"; font.pixelSize: 11 }
            }
        }

        Rectangle {
            id: inspector
            visible: root.inspectorVisible
            width: 318
            height: root.inspectorCompact ? 58 : 238
            radius: 24
            color: "#dd101735"
            border.color: selectedNode && selectedNode.id ? kindColor(selectedNode.kind, selectedNode.severity) : "#24345f"
            x: Math.max(22, Math.min(root.inspectorX, graphShell.width - width - 22))
            y: Math.max(112, Math.min(root.inspectorY, graphShell.height - height - 22))
            scale: 1
            clip: true

            SequentialAnimation {
                id: inspectorPulse
                NumberAnimation { target: inspector; property: "scale"; to: 1.035; duration: 80 }
                NumberAnimation { target: inspector; property: "scale"; to: 1.0; duration: 140 }
            }

            Rectangle {
                id: inspectorHandle
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                height: 48
                color: "#17234a"
                opacity: 0.92

                Text {
                    text: selectedNode && selectedNode.id ? kindTitle(selectedNode.kind) : "Node Inspector"
                    color: "#8fa0c6"
                    font.pixelSize: 12
                    font.letterSpacing: 1.6
                    x: 18
                    y: 9
                }
                Text {
                    text: selectedNode && selectedNode.id ? selectedNode.label : "Click a node"
                    color: "#f4f8ff"
                    font.pixelSize: 14
                    font.weight: Font.Black
                    x: 18
                    y: 25
                    width: parent.width - 96
                    elide: Text.ElideRight
                }
                GraphButton {
                    width: 36
                    height: 28
                    label: root.inspectorCompact ? "+" : "-"
                    accent: "#ffd166"
                    anchors.right: closeInspector.left
                    anchors.rightMargin: 8
                    anchors.verticalCenter: parent.verticalCenter
                    onClicked: root.inspectorCompact = !root.inspectorCompact
                }
                GraphButton {
                    id: closeInspector
                    width: 36
                    height: 28
                    label: "X"
                    accent: "#93a4c7"
                    anchors.right: parent.right
                    anchors.rightMargin: 12
                    anchors.verticalCenter: parent.verticalCenter
                    onClicked: root.inspectorVisible = false
                }
                MouseArea {
                    anchors.fill: parent
                    anchors.rightMargin: 92
                    cursorShape: Qt.SizeAllCursor
                    property real dx: 0
                    property real dy: 0
                    onPressed: function(mouse) {
                        dx = mouse.x
                        dy = mouse.y
                    }
                    onPositionChanged: function(mouse) {
                        root.inspectorX = inspector.x + mouse.x - dx
                        root.inspectorY = inspector.y + mouse.y - dy
                    }
                }
            }

            Text {
                visible: !root.inspectorCompact
                text: selectedNode && selectedNode.id ? selectedNode.label : "Click a node to inspect source, stage, rule, or MITRE technique."
                color: "#f4f8ff"
                font.pixelSize: selectedNode && selectedNode.id ? 20 : 15
                font.weight: Font.Black
                wrapMode: Text.WordWrap
                x: 20
                y: 64
                width: parent.width - 40
            }
            Text {
                visible: !root.inspectorCompact
                text: selectedNode && selectedNode.id
                      ? ("Severity: " + (selectedNode.severity || "INFO") +
                         "\nRisk: " + (selectedNode.risk || 0) +
                         "\nFindings: " + (selectedNode.weight || 0) +
                         "\nTactics: " + ((selectedNode.tactics || []).join(", ") || "none") +
                         "\nPath: connected edges are highlighted")
                      : "The graph is layered left-to-right: source -> attack stage -> detection rule -> MITRE technique."
                color: "#aab9dd"
                font.pixelSize: 13
                wrapMode: Text.WordWrap
                x: 20
                y: 128
                width: parent.width - 40
            }
        }

        GraphButton {
            visible: !root.inspectorVisible
            x: graphShell.width - width - 22
            y: 112
            width: 122
            label: "Show Inspector"
            accent: "#a88cff"
            onClicked: root.inspectorVisible = true
        }

        Rectangle {
            visible: root.storyVisible
            width: 440
            height: 212
            radius: 24
            color: "#dd101735"
            border.color: "#ff4d7d"
            x: graphShell.width - width - 22
            y: root.inspectorVisible ? Math.min(graphShell.height - height - 22, inspector.y + inspector.height + 14) : 154

            Text {
                text: "ATTACK STORY"
                color: "#ff9db7"
                font.pixelSize: 12
                font.letterSpacing: 1.7
                font.weight: Font.Bold
                x: 20
                y: 16
            }
            Text {
                text: root.attackStory()
                color: "#eaf3ff"
                font.pixelSize: 13
                lineHeight: 1.18
                wrapMode: Text.WordWrap
                x: 20
                y: 44
                width: parent.width - 40
                height: parent.height - 62
            }
        }

        Rectangle {
            visible: hoveredNode && hoveredNode.id
            z: 8
            width: Math.min(320, Math.max(150, hoverTitle.implicitWidth + 26))
            height: 62
            radius: 12
            color: "#e50a1023"
            border.color: hoveredNode && hoveredNode.severity ? sevColor(hoveredNode.severity) : "#62f3ff"
            x: Math.min(graphShell.width - width - 16, Math.max(16, dragArea.mouseX + 18))
            y: Math.min(graphShell.height - height - 16, Math.max(16, dragArea.mouseY - height - 10))

            Text {
                id: hoverTitle
                x: 12
                y: 10
                text: (hoveredNode.label || hoveredNode.id || "").slice(0, 48)
                color: "#f4f8ff"
                font.pixelSize: 12
                font.weight: Font.Bold
                width: parent.width - 24
                elide: Text.ElideRight
            }
            Text {
                x: 12
                y: 34
                text: (hoveredNode.kind || "node") + " | sev " + (hoveredNode.severity || "INFO") + " | risk " + (hoveredNode.risk || 0)
                color: "#9ab2de"
                font.pixelSize: 11
                width: parent.width - 24
                elide: Text.ElideRight
            }
        }

        Rectangle {
            visible: graphState === "empty" || graphState === "malformed"
            width: Math.min(660, graphShell.width - 120)
            height: 154
            radius: 16
            color: "#c80b1229"
            border.color: graphState === "malformed" ? "#ffb74d" : "#314e87"
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 86
            z: 7

            Text {
                x: 22
                y: 18
                text: graphState === "malformed" ? "Graph data was repaired before rendering." : "No attack graph nodes yet."
                color: "#d9e7ff"
                font.pixelSize: 17
                font.weight: Font.Bold
                width: parent.width - 44
                elide: Text.ElideRight
            }
            Text {
                x: 22
                y: 50
                text: graphState === "malformed"
                      ? (graphIssue || "Some nodes or edges were malformed, so NexLog filtered them to keep the 3D view stable.")
                      : (lastAnalysis.state === "complete"
                         ? ((lastAnalysis.total_findings || 0) === 0
                            ? "Analysis completed with 0 findings, so no graph nodes were created."
                            : "Analysis completed, but no graphable findings were found in this session.")
                         : "Run analysis or refresh sessions to populate the 3D attack path.")
                color: "#9fb0d4"
                font.pixelSize: 13
                width: parent.width - 44
                wrapMode: Text.WordWrap
            }
            Row {
                x: 22
                y: 104
                spacing: 10
                GraphButton {
                    label: "Refresh"
                    width: 88
                    accent: "#62f3ff"
                    onClicked: {
                        if (bridge) bridge.refreshSessions()
                        root.refresh()
                    }
                }
                GraphButton {
                    label: "All Logs"
                    width: 88
                    accent: "#ffd166"
                    onClicked: {
                        if (bridge) bridge.showAllLogs()
                        root.refresh()
                    }
                }
                GraphButton {
                    label: "Fit"
                    width: 58
                    accent: "#7df9c7"
                    onClicked: root.fitView()
                }
            }
        }
    }

    component GraphButton: Rectangle {
        id: btn
        property string label: "Action"
        property string accent: "#5ee7ff"
        signal clicked()
        width: 76
        height: 36
        radius: 14
        color: mouse.containsMouse ? "#1b2854" : "#111b3b"
        border.color: accent
        scale: mouse.containsMouse ? 1.035 : 1
        Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }
        Text {
            anchors.centerIn: parent
            text: label
            color: "#dce8ff"
            font.pixelSize: 12
            font.weight: Font.Bold
        }
        MouseArea {
            id: mouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: btn.clicked()
        }
    }

    component OptionGroup: Rectangle {
        id: group
        property string title: ""
        default property alias content: groupBody.data
        width: parent ? parent.width : 320
        height: groupBody.childrenRect.height + 42
        radius: 18
        color: "#aa0a1023"
        border.color: "#26375f"

        Text {
            text: group.title
            color: "#8fa0c6"
            font.pixelSize: 11
            font.letterSpacing: 1.4
            font.weight: Font.Black
            x: 14
            y: 10
        }

        Item {
            id: groupBody
            x: 14
            y: 32
            width: parent.width - 28
            height: childrenRect.height
        }
    }

    component LegendDot: Row {
        property string label: ""
        property string colorValue: "#5ee7ff"
        spacing: 6
        Rectangle {
            width: 10
            height: 10
            radius: 5
            color: colorValue
            anchors.verticalCenter: parent.verticalCenter
        }
        Text {
            text: label
            color: "#dce8ff"
            font.pixelSize: 11
            anchors.verticalCenter: parent.verticalCenter
        }
    }
}
