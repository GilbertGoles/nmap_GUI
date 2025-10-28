from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QLabel, QComboBox, QCheckBox, QSlider, QPushButton,
                             QSplitter, QGraphicsView, QGraphicsScene, QGraphicsItem,
                             QMenu, QColorDialog, QInputDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSlot, QPointF, QRectF
from PyQt6.QtGui import QPainter, QPen, QBrush, QColor, QFont, QPainterPath
import math
import random
from typing import Dict, List, Set, Tuple
from enum import Enum

from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import ScanResult, HostInfo, PortInfo

class NodeType(Enum):
    HOST = "host"
    NETWORK = "network"
    SERVICE = "service"
    PORT = "port"

class GraphNode:
    """Узел графа для визуализации"""
    
    def __init__(self, node_id: str, node_type: NodeType, label: str, data: any = None):
        self.id = node_id
        self.type = node_type
        self.label = label
        self.data = data
        self.position = QPointF(0, 0)
        self.size = 40
        self.color = QColor(100, 150, 255)
        self.connections: Set[str] = set()
        
        # Настройки внешнего вида по типу
        self._setup_appearance()
    
    def _setup_appearance(self):
        """Настраивает внешний вид узла по его типу"""
        if self.type == NodeType.HOST:
            self.size = 50
            self.color = QColor(70, 130, 180)  # SteelBlue
        elif self.type == NodeType.NETWORK:
            self.size = 60
            self.color = QColor(47, 79, 79)    # DarkSlateGray
        elif self.type == NodeType.SERVICE:
            self.size = 40
            self.color = QColor(60, 179, 113)  # MediumSeaGreen
        elif self.type == NodeType.PORT:
            self.size = 30
            self.color = QColor(205, 92, 92)   # IndianRed
    
    def add_connection(self, node_id: str):
        """Добавляет соединение с другим узлом"""
        self.connections.add(node_id)
    
    def get_bounds(self) -> QRectF:
        """Возвращает границы узла"""
        return QRectF(
            self.position.x() - self.size/2,
            self.position.y() - self.size/2,
            self.size,
            self.size
        )

class GraphEdge:
    """Ребро графа для визуализации"""
    
    def __init__(self, source_id: str, target_id: str, label: str = ""):
        self.source_id = source_id
        self.target_id = target_id
        self.label = label
        self.color = QColor(100, 100, 100, 150)
        self.width = 2

class GraphView(QGraphicsView):
    """Виджет для отображения графа"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        
        # Настройки масштабирования
        self.scale_factor = 1.15
        self.zoom_level = 0
        
        # Данные графа
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        
        # Настройки отображения
        self.show_labels = True
        self.show_connections = True
        
    def wheelEvent(self, event):
        """Обработка колесика мыши для масштабирования"""
        if event.angleDelta().y() > 0:
            self.zoom_in()
        else:
            self.zoom_out()
    
    def zoom_in(self):
        """Увеличивает масштаб"""
        if self.zoom_level < 10:
            self.scale(self.scale_factor, self.scale_factor)
            self.zoom_level += 1
    
    def zoom_out(self):
        """Уменьшает масштаб"""
        if self.zoom_level > -10:
            self.scale(1/self.scale_factor, 1/self.scale_factor)
            self.zoom_level -= 1
    
    def reset_zoom(self):
        """Сбрасывает масштаб"""
        self.resetTransform()
        self.zoom_level = 0
    
    def add_node(self, node: GraphNode):
        """Добавляет узел в граф"""
        self.nodes[node.id] = node
    
    def add_edge(self, source_id: str, target_id: str, label: str = ""):
        """Добавляет ребро в граф"""
        edge = GraphEdge(source_id, target_id, label)
        self.edges.append(edge)
        
        # Добавляем соединения в узлы
        if source_id in self.nodes:
            self.nodes[source_id].add_connection(target_id)
        if target_id in self.nodes:
            self.nodes[target_id].add_connection(source_id)
    
    def clear_graph(self):
        """Очищает граф"""
        self.nodes.clear()
        self.edges.clear()
        self.scene.clear()
    
    def render_graph(self):
        """Отрисовывает граф"""
        self.scene.clear()
        
        # Отрисовываем ребра
        for edge in self.edges:
            self._draw_edge(edge)
        
        # Отрисовываем узлы
        for node in self.nodes.values():
            self._draw_node(node)
    
    def _draw_node(self, node: GraphNode):
        """Отрисовывает узел"""
        # Создаем путь для узла (круг или шестиугольник)
        path = QPainterPath()
        
        if node.type == NodeType.HOST:
            # Хост - шестиугольник
            self._draw_hexagon(path, node.position, node.size)
        elif node.type == NodeType.NETWORK:
            # Сеть - восьмиугольник
            self._draw_octagon(path, node.position, node.size)
        else:
            # Сервисы и порты - круги
            path.addEllipse(node.position, node.size/2, node.size/2)
        
        # Добавляем узел на сцену
        graphics_item = self.scene.addPath(path, QPen(Qt.GlobalColor.black, 2), QBrush(node.color))
        graphics_item.setData(0, node.id)  # Сохраняем ID для взаимодействия
        graphics_item.setToolTip(f"{node.type.value}: {node.label}")
        
        # Добавляем текст
        if self.show_labels:
            text_item = self.scene.addText(node.label)
            text_item.setDefaultTextColor(Qt.GlobalColor.white)
            text_item.setFont(QFont("Arial", 8))
            text_item.setToolTip(f"{node.type.value}: {node.label}")
            
            # Центрируем текст
            text_rect = text_item.boundingRect()
            text_item.setPos(
                node.position.x() - text_rect.width()/2,
                node.position.y() - text_rect.height()/2
            )
    
    def _draw_edge(self, edge: GraphEdge):
        """Отрисовывает ребро"""
        source = self.nodes.get(edge.source_id)
        target = self.nodes.get(edge.target_id)
        
        if not source or not target:
            return
        
        # Создаем линию между узлами
        line = self.scene.addLine(
            source.position.x(), source.position.y(),
            target.position.x(), target.position.y(),
            QPen(edge.color, edge.width)
        )
        
        # Добавляем текст ребра если есть
        if edge.label and self.show_connections:
            mid_x = (source.position.x() + target.position.x()) / 2
            mid_y = (source.position.y() + target.position.y()) / 2
            
            text_item = self.scene.addText(edge.label)
            text_item.setDefaultTextColor(Qt.GlobalColor.darkGray)
            text_item.setFont(QFont("Arial", 7))
            text_item.setPos(mid_x, mid_y)
    
    def _draw_hexagon(self, path: QPainterPath, center: QPointF, size: float):
        """Рисует шестиугольник"""
        for i in range(6):
            angle = 2 * math.pi * i / 6
            x = center.x() + size/2 * math.cos(angle)
            y = center.y() + size/2 * math.sin(angle)
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        
        path.closeSubpath()
    
    def _draw_octagon(self, path: QPainterPath, center: QPointF, size: float):
        """Рисует восьмиугольник"""
        for i in range(8):
            angle = 2 * math.pi * i / 8
            x = center.x() + size/2 * math.cos(angle)
            y = center.y() + size/2 * math.sin(angle)
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        
        path.closeSubpath()
    
    def apply_force_directed_layout(self, iterations: int = 100):
        """Применяет force-directed layout для размещения узлов"""
        if not self.nodes:
            return
        
        # Параметры layout
        k = 100  # Константа отталкивания
        temperature = 100.0
        cooling_rate = 0.95
        
        # Инициализируем случайные позиции
        for node in self.nodes.values():
            node.position = QPointF(
                random.uniform(-200, 200),
                random.uniform(-200, 200)
            )
        
        # Итерации layout
        for iteration in range(iterations):
            # Вычисляем силы отталкивания
            displacements = {}
            for node_id, node in self.nodes.items():
                displacements[node_id] = QPointF(0, 0)
                
                for other_id, other_node in self.nodes.items():
                    if node_id != other_id:
                        # Вектор от другого узла к текущему
                        dx = node.position.x() - other_node.position.x()
                        dy = node.position.y() - other_node.position.y()
                        distance = max(math.sqrt(dx*dx + dy*dy), 0.1)
                        
                        # Сила отталкивания (закон Кулона)
                        force = k * k / distance
                        displacements[node_id] += QPointF(
                            dx / distance * force,
                            dy / distance * force
                        )
            
            # Вычисляем силы притяжения для соединенных узлов
            for edge in self.edges:
                source = self.nodes[edge.source_id]
                target = self.nodes[edge.target_id]
                
                dx = target.position.x() - source.position.x()
                dy = target.position.y() - source.position.y()
                distance = max(math.sqrt(dx*dx + dy*dy), 0.1)
                
                # Сила притяжения (закон Гука)
                force = distance * distance / k
                
                displacements[edge.source_id] += QPointF(
                    dx / distance * force,
                    dy / distance * force
                )
                displacements[edge.target_id] -= QPointF(
                    dx / distance * force,
                    dy / distance * force
                )
            
            # Применяем перемещения
            for node_id, node in self.nodes.items():
                displacement = displacements[node_id]
                disp_length = max(math.sqrt(displacement.x()**2 + displacement.y()**2), 0.1)
                
                node.position += QPointF(
                    displacement.x() / disp_length * min(disp_length, temperature),
                    displacement.y() / disp_length * min(disp_length, temperature)
                )
            
            # Охлаждаем систему
            temperature *= cooling_rate
        
        self.render_graph()

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return VisualizationTab(event_bus, dependencies)

class VisualizationTab(BaseTabModule):
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        print(f"🟣 [Visualization] __init__ started")
        self.current_results = None
        self.graph_view = None
        self.status_label = None
        self._is_initialized = False
        print(f"🟣 [Visualization] __init__ completed - current_results: {self.current_results}")

    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        print(f"🟣 [Visualization] _setup_event_handlers")
        self.event_bus.results_updated.connect(self._on_results_updated)
        self.event_bus.scan_completed.connect(self._on_scan_completed)

    def _create_ui(self):
        """Создает UI компонент визуализации"""
        print(f"🟣 [Visualization] _create_ui started")
        layout = QVBoxLayout(self)
        
        # Панель управления
        layout.addWidget(self._create_control_panel())
        
        # Сплиттер для графа и информации
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая часть - граф
        splitter.addWidget(self._create_graph_widget())
        
        # Правая часть - настройки и информация
        splitter.addWidget(self._create_info_panel())
        
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        # Статусная строка
        self.status_label = QLabel("No results to visualize")
        layout.addWidget(self.status_label)
        
        self._is_initialized = True
        print(f"🟣 [Visualization] _create_ui completed - is_initialized: {self._is_initialized}")
        
        # Если уже есть результаты, отображаем их
        if self.current_results:
            print(f"🟣 [Visualization] Building graph from existing results")
            self._build_graph_from_results(self.current_results)
        else:
            print(f"🟣 [Visualization] No current results available")

    def _create_control_panel(self) -> QGroupBox:
        """Создает панель управления визуализацией"""
        group = QGroupBox("Visualization Control")
        layout = QHBoxLayout(group)
        
        # Выбор layout
        layout.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Force Directed", "Circular", "Grid", "Hierarchical"])
        layout.addWidget(self.layout_combo)
        
        # Кнопки управления
        self.apply_layout_btn = QPushButton("Apply Layout")
        self.apply_layout_btn.clicked.connect(self._apply_layout)
        layout.addWidget(self.apply_layout_btn)
        
        self.zoom_in_btn = QPushButton("Zoom In")
        self.zoom_in_btn.clicked.connect(self._zoom_in)
        layout.addWidget(self.zoom_in_btn)
        
        self.zoom_out_btn = QPushButton("Zoom Out")
        self.zoom_out_btn.clicked.connect(self._zoom_out)
        layout.addWidget(self.zoom_out_btn)
        
        self.reset_view_btn = QPushButton("Reset View")
        self.reset_view_btn.clicked.connect(self._reset_view)
        layout.addWidget(self.reset_view_btn)
        
        return group
    
    def _create_graph_widget(self) -> QGroupBox:
        """Создает виджет графа"""
        print(f"🟣 [Visualization] _create_graph_widget")
        group = QGroupBox("Network Graph")
        layout = QVBoxLayout(group)
        
        self.graph_view = GraphView()
        layout.addWidget(self.graph_view)
        
        return group
    
    def _create_info_panel(self) -> QWidget:
        """Создает панель информации и настроек"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Настройки отображения
        layout.addWidget(self._create_display_settings())
        
        # Слои
        layout.addWidget(self._create_layers_widget())
        
        # Информация о выбранном узле
        layout.addWidget(self._create_node_info_widget())
        
        return widget
    
    def _create_display_settings(self) -> QGroupBox:
        """Создает настройки отображения"""
        group = QGroupBox("Display Settings")
        layout = QVBoxLayout(group)
        
        self.show_labels_check = QCheckBox("Show Labels")
        self.show_labels_check.setChecked(True)
        self.show_labels_check.toggled.connect(self._on_display_settings_changed)
        layout.addWidget(self.show_labels_check)
        
        self.show_connections_check = QCheckBox("Show Connections")
        self.show_connections_check.setChecked(True)
        self.show_connections_check.toggled.connect(self._on_display_settings_changed)
        layout.addWidget(self.show_connections_check)
        
        self.heat_map_check = QCheckBox("Enable Heat Map")
        self.heat_map_check.toggled.connect(self._on_heat_map_toggled)
        layout.addWidget(self.heat_map_check)
        
        # Настройка размера узлов
        layout.addWidget(QLabel("Node Size:"))
        self.node_size_slider = QSlider(Qt.Orientation.Horizontal)
        self.node_size_slider.setRange(20, 100)
        self.node_size_slider.setValue(40)
        self.node_size_slider.valueChanged.connect(self._on_node_size_changed)
        layout.addWidget(self.node_size_slider)
        
        return group
    
    def _create_layers_widget(self) -> QGroupBox:
        """Создает виджет управления слоями"""
        group = QGroupBox("Layers")
        layout = QVBoxLayout(group)
        
        self.hosts_layer_check = QCheckBox("Hosts")
        self.hosts_layer_check.setChecked(True)
        self.hosts_layer_check.toggled.connect(self._on_layers_changed)
        layout.addWidget(self.hosts_layer_check)
        
        self.ports_layer_check = QCheckBox("Ports")
        self.ports_layer_check.setChecked(False)
        self.ports_layer_check.toggled.connect(self._on_layers_changed)
        layout.addWidget(self.ports_layer_check)
        
        self.services_layer_check = QCheckBox("Services")
        self.services_layer_check.setChecked(True)
        self.services_layer_check.toggled.connect(self._on_layers_changed)
        layout.addWidget(self.services_layer_check)
        
        self.networks_layer_check = QCheckBox("Networks")
        self.networks_layer_check.setChecked(True)
        self.networks_layer_check.toggled.connect(self._on_layers_changed)
        layout.addWidget(self.networks_layer_check)
        
        return group
    
    def _create_node_info_widget(self) -> QGroupBox:
        """Создает виджет информации об узле"""
        group = QGroupBox("Node Information")
        layout = QVBoxLayout(group)
        
        self.node_info_text = QLabel("Select a node to view details")
        self.node_info_text.setWordWrap(True)
        self.node_info_text.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.node_info_text)
        
        return group
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🟣 [Visualization] Results updated: {scan_id}")
        print(f"🟣 [Visualization] Has results: {results is not None}")
        print(f"🟣 [Visualization] Is initialized: {self._is_initialized}")
        
        if results and self._is_initialized:
            self.current_results = results
            self._build_graph_from_results(results)
        elif results:
            # Сохраняем результаты, но ждем инициализации UI
            self.current_results = results
            print("🟣 [Visualization] Results saved, waiting for UI initialization")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🟣 [Visualization] Scan completed: {scan_id}")
        
        if results and self._is_initialized:
            self.current_results = results
            self._build_graph_from_results(results)
        elif results:
            self.current_results = results
    
    def showEvent(self, event):
        """Вызывается когда вкладка становится видимой"""
        super().showEvent(event)
        print(f"🟣 [Visualization] Tab shown, building graph if results available")
        
        # Если есть результаты и UI инициализирован, строим граф
        if self.current_results and self._is_initialized:
            self._build_graph_from_results(self.current_results)
    
    def _build_graph_from_results(self, scan_result: ScanResult):
        """Строит граф из результатов сканирования"""
        print(f"🟣 [Visualization] Building graph from results...")
        
        if not self._is_initialized or not scan_result or not hasattr(scan_result, 'hosts'):
            self.status_label.setText("No valid results to visualize")
            return
        
        if not hasattr(self, 'graph_view') or not self.graph_view:
            print(f"🟣 [Visualization] Graph view not available")
            return
            
        self.graph_view.clear_graph()
        
        host_count = 0
        service_count = 0
        
        print(f"🟣 [Visualization] Processing {len(scan_result.hosts)} hosts")
        
        # Создаем узлы для хостов
        for host in scan_result.hosts:
            if host.state != "up":
                continue
            
            host_count += 1
            
            # Узел хоста
            host_node = GraphNode(
                node_id=f"host_{host.ip}",
                node_type=NodeType.HOST,
                label=host.hostname or host.ip,
                data=host
            )
            self.graph_view.add_node(host_node)
            
            # Узлы для сервисов
            for port in host.ports:
                if port.state == "open" and port.service and port.service != "unknown":
                    service_count += 1
                    
                    # Узел сервиса
                    service_label = f"{port.service}\n{port.port}"
                    if port.version:
                        service_label += f"\n{port.version[:20]}"
                    
                    service_node = GraphNode(
                        node_id=f"service_{host.ip}_{port.port}",
                        node_type=NodeType.SERVICE,
                        label=service_label,
                        data=port
                    )
                    self.graph_view.add_node(service_node)
                    
                    # Соединение хост-сервис
                    self.graph_view.add_edge(host_node.id, service_node.id, port.service)
        
        # Применяем layout если есть узлы
        if host_count > 0:
            self.graph_view.apply_force_directed_layout()
            self.status_label.setText(f"Visualizing {host_count} hosts, {service_count} services")
            print(f"🟣 [Visualization] Graph built successfully: {host_count} hosts, {service_count} services")
        else:
            self.status_label.setText("No active hosts found in results")
    
    def _apply_layout(self):
        """Применяет выбранный layout"""
        if not hasattr(self, 'graph_view') or not self.graph_view or not self.graph_view.nodes:
            return
        
        layout_type = self.layout_combo.currentText()
        
        if layout_type == "Force Directed":
            self.graph_view.apply_force_directed_layout()
        elif layout_type == "Circular":
            self._apply_circular_layout()
        elif layout_type == "Grid":
            self._apply_grid_layout()
        elif layout_type == "Hierarchical":
            self._apply_hierarchical_layout()
    
    def _apply_circular_layout(self):
        """Применяет круговой layout"""
        if not hasattr(self, 'graph_view') or not self.graph_view:
            return
            
        nodes = list(self.graph_view.nodes.values())
        radius = 200
        angle_step = 2 * math.pi / len(nodes)
        
        for i, node in enumerate(nodes):
            angle = i * angle_step
            node.position = QPointF(
                radius * math.cos(angle),
                radius * math.sin(angle)
            )
        
        self.graph_view.render_graph()
    
    def _apply_grid_layout(self):
        """Применяет grid layout"""
        if not hasattr(self, 'graph_view') or not self.graph_view:
            return
            
        nodes = list(self.graph_view.nodes.values())
        cols = math.ceil(math.sqrt(len(nodes)))
        spacing = 100
        
        for i, node in enumerate(nodes):
            row = i // cols
            col = i % cols
            node.position = QPointF(
                col * spacing - (cols-1)*spacing/2,
                row * spacing - (len(nodes)//cols)*spacing/2
            )
        
        self.graph_view.render_graph()
    
    def _apply_hierarchical_layout(self):
        """Применяет иерархический layout"""
        if not hasattr(self, 'graph_view') or not self.graph_view:
            return
            
        # Простая иерархия: хосты на одном уровне, сервисы на другом
        hosts = [n for n in self.graph_view.nodes.values() if n.type == NodeType.HOST]
        services = [n for n in self.graph_view.nodes.values() if n.type == NodeType.SERVICE]
        
        # Размещаем хосты
        host_spacing = 150
        for i, host in enumerate(hosts):
            host.position = QPointF(
                i * host_spacing - (len(hosts)-1)*host_spacing/2,
                -100
            )
        
        # Размещаем сервисы под хостами
        for service in services:
            # Находим связанный хост
            connected_hosts = [edge.source_id for edge in self.graph_view.edges 
                             if edge.target_id == service.id]
            if connected_hosts:
                host = self.graph_view.nodes.get(connected_hosts[0])
                if host:
                    # Размещаем сервис под хостом
                    service.position = QPointF(
                        host.position.x(),
                        host.position.y() + 100
                    )
        
        self.graph_view.render_graph()
    
    def _zoom_in(self):
        """Увеличивает масштаб"""
        if hasattr(self, 'graph_view') and self.graph_view:
            self.graph_view.zoom_in()
    
    def _zoom_out(self):
        """Уменьшает масштаб"""
        if hasattr(self, 'graph_view') and self.graph_view:
            self.graph_view.zoom_out()
    
    def _reset_view(self):
        """Сбрасывает вид"""
        if hasattr(self, 'graph_view') and self.graph_view:
            self.graph_view.reset_zoom()
    
    def _on_display_settings_changed(self):
        """Обрабатывает изменение настроек отображения"""
        if hasattr(self, 'graph_view') and self.graph_view:
            self.graph_view.show_labels = self.show_labels_check.isChecked()
            self.graph_view.show_connections = self.show_connections_check.isChecked()
            self.graph_view.render_graph()
    
    def _on_heat_map_toggled(self, checked: bool):
        """Обрабатывает включение/выключение heat map"""
        if not hasattr(self, 'current_results') or self.current_results is None:
            print(f"🟣 [Visualization] _on_heat_map_toggled - current_results not available")
            return
        
        print(f"🟣 [Visualization] _on_heat_map_toggled - current_results available")
        if checked:
            self._apply_heat_map()
        else:
            # Восстанавливаем стандартные цвета
            if hasattr(self, 'graph_view') and self.graph_view:
                for node in self.graph_view.nodes.values():
                    node._setup_appearance()
                self.graph_view.render_graph()
    
    def _apply_heat_map(self):
        """Применяет heat map на основе количества открытых портов"""
        if not hasattr(self, 'current_results') or self.current_results is None:
            print(f"🟣 [Visualization] _apply_heat_map - current_results not available")
            return
        
        if not hasattr(self, 'graph_view') or not self.graph_view:
            return
            
        print(f"🟣 [Visualization] _apply_heat_map - current_results available")
        # Находим максимальное количество портов для нормализации
        max_ports = 0
        for host in self.current_results.hosts:
            open_ports = len([p for p in host.ports if p.state == "open"])
            max_ports = max(max_ports, open_ports)
        
        if max_ports == 0:
            return
        
        # Применяем цвета heat map
        for node in self.graph_view.nodes.values():
            if node.type == NodeType.HOST and node.data:
                open_ports = len([p for p in node.data.ports if p.state == "open"])
                intensity = open_ports / max_ports
                
                # От зеленого (мало портов) к красному (много портов)
                red = int(255 * intensity)
                green = int(255 * (1 - intensity))
                blue = 50
                
                node.color = QColor(red, green, blue)
        
        self.graph_view.render_graph()
    
    def _on_node_size_changed(self, value: int):
        """Обрабатывает изменение размера узлов"""
        if not hasattr(self, 'graph_view') or not self.graph_view:
            print(f"🟣 [Visualization] _on_node_size_changed - graph_view not available")
            return
            
        print(f"🟣 [Visualization] _on_node_size_changed")
        for node in self.graph_view.nodes.values():
            # Сохраняем пропорции по типу
            if node.type == NodeType.HOST:
                node.size = value + 10
            elif node.type == NodeType.NETWORK:
                node.size = value + 20
            elif node.type == NodeType.SERVICE:
                node.size = value
            elif node.type == NodeType.PORT:
                node.size = value - 10
        
        self.graph_view.render_graph()

    def _on_layers_changed(self):
        """Обрабатывает изменение видимости слоев"""
        if not hasattr(self, 'current_results') or self.current_results is None:
            print(f"🟣 [Visualization] _on_layers_changed - current_results not available")
            return
            
        print(f"🟣 [Visualization] _on_layers_changed - rebuilding graph")
        # В этой версии просто перестраиваем граф
        if self.current_results:
            self._build_graph_from_results(self.current_results)
