FROM grafana/grafana:10.1.1

# Instalar plugins
RUN grafana cli plugins install grafana-clock-panel \
    && grafana cli plugins install grafana-piechart-panel \
    && grafana cli plugins install yesoreyeram-boomtable-panel \
    && grafana cli plugins install natel-discrete-panel
