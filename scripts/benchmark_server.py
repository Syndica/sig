import os
import json
import plotly.express as px
from dash import Dash, html, dcc, callback, Output, Input

cached_timestamp = None
cached_layout = None

def server_layout():
    path = "results/metrics/"
    layout = [
        html.H1(children='Sig: Benchmarks', style={'textAlign':'center'}),
    ]

    # hash all the files together
    latest_timestamp = 0
    for file_path in os.listdir(path):
        # results/metrics/output-$git_commit-$timestamp.json
        # parse file name
        timestamp = int(file_path.split("-")[2].split(".")[0])
        latest_timestamp = max(latest_timestamp, timestamp)

    if latest_timestamp == cached_timestamp:
        return cached_layout

    # for each file in the directory
    all_metrics = {}
    for file_path in os.listdir(path):
        # results/metrics/output-$git_commit-$timestamp.json
        # parse file_path name
        commit = file_path.split("-")[1]
        timestamp = file_path.split("-")[2].split(".")[0]

        commit_metrics = json.load(open(path + file_path))
        for metric in commit_metrics:
            metric["timestamp"] = timestamp
            metric["commit"] = commit
            key = metric["name"]
            if key in all_metrics:
                all_metrics[key].append(metric)
            else:
                all_metrics[key] = [metric]

    for key in all_metrics:
        data = all_metrics[key]
        if len(data) == 0: continue
        title = data[0]["name"]
        fig = px.scatter(
            x=[d['timestamp'] for d in data],
            y=[d['value'] for d in data],
            title=title,
            hover_data={"commit": [d['commit'] for d in data]},
        )
        fig.update_layout(
            xaxis_title="Timestamp",
            yaxis_title=data[0]["unit"],
        )
        layout.append(dcc.Graph(figure=fig))

    cached_layout = layout
    return layout


app = Dash()
# re-runs on each page refresh
app.layout = server_layout

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
