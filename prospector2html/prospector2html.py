#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
from datetime import datetime
import argparse
import json
import yaml
import pathlib
import html
from json2html import *

class Prospector2HTML:

    PRH_CONFIG_FILE = '.prospector-html.yaml'
    PRH_DEF_OUTPUT_FILE = 'prospector-html-report'

    # Default - empty message filters config
    prh_config = {'filter': {'message': [], 'message_re': []}}

    def filter_message_by_match(self, x):
        if not self.prh_config or not self.prh_config['filter'] or not self.prh_config['filter']['message']:
            return True
        return not any(x['message'] in m for m in self.prh_config['filter']['message'])


    def filter_message_by_re(self, x):
        if not self.prh_config or not self.prh_config['filter'] or not self.prh_config['filter']['message_re']:
            return True
        return not any((re.search(rre, x['message']) is not None) for rre in self.prh_config['filter']['message_re'])


    def filter_message(self, x):
        return self.filter_message_by_match(x) and self.filter_message_by_re(x)


    def normalize_prospector(self, x):
        result = []
        for item in x:
            try:
                result.append({
                    'tool': item['source'],
                    'code': item['code'],
                    'severity': 'unknown',
                    'confidence': 'unknown',
                    'function': item['location']['function'],
                    'file': item['location']['path'],
                    'line': item['location']['line'],
                    'position': item['location']['character'],
                    'message': item['message']
                })
            except KeyError as e:
                print("ERROR: Can't normalize prospector item: ", str(e), " is absent.")

        return result


    def normalize_gitlab_sast(self, x):
        result = []
        for item in x:
            try:
                result.append({
                    'tool': item['scanner']['id'],
                    'code': ', '.join([i['value'] for i in item['identifiers']]),
                    'severity': item['severity'],
                    'confidence': item['confidence'],
                    'function': 'unknown',
                    'file': item['location']['file'],
                    'line': item['location']['start_line'],
                    'position': 0,
                    'message': item['message']
                })
            except KeyError as e:
                print("ERROR: Can't normalize gitlab-sast item: ", str(e), " is absent.")

        return result



    def normalize_semgrep(self, args, x):
        def readSnippet(path, line):
            lines = []
            try:
                print(f"trying file {path}, line: {line}")
                with open(path, 'r') as fp:
                    line_n = line-5 if line > 5 else line
                    lines = fp.readlines()
                    lines = lines[line_n:line_n+11]
            except Exception as e:
                print(str(e))
                return []
            else:
                if path.endswith('.js') and len(lines) > 0 and any(len(l) > 200 for l in lines):
                    return ["minimized js..."]
                line_numbers = []
                for idx, l in enumerate(lines):
                    line_numbers.append(f"{idx+line_n+1} {l}")
                return line_numbers

        result = []
        url = args.repository_url.rstrip("/")
        for item in x:
            code = readSnippet(item["path"],item['start']['line'])
            code = "".join(code)
            impact = item['extra']['metadata']['impact']
            severity = item['extra']['severity']
            confidence = item['extra']['metadata']['confidence']
            start_line = item['start']['line']


            ext = pathlib.Path(item["path"]).suffix.lstrip(".")
            html_class = ""
            if ext in ["php", "js", "yaml", "java", "html" ]:
                html_class = f"language-{ext}"
            if ext == "html":
                code = html.escape(code)
            try:
                result.append({
                    'code': ' . '.join(item['check_id'].split('.')),
                    'impact': f"<div class=\"data\" data-impact=\"{impact}\"><span class=\"badge\">{impact}</span></div>",
                    'severity': f"<div class=\"data\" data-severity=\"{severity}\"><span class=\"badge\">{severity}</span></div>",
                    'confidence': f"<div class=\"data\" data-confidence=\"{confidence}\" ><span class=\"badge \">{confidence}</span></div>",
                    'file': f"<a target=\"_blank\" href=\"{url}/blob/{args.sha}/{item['path']}#L{start_line}\">{' / '.join(item['path'].split('/'))}</a>",
                    'message': item['extra']['message'],
                    'snippet': f"<pre>line: {start_line}, pos: {item['start']['col']} <code class=\"{html_class}\">" + code + "</code></pre>"
                })
            except KeyError as e:
                print("ERROR: Can't normalize semgrep item: ", str(e), " is absent.")

        return result


    def get_report_body(self, obj):
        return json2html.convert(json=obj, escape=False, table_attributes="id=\"info-table\" class=\"table table-striped table-bordered table-hover\"")


    def main(self):
        parser = argparse.ArgumentParser(prog='propsector-html')
        parser.add_argument('-i', '--input', help='input JSON file name', required=True,
                            action='store', type=str)
        parser.add_argument('-o', '--output', help='output file name', required=False,
                            default=self.PRH_DEF_OUTPUT_FILE, action='store', type=str)
        parser.add_argument('-c', '--config', help='config file name', required=False,
                            default=self.PRH_CONFIG_FILE, action='store', type=str)
        parser.add_argument('-j', '--json', help='dump output as JSON', required=False,
                            default=False, action=argparse.BooleanOptionalAction)
        parser.add_argument("-z", "--zero-exit", action="store_true", default=False,
                            help="Always exit with zero return code.")
        parser.add_argument('-f', '--filter', help='apply tool filter for input JSON', required=False,
                            default='prospector', choices = ['none', 'prospector', 'semgrep', 'gitlab-sast'])
        parser.add_argument('-l', '--repository-url', help='repository url', required=False,
                            default='https://github.com', action='store', type=str, dest='repository_url' )
        parser.add_argument('-s', '--sha', help='sha, branch, or tag', required=False, action='store',
                            type=str, dest='sha')

        args = parser.parse_args()

        try:
            with open(args.config, 'r') as stream:
                try:
                    self.prh_config = yaml.safe_load(stream)
                    print("Using config file '" + args.config + "'")
                except yaml.YAMLError as exc:
                    print("Can't parse config file '" + args.config + "': " + str(exc))
                    return 3
        except IOError as e:
            if args.config != self.PRH_CONFIG_FILE:
                print("Can't open config file '" + args.config + "': " + e.strerror)
                return 3

        with open(args.input, 'r') as f:
            json_str = f.read()

        json_obj = json.loads(json_str)
        msgs = json_obj

        if args.filter == 'gitlab-sast':
            msgs = json_obj['vulnerabilities']
        elif args.filter == 'semgrep':
            msgs = json_obj['results']
        elif args.filter == 'prospector':
            msgs = json_obj['messages']
        else:
            # filter == none - left for future
            pass

        if args.repository_url and not args.sha:
            print("Missing sha argument")
            return 1

        deduplicated_msgs = []
        for msg in msgs:
            if msg not in deduplicated_msgs:
                deduplicated_msgs.append(dict(msg))

        if args.filter == 'gitlab-sast':
            deduplicated_msgs = self.normalize_gitlab_sast(deduplicated_msgs)
        elif args.filter == 'semgrep':
            deduplicated_msgs = self.normalize_semgrep(args, deduplicated_msgs)
        elif args.filter == 'prospector':
            deduplicated_msgs = self.normalize_prospector(deduplicated_msgs)
        else:
            # filter == none - left for future
            pass

        repository_name = args.repository_url.rsplit("/", 1)[-1]
        filtered_msgs = list(filter(self.filter_message, deduplicated_msgs))

        meta_info = {
            'report_date': str(datetime.now()),
            'report_from_ci': os.environ.get('GITLAB_CI', False),
            'commit_date': os.environ.get('CI_COMMIT_TIMESTAMP', None),
            'commit_author': os.environ.get('CI_COMMIT_AUTHOR', None),
            'commit_title': os.environ.get('CI_COMMIT_TITLE', None),
            'commit_branch': os.environ.get('CI_COMMIT_BRANCH', None),
            'commit_sha': os.environ.get('CI_COMMIT_SHA', None),
            'mr_source_branch': os.environ.get('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME', None),
            'mr_target_branch': os.environ.get('CI_MERGE_REQUEST_TARGET_BRANCH_NAME', None),
            'mr_title': os.environ.get('CI_MERGE_REQUEST_TITLE', None),
            'mr_iid': os.environ.get('CI_MERGE_REQUEST_IID', None),
            'pipeline_job_started_by_id': os.environ.get('GITLAB_USER_ID', None),
            'pipeline_job_started_by_login': os.environ.get('GITLAB_USER_LOGIN', None),
            'pipeline_job_started_by_name': os.environ.get('GITLAB_USER_NAME', None),
            'pipeline_job_started_by_email': os.environ.get('GITLAB_USER_EMAIL', None),
            'pipeline_job_image': os.environ.get('CI_JOB_IMAGE', None),
            'pipeline_job_name': os.environ.get('CI_JOB_NAME', None),
            'pipeline_job_stage': os.environ.get('CI_JOB_STAGE', None),
            'pipeline_job_url': os.environ.get('CI_JOB_URL', None),
            'pipeline_job_date': os.environ.get('CI_JOB_STARTED_AT', None),
            'pipeline_date': os.environ.get('CI_PIPELINE_CREATED_AT', None),
            'pipeline_url': os.environ.get('CI_PIPELINE_URL', None),
            'pipeline_project_path': os.environ.get('CI_PROJECT_PATH', None),
            'pipeline_project_path_slug': os.environ.get('CI_PROJECT_PATH_SLUG', None),
            'pipeline_project_name': os.environ.get('CI_PROJECT_NAME', None),
            'pipeline_project_group_root': os.environ.get('CI_PROJECT_ROOT_NAMESPACE', None),
            'pipeline_project_group': os.environ.get('CI_PROJECT_NAMESPACE', None),
            'pipeline_project_url': os.environ.get('CI_PROJECT_URL', None),
            'pipeline_server_url': os.environ.get('CI_SERVER_URL', None),
        }

        report_string = ''
        if args.json:
            report_content = {
                'meta': meta_info,
                'data': filtered_msgs
            }
            report_string = json.dumps(report_content, indent=2, sort_keys=True)
        else:
            report_string = '''
            <!doctype html>
            <html lang="en">
                <head>
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/default.min.css">
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>
                    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
                    <link href="https://cdn.datatables.net/v/bs4/dt-1.13.6/datatables.min.css" rel="stylesheet">
                    <script src="https://cdn.datatables.net/v/bs4/dt-1.13.6/datatables.min.js"></script>
                    <style>
                        body{ margin:0; background:whitesmoke; }
                        table {
                            table-layout: fixed;
                            border-collapse: collapse;
                            width: 100%;
                        }

                        code {
                            min-width: 600px;
                        }
                        #info-table th:nth-child(2), #info-table th:nth-child(3), #info-table th:nth-child(4), #info-table td:nth-child(2), #info-table td:nth-child(3), #info-table td:nth-child(4) {
                            width: 100px;
                        }
                        #info-table  th:nth-child(1), #info-table td:nth-child(1) {
                            width: 200px;
                        }
                        #info-table th:nth-child(5), #info-table td:nth-child(5) {
                            width: 200px;
                        }
                        #info-table th:nth-child(6), #info-table td:nth-child(6) {
                            width: 300px;
                        }
                        #info-table td {
                            overflow: hidden;
                            text-overflow: ellipsis;
                            word-wrap: break-word;
                        }
                        .red {
                            color: red;
                        }
                        .red-bg {
                        background-color: #fa5858;
                        }
                        .green {
                            color: green;
                        }
                        .orange {
                            color: #FF9900;
                        }
                        .magenta {
                            color: #CC338B;
                        }
                        .none {
                            display: none;
                        }
                        .bold {
                            font-weight: bold;
                        }
                        .controls {
                            margin: 20px 0px 20px 20px;
                            box-shadow: 3px 3px 10px #686060;
                            font-size: 1.2em;
                            padding: 20px 20px 20px 25px;
                            background-color: #e8e6e6;
                        }
                        .filters {
                            line-height: 5em;
                        }
                        table#summary {
                            width: 45%;
                        }
                        .container-fluid > h2 {
                            margin: 20px 20px 20px 20px;
                        }
                        #info-table_wrapper {
                            overflow: hidden;
                        }
                    </style>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/languages/go.min.js"></script>
                    <script>
                    function main() {

                        function filterText(ev) {
                                filterCheckboxes();
                                var input, filter, tr, txtValue;
                                input = document.getElementById("text_filter");
                                filter = input.value.toUpperCase();
                                let table = document.getElementById("info-table");
                                tr = table.getElementsByTagName("tr");
                                for (let i = 0; i < tr.length; i++) {
                                    let td = tr[i].getElementsByTagName("td");
                                    if (td.length == 0) {
                                        continue;
                                    }
                                    let txt = []
                                    for (let td_idx = 0; td_idx < td.length; td_idx++) {
                                        let t = td[td_idx];
                                        txtValue = t.textContent || t.innerText;
                                        txt.push(txtValue.toUpperCase())
                                    }
                                    if (txt.some( (t) => t.includes(filter)) ) {
                                        tr[i].classList.remove("none");
                                    } else {
                                        tr[i].classList.add("none");
                                    }
                                }
                        }

                        function filterCheckboxes() {
                            let severities = [];
                            let impacts = [];
                            $("#filters .severity").each(function(idx) {
                                if (this.checked) {
                                    severities.push(this.value.toUpperCase())
                                }
                            })
                            $("#filters .impact").each(function(idx) {
                                if (this.checked) {
                                    impacts.push(this.value.toUpperCase())
                                }
                            })

                            let table = document.getElementById("info-table");
                            tr = table.getElementsByTagName("tr");
                            for (i = 1; i < tr.length; i++) {
                                let div
                                let impact
                                let severity
                                div = tr[i].getElementsByClassName("data")[0];
                                if ( ! div) {
                                    continue;
                                }
                                impact = div.dataset.impact.toUpperCase()
                                div = tr[i].getElementsByClassName("data")[1];
                                if ( ! div) {
                                    continue;
                                }
                                severity = div.dataset.severity.toUpperCase()

                                if ( ! severities.includes(severity) || ! impacts.includes(impact) ) {
                                    if ( ! tr[i].classList.contains("none") ) {
                                        //console.log("adding add 'none'");
                                        tr[i].classList.add("none");
                                    }
                                } else {
                                    tr[i].classList.remove("none");
                                }
                            }
                        }
                        function formChanged(ev){
                            try {
                                let value = ev.target.value;
                                let type = ev.target.dataset.checkbox;

                                if ( typeof value !== "undefined" && typeof type !== "undefined") {
                                    filterCheckboxes();
                                }

                            } catch(e){
                                //console.log(e)
                            }

                        }

                        badgeMap = { "HIGH": "badge-danger","ERROR": "badge-danger",  "MEDIUM": "badge-warning", "WARNING": "badge-warning", "LOW": "badge-info"}

                        function initCount() {
                            impacts = []
                            severities = []
                            let table = document.getElementById("info-table");
                            tr = table.getElementsByTagName("tr");
                            for (i = 1; i < tr.length; i++) {
                                let div
                                let impact
                                let severity
                                let span
                                div = tr[i].getElementsByClassName("data")[0];
                                if ( ! div) {
                                    continue;
                                }
                                impact = div.dataset.impact.toUpperCase();
                                span = div.getElementsByClassName("badge")[0]
                                span.classList.add(badgeMap[impact]);
                                div = tr[i].getElementsByClassName("data")[1];
                                if ( ! div) {
                                    continue;
                                }
                                severity = div.dataset.severity.toUpperCase();
                                span = div.getElementsByClassName("badge")[0]
                                span.classList.add(badgeMap[severity]);
                                impacts.push(impact);
                                severities.push(severity);

                                div = tr[i].getElementsByClassName("data")[2];
                                confidence = div.dataset.confidence.toUpperCase();
                                span = div.getElementsByClassName("badge")[0]
                                span.classList.add(badgeMap[confidence]);
                            }
                            var severityMap = severities.reduce(function(prev, cur) {
                                prev[cur] = (prev[cur] || 0) + 1;
                                return prev;
                                }, {});
                            var impactMap = impacts.reduce(function(prev, cur) {
                                prev[cur] = (prev[cur] || 0) + 1;
                                return prev;
                                }, {});

                            for (var key in impactMap) {
                                if (impactMap.hasOwnProperty(key)) {
                                    //console.log(key, impactMap[key]);
                                    $("#impact-" + key.toLowerCase() + "-sum").html(impactMap[key])
                                }
                            }
                            for (var key in severityMap) {
                                if (severityMap.hasOwnProperty(key)) {
                                    $("#severity-" + key.toLowerCase() + "-sum").html(severityMap[key])
                                }
                            }
                        }

                        document.getElementById("text_filter").addEventListener("keyup", filterText);
                        document.getElementById("filters").addEventListener("click", formChanged);
                        $('#filters').submit(function(ev) {
                            ev.preventDefault();
                        });
                        initCount();
                        $("#info-table").DataTable({
                            "ordering": true,
                            "paging": false
                        });
                    }
                    </script>
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <title> ''' + str(repository_name) + '''</title>
                </head>
<!-- 
''' + json.dumps({ 'meta': meta_info }, indent=2, sort_keys=True) + '''
-->
                <body>
                <div class="container-fluid">
                <h2>''' + str(repository_name) + '''</h2>
                <div class="row">
                    <div class="col controls">
                        <table class="table table-striped" id="summary">
                            <tr><th>Level</th><th>Impact</th><th>Level</th><th>Severity</th></tr>
                            <tr class=""><td><span class="badge badge-danger"><b>High</b></span></td><td id="impact-high-sum">0</td><td><span class="badge badge-danger"><b>Error</b></span></td><td id="severity-error-sum">0</td></tr>
                            <tr class=""><td></td><td></td><td><span class="badge badge-danger"><b>High</b></span></td><td id="severity-high-sum">0</td></tr>
                            <tr class=""><td><span class="badge badge-warning"><b>Medium</b></span></td><td id="impact-medium-sum">0</td><td><span class="badge badge-warning"><b>Warning</b></span></td><td id="severity-warning-sum">0</td></tr>
                            <tr class=""><td><span class="badge badge-info"><b>Low</b></span></td><td id="impact-low-sum">0</td><td><span class="badge badge-info"><b>Low</b></span></td><td></td></tr>
                        </table>
                    </div>
                    <div class="col controls filters">
                        <form id="filters">
                            <span class="fixed"><b>Impact</b>&nbsp;&nbsp;&nbsp;&nbsp;</span>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input impact" data-checkbox="impact" type="checkbox" id="impact-chackebox-high" value="high" checked>
                            <label class="form-check-label" for="impact-chackebox-high">High</label>
                            </div>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input impact" data-checkbox="impact" type="checkbox" id="impact-chackebox-medium" value="medium" checked>
                            <label class="form-check-label" for="impact-chackebox-medium">Medium</label>
                            </div>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input impact" data-checkbox="impact" type="checkbox" id="impact-chackebox-low" value="low" checked>
                            <label class="form-check-label" for="impact-chackebox-low">Low</label>
                            </div>
                            <br>
                            <span class="fixed"><b>Severity</b>&nbsp;&nbsp;</span>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input severity" data-checkbox="severity" type="checkbox" id="severity-chackebox-error" value="error" checked>
                            <label class="form-check-label" for="severity-chackebox-error">Error</label>
                            </div>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input severity" data-checkbox="severity" type="checkbox" id="severity-chackebox-high" value="high" checked>
                            <label class="form-check-label" for="severity-chackebox-high">High</label>
                            </div>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input severity" data-checkbox="severity" type="checkbox" id="severity-chackebox-warning" value="warning" checked>
                            <label class="form-check-label" for="severity-chackebox-warning">Warning</label>
                            </div>
                            <div class="form-check form-check-inline">
                            <input class="form-check-input severity" data-checkbox="severity" type="checkbox" id="severity-chackebox-low" value="low" checked>
                            <label class="form-check-label" for="severity-chackebox-low">Low</label>
                            </div>
                            <div class="input-group mb-3">
                            <div class="input-group-prepend">
                                <button class="btn btn-outline-secondary" type="button">Search</button>
                            </div>
                            <input type="text" id="text_filter" class="form-control" placeholder="type text here..." aria-label="Search" aria-describedby="search">
                            </div>
                        </form>
                    </div>
                </div>
                </div>
            ''' + self.get_report_body(filtered_msgs) + '''
                </body>
                <script>hljs.highlightAll();
                document.addEventListener('DOMContentLoaded', (event) => { main() })
                </script>
            </html>'''

        report_file = args.output
        if report_file == self.PRH_DEF_OUTPUT_FILE:
            if args.json:
                report_file += '.json'
            else:
                report_file += '.html'

        with open(report_file, 'w') as f:
            f.write(report_string)

        ret_code = 5
        if filtered_msgs:
            print('Still ' + str(len(filtered_msgs)) + ' messages after filtering...')
            ret_code = 1
        else:
            print('No messages after filtering...')
            ret_code = 0

        if args.zero_exit:
            ret_code = 0

        return ret_code


if __name__ == '__main__':
    prh = Prospector2HTML()
    sys.exit(prh.main())
