#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
from datetime import datetime
import argparse
import json
import yaml
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
                    line_n = line-1 if line > 1 else line
                    lines = fp.readlines()[line_n:line_n+11]
            except Exception as e:
                print(str(e))
                return []
            else:
                if path.endswith('.js') and len(lines) > 0 and any(len(l) > 200 for l in lines):
                    return ["minimized js..."]
                line_numbers = []
                for idx, l in enumerate(lines):
                    line_numbers.append(f"{idx+line_n1} {l}")
                return line_numbers

        result = []
        url = args.repository_url.rstrip("/")
        for item in x:
            code = readSnippet(item["path"],item['start']['line'])
            #print(code)
            #print("<pre>" + ''.join(code) + "</pre>")
            try:
                result.append({
                    'code': item['check_id'],
                    'severity  / confidence': f"<span class='red'>{item['extra']['severity']}</span> / {item['extra']['metadata']['confidence']}",
                    'file': f"<a target=\"_blank\" href=\"{url}/blob/{args.sha}/{item['path']}#L{item['start']['line']}\">{item['path']}</a>",
                    'pos': item['start']['col'],
                    'line': item['start']['line'],
                    'message': item['extra']['message'],
                    'snippet': "<pre><code>" + ''.join(code) + "</code></pre>"
                })
            except KeyError as e:
                print("ERROR: Can't normalize semgrep item: ", str(e), " is absent.")

        return result

    def get_report_body(self, obj):
        return json2html.convert(json=obj, escape=False, table_attributes="id=\"info-table\" class=\"table table-bordered table-hover\"")


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

        filtered_msgs = list(filter(self.filter_message, deduplicated_msgs))
        filtered_msgs.sort(key=lambda x: (x['file'], x['line']))

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
            'filtered_message_count': len(deduplicated_msgs),
            'total_message_count': len(filtered_msgs)
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
            <html>
                <head>
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
                    <style>body{ margin:0; background:whitesmoke; }</style>
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/default.min.css">
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>

                    <style>code {width: 600px } td:nth-child(6),td:nth-child(1) { font-size: 10pt} .red {color: red}</style>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/languages/go.min.js"></script>
                </head>
<!-- 
''' + json.dumps({ 'meta': meta_info }, indent=2, sort_keys=True) + '''
-->
                <body>
            ''' + self.get_report_body(filtered_msgs) + '''
                </body>
                <script>hljs.highlightAll();</script>
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
