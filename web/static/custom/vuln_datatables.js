const vuln_datatable_columns = [
	{'data': 'id', 'responsivePriority': 1},
	{'data': 'source', 'responsivePriority': 6},
	{'data': 'type', 'responsivePriority': 4},

	{'data': 'name', 'responsivePriority': 1},
	{'data': 'cvss_metrics', 'responsivePriority': 7},
	{'data': 'tags', 'responsivePriority': 5},
	{'data': 'hackerone_report_id', 'responsivePriority': 8},

	{'data': 'severity', 'responsivePriority': 2},
	{'data': 'cvss_score', 'responsivePriority': 3},
	{'data': 'cve_ids', 'responsivePriority': 4},
	{'data': 'cwe_ids', 'responsivePriority': 6},
	{'data': 'http_url', 'responsivePriority': 3},

	{'data': 'description', 'responsivePriority': 7},
	{'data': 'references', 'responsivePriority': 8},

	{'data': 'discovered_date', 'responsivePriority': 5},

	{'data': 'open_status', 'responsivePriority': 4},

	{'data': 'hackerone_report_id', 'responsivePriority': 8},

	{'data': 'extracted_results', 'responsivePriority': 9},
	{'data': 'curl_command', 'responsivePriority': 9},
	{'data': 'matcher_name', 'responsivePriority': 8},
	{'data': 'request', 'responsivePriority': 9},
	{'data': 'response', 'responsivePriority': 9},
	{'data': 'template', 'responsivePriority': 8},
	{'data': 'template_url', 'responsivePriority': 9},
	{'data': 'template_id', 'responsivePriority': 8},
	{'data': 'impact', 'responsivePriority': 7},
	{'data': 'remediation', 'responsivePriority': 7},
	{'data': 'is_gpt_used', 'responsivePriority': 9},
];

const vuln_datatable_page_length = 50;
const vuln_datatable_length_menu = [[50, 100, 500, 1000, -1], [50, 100, 500, 1000, 'All']];


function vulnerability_datatable_col_visibility(table){
	if(!$('#vuln_source_checkbox').is(":checked")){
		table.column(get_datatable_col_index('vuln_source_checkbox', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_severity_checkbox').is(":checked")){
		table.column(get_datatable_col_index('severity', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_vulnerable_url_checkbox').is(":checked")){
		table.column(get_datatable_col_index('http_url', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_status_checkbox').is(":checked")){
		table.column(get_datatable_col_index('status', vuln_datatable_columns)).visible(false);
	}
}
