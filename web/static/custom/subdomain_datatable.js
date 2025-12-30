const subdomain_datatable_columns = [
  {'data': 'id', 'responsivePriority': 1},
  {'data': 'name', 'responsivePriority': 1},
  {'data': 'endpoint_count', 'responsivePriority': 5},
  {'data': 'endpoint_count', 'responsivePriority': 5},
  {'data': 'http_status', 'responsivePriority': 2},
  {'data': 'page_title', 'responsivePriority': 6},
  {'data': 'ip_addresses', 'responsivePriority': 4},
  {'data': 'ip_addresses', 'responsivePriority': 4},
  {'data': 'content_length', 'searchable': false, 'responsivePriority': 7},
  {'data': 'screenshot_path', 'searchable': false, 'responsivePriority': 8},
  {'data': 'response_time', 'responsivePriority': 7},
  {'data': 'technologies', 'responsivePriority': 3},
  {'data': 'http_url', 'responsivePriority': 6},
  {'data': 'cname', 'responsivePriority': 8},
  {'data': 'is_interesting', 'responsivePriority': 5},
  {'data': 'info_count', 'responsivePriority': 9},
  {'data': 'low_count', 'responsivePriority': 9},
  {'data': 'medium_count', 'responsivePriority': 9},
  {'data': 'high_count', 'responsivePriority': 9},
  {'data': 'critical_count', 'responsivePriority': 3},
  {'data': 'todos_count', 'responsivePriority': 8},
  {'data': 'is_important', 'responsivePriority': 4},
  {'data': 'webserver', 'responsivePriority': 7},
  {'data': 'content_type', 'responsivePriority': 8},
  {'data': 'id', 'responsivePriority': 1},
  {'data': 'directories_count', 'responsivePriority': 8},
  {'data': 'subscan_count', 'responsivePriority': 8},
  {'data': 'waf', 'responsivePriority': 6},
  {'data': 'attack_surface', 'responsivePriority': 5},
];

const subdomain_datatable_page_length = 50;
const subdomain_datatable_length_menu = [[50, 100, 500, 1000, -1], [50, 100, 500, 1000, 'All']];

const subdomain_oLanguage = {
  "oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
  "sInfo": "Showing page _PAGE_ of _PAGES_",
  "sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
  "sSearchPlaceholder": "Search...",
  "sLengthMenu": "Results :  _MENU_",
  "sProcessing": "Fetching Subdomains... Please wait..."
};

function subdomain_datatable_col_visibility(subdomain_datatables){
  if(!$('#sub_http_status_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('http_status', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_page_title_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('page_title', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_ip_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('ip_addresses', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_ports_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('ip_addresses', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_content_length_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('content_length', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_http_status_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('http_status', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_response_time_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('response_time', subdomain_datatable_columns)).visible(false);
  }
  if(!$('#sub_screenshot_filter_checkbox').is(":checked")){
    subdomain_datatables.column(get_datatable_col_index('screenshot_path', subdomain_datatable_columns)).visible(false);
  }
}
