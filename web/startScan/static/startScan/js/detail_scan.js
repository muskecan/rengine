function get_ips_from_port(port_number, history_id){
	document.getElementById("detailScanModalLabel").innerHTML='IPs with port ' + port_number + ' OPEN';
	var ip_badge = '';
	fetch('../port/ip/'+port_number+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ips(data));
}

function get_ports_for_ip(ip, history_id){
	console.log(ip, history_id);
	document.getElementById("detailScanModalLabel").innerHTML='Open Ports identified for ' + ip;
	var port_badge = '';
	fetch('../ip/ports/'+ip+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ports(data));
}

function render_ports(data)
{
	var port_badge = ''
	ip_address_content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		badge_color = value[3] ? 'danger' : 'info';
		title = value[3] ? 'Uncommon Port - ' + value[2] : value[2];
		port_badge += `<span class='m-1 badge  badge-soft-${badge_color} bs-tooltip' title='${title}'>${value[0]}/${value[1]}</span>`
	});
	ip_address_content.innerHTML = port_badge;
	$('.bs-tooltip').tooltip();
}

function render_ips(data)
{
	var ip_badge = ''
	content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		badge_color = value[1] ? 'warning' : 'info';
		title = value[1] ? 'CDN IP Address' : '';
		ip_badge += `<span class='m-1 badge  badge-soft-${badge_color} bs-tooltip' title='${title}'>${value[0]}</span>`
	});
	content.innerHTML = ip_badge;
	$('.bs-tooltip').tooltip();
}


function get_endpoints(project, scan_history_id=null, domain_id=null, gf_tags=null){
	var is_endpoint_grouping = false;
	var endpoint_grouping_col = 6;

	var lookup_url = '/api/listEndpoints/?format=datatables&project=' + project;

	if (scan_history_id) {
		lookup_url += `&scan_history=${scan_history_id}`;
	}
	else if (domain_id) {
		lookup_url += `&target_id=${domain_id}`;
	}

	if (gf_tags){
		lookup_url += `&gf_tag=${gf_tags}`
	}
	var endpoint_datatable_columns = [
		{'data': 'id'},
		{'data': 'http_url'},
		{'data': 'http_status'},
		{'data': 'page_title'},
		{'data': 'matched_gf_patterns'},
		{'data': 'content_type'},
		{'data': 'content_length', 'searchable': false},
		{'data': 'techs'},
		{'data': 'webserver'},
		{'data': 'response_time', 'searchable': false},
	];
	var endpoint_table = $('#endpoint_results').DataTable({
		"destroy": true,
		"processing": true,
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sLengthMenu": "Results :  _MENU_",
			"sProcessing": "Processing... Please wait..."
		},
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"stripeClasses": [],
		"lengthMenu": [100, 200, 300, 500, 1000],
		"pageLength": 100,
		'serverSide': true,
		"ajax": {
				'url': lookup_url,
		},
		"rowGroup": {
			"startRender": function(rows, group) {
				return group + ' (' + rows.count() + ' Endpoints)';
			}
		},
		"order": [[ 6, "desc" ]],
		"columns": endpoint_datatable_columns,
		"columnDefs": [
			{
				"targets": [ 0 ],
				"visible": false,
				"searchable": false,
			},
			{
				"targets": [ 7, 8 ],
				"visible": false,
				"searchable": true,
			},
			{
				"render": function ( data, type, row ) {
					var tech_badge = '';
					var web_server = '';
					if (row['techs']){
						tech_badge = `</br>` + parse_technology(row['techs'], "primary", outline=true);
					}

					if (row['webserver']) {
						web_server = `<span class='m-1 badge badge-soft-info' data-toggle="tooltip" data-placement="top" title="Web Server">${row['webserver']}</span>`;
					}

					var url = split_into_lines(data, 70);
					var action_icons = `
					<div class="float-left subdomain-table-action-icons mt-2">
					<span class="m-1">
					<a href="javascript:;" data-clipboard-action="copy" class="badge-link text-primary copyable text-primary" data-toggle="tooltip" data-placement="top" title="Copy Url!" data-clipboard-target="#url-${row['id']}" id="#url-${row['id']}" onclick="setTooltip(this.id, 'Copied!')">
					<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></span>
					</a>
					</div>
					`;
					tech_badge += web_server;

					return `<div class="clipboard copy-txt">` + "<a href='"+ data +`' id="url-${row['id']}" target='_blank' class='text-primary'>`+ url +"</a>" + tech_badge + "<br>" + action_icons ;
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data) {
						return get_http_status_badge(data);
					}
					return '';

				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					return htmlEncode(data);
				},
				"targets": 3,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return parse_comma_values_into_span(data, "info");
					}
					return "";
				},
				"targets": 8,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return parse_comma_values_into_span(data, "danger", outline=true);
					}
					return "";
				},
				"targets": 4,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return get_response_time_text(data);
					}
					return "";
				},
				"targets": 9,
			},
		],
		"initComplete": function(settings, json) {
			api = this.api();
			endpoint_datatable_col_visibility(endpoint_table);
			$(".dtrg-group th:contains('No group')").remove();
		},
		"drawCallback": function () {
			$("body").tooltip({ selector: '[data-toggle=tooltip]' });
			// $('.dataTables_wrapper table').removeClass('table-striped');
			$('.badge').tooltip({ template: '<div class="tooltip status" role="tooltip"><div class="arrow"></div><div class="tooltip-inner"></div></div>' })
			$('.dtrg-group').remove();
			$('.bs-tooltip').tooltip();
			var clipboard = new Clipboard('.copyable');
			$('.bs-tooltip').tooltip();
			clipboard.on('success', function(e) {
				setTooltip(e.trigger, 'Copied!');
				hideTooltip(e.trigger);
			});
			drawCallback_api = this.api();
			setTimeout(function() {
				$(".dtrg-group th:contains('No group')").remove();
			}, 1);
		}
	});

	var radioGroup = document.getElementsByName('grouping_endpoint_row');
	radioGroup.forEach(function(radioButton) {
	  radioButton.addEventListener('change', function() {
	    if (this.checked) {
	      var groupRows = document.querySelectorAll('tr.group');
	      // Remove each group row
				var col_index = get_datatable_col_index(this.value, endpoint_datatable_columns);
				api.page.len(-1).draw();
				api.order([col_index, 'asc']).draw();
				endpoint_table.rowGroup().dataSrc(this.value);
	      Snackbar.show({
	        text: 'Endpoints grouped by ' + this.value,
	        pos: 'top-right',
	        duration: 2500
	      });
	    }
	  });
	});

	$('#endpoint-search-button').click(function () {
		endpoint_table.search($('#endpoints-search').val()).draw() ;
	});
	$('input[name=end_http_status_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(2).visible(true);
		} else {
			endpoint_table.column(2).visible(false);
		}
		window.localStorage.setItem('end_http_status_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_page_title_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(3).visible(true);
		} else {
			endpoint_table.column(3).visible(false);
		}
		window.localStorage.setItem('end_page_title_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_tags_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(4).visible(true);
		} else {
			endpoint_table.column(4).visible(false);
		}
		window.localStorage.setItem('end_tags_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_content_type_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(5).visible(true);
		} else {
			endpoint_table.column(5).visible(false);
		}
		window.localStorage.setItem('end_content_type_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_content_length_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(6).visible(true);
		} else {
			endpoint_table.column(6).visible(false);
		}
		window.localStorage.setItem('end_content_length_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_response_time_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(9).visible(true);
		} else {
			endpoint_table.column(9).visible(false);
		}
		window.localStorage.setItem('end_response_time_filter_checkbox', $(this).is(':checked'));
	});
}

function get_subdomain_changes(scan_history_id){
	$('#table-subdomain-changes').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			if (this.fnSettings().fnRecordsTotal() > 0) {
				$('#subdomain_change_count').empty();
				$("#subdomain_change_count").html(`<span class="badge badge-soft-primary me-1">${this.fnSettings().fnRecordsTotal()}</span>`);
				$('.recon-changes-tab-show').removeAttr('style');
				$('#subdomain_changes_alert').html(`${this.fnSettings().fnRecordsTotal()} Subdomain changes.`)
			}
			else{
				$('#recon_changes_subdomain_div').remove();
			}
			$("#subdomain-changes-loader").remove();
		},
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"destroy": true,
		"stripeClasses": [],
		'serverSide': true,
		"ajax": `/api/listSubdomainChanges/?scan_id=${scan_history_id}&format=datatables`,
		"order": [[ 3, "desc" ]],
		"columns": [
			{'data': 'name'},
			{'data': 'page_title'},
			{'data': 'http_status'},
			{'data': 'content_length'},
			{'data': 'change'},
			{'data': 'http_url'},
			{'data': 'is_cdn'},
			{'data': 'is_interesting'},
		],
		"bInfo": false,
		"columnDefs": [
			{
				"targets": [ 5, 6, 7 ],
				"visible": false,
				"searchable": false,
			},
			{"className": "text-center", "targets": [ 2, 4 ]},
			{
				"render": function ( data, type, row ) {
					badges = '';
					cdn_badge = '';
					tech_badge = '';
					interesting_badge = '';
					if (row['is_cdn'])
					{
						cdn_badge = "<span class='m-1 badge  badge-soft-warning'>CDN</span>"
					}
					if(row['is_interesting'])
					{
						interesting_badge = "<span class='m-1 badge  badge-soft-danger'>Interesting</span>"
					}
					if(cdn_badge || interesting_badge)
					{
						badges = cdn_badge + interesting_badge + '</br>';
					}
					if (row['http_url']) {
						if (row['cname']) {
							return badges + `<a href="`+row['http_url']+`" class="text-primary" target="_blank">`+data+`</a><br><span class="text-dark">CNAME<br><span class="text-warning"> ❯ </span>` + row['cname'].replace(',', '<br><span class="text-warning"> ❯ </span>')+`</span>`;
						}
						return badges + `<a href="`+row['http_url']+`" class="text-primary" target="_blank">`+data+`</a>`;
					}
					return badges + `<a href="https://`+data+`" class="text-primary" target="_blank">`+data+`</a>`;
				},
				"targets": 0
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return htmlEncode(data);
					}
					return "";
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data >= 200 && data < 300) {
						return "<span class='badge  badge-soft-success'>"+data+"</span>";
					}
					else if (data >= 300 && data < 400) {
						return "<span class='badge  badge-soft-warning'>"+data+"</span>";
					}
					else if (data == 0){
						// datatable throws error when no data is returned
						return "";
					}
					return `<span class='badge  badge-soft-danger'>`+data+`</span>`;
				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return `<span class='text-center' style="display:block; text-align:center; margin:0 auto;">${data}</span>`;
					}
					return "";
				},
				"targets": 3,
			},
			{
				"render": function ( data, type, row ) {
					if (data == 'added'){
						return `<span class='badge badge-soft-success'><i class="fe-plus-circle"></i> Added</span>`;
					}
					else{
						return `<span class='badge badge-soft-danger'><i class="fe-minus-circle"></i> Removed</span>`;
					}
				},
				"targets": 4,
			},
		],
	});
}

function get_endpoint_changes(scan_history_id){
	$('#table-endpoint-changes').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			if (this.fnSettings().fnRecordsTotal() > 0) {
				$("#endpoint_change_count").empty();
				$("#endpoint_change_count").html(`${this.fnSettings().fnRecordsTotal()}`);
				$('.recon-changes-tab-show').removeAttr('style');
			}
			else{
				$("#endpoint-changes-div").remove();
			}
			$("#endpoint-changes-loader").remove();
		},
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"destroy": true,
		"stripeClasses": [],
		'serverSide': true,
		"ajax": `/api/listEndPointChanges/?scan_id=${scan_history_id}&format=datatables`,
		"order": [[ 3, "desc" ]],
		"columns": [
			{'data': 'http_url'},
			{'data': 'page_title'},
			{'data': 'http_status'},
			{'data': 'content_length'},
			{'data': 'change'},
		],
		"bInfo": false,
		"columnDefs": [
			{"className": "text-center", "targets": [ 2 ]},
			{
				"render": function ( data, type, row ) {
					var url = split_into_lines(data, 70);
					return "<a href='"+data+"' target='_blank' class='text-primary'>"+url+"</a>";
				},
				"targets": 0
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return htmlEncode(data);
					}
					return "";
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data >= 200 && data < 300) {
						return "<span class='badge  badge-soft-success'>"+data+"</span>";
					}
					else if (data >= 300 && data < 400) {
						return "<span class='badge  badge-soft-warning'>"+data+"</span>";
					}
					else if (data == 0){
						// datatable throws error when no data is returned
						return "";
					}
					return `<span class='badge  badge-soft-danger'>`+data+`</span>`;
				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					if (data == 'added'){
						return `<span class='badge badge-soft-success'><i class="fe-plus-circle"></i> Added</span>`;
					}
					else{
						return `<span class='badge badge-soft-danger'><i class="fe-minus-circle"></i> Removed</span>`;
					}
				},
				"targets": 4,
			},
		],
	});
}

function get_osint_users(scan_id){
	$.getJSON(`/api/queryOsintUsers/?scan_id=${scan_id}&format=json`, function(data) {
		$('#osint-users-count').empty();
		for (var val in data['users']){
			user = data['users'][val]
			$("#osint-users").append(`<span class='badge badge-soft-info  m-1'>${user['author']}</span>`);
		}
		$('#osint-users-count').html(`<span class="badge badge-soft-primary">${data['users'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	}).fail(function(){
		$('#osint-users-count').empty();
		$("#osint-users").append(`<p>No Users discovered.</p>`);
	});
}

function get_screenshot(scan_id){
	var screenshotData = [];
	var container = document.getElementById('screenshots-table');
	
	if (!container) {
		console.error('Screenshot container not found');
		return;
	}
	
	// Replace gridzy with our new gallery container
	container.className = 'screenshot-gallery-container';
	container.innerHTML = '';
	
	$.getJSON(`/api/listSubdomains/?scan_id=${scan_id}&no_page&only_screenshot`)
	.done(function(data) {
		$("#screenshot-loader").remove();
		
		// Check if there are any screenshots
		if (!data || data.length === 0) {
			$("#filter-screenshot").hide();
			container.innerHTML = `
				<div class="screenshot-empty-state">
					<i class="fe-camera-off screenshot-empty-state-icon"></i>
					<h4>No screenshots available</h4>
					<p>Screenshots are captured during the scan if the screenshot task is enabled in your scan engine configuration.</p>
				</div>`;
			return;
		}
		
		screenshotData = data;
		$("#filter-screenshot").show();
		
		// Create grid container
		let grid = document.createElement('div');
		grid.className = 'screenshot-grid';
		grid.id = 'screenshot-grid';
		container.appendChild(grid);
		
		// Render screenshots
		renderScreenshotGrid(data, grid);
		
		// Update screenshot count badge
		updateScreenshotCount(data.length);
		
		// Setup search functionality using the original search bar
		let searchInput = document.getElementById('screenshot-search');
		if (searchInput) {
			// Remove any existing listeners by cloning
			let newSearchInput = searchInput.cloneNode(true);
			searchInput.parentNode.replaceChild(newSearchInput, searchInput);
			
			newSearchInput.addEventListener('input', function(e) {
				filterScreenshots(screenshotData, e.target.value.toLowerCase());
			});
			
			// Update placeholder
			newSearchInput.placeholder = 'Search by domain, title, status...';
		}
		
		// Create lightbox container
		if (!document.getElementById('screenshot-lightbox')) {
			let lightbox = document.createElement('div');
			lightbox.id = 'screenshot-lightbox';
			lightbox.className = 'screenshot-lightbox';
			lightbox.innerHTML = `
				<div class="screenshot-lightbox-content">
					<button class="screenshot-lightbox-close" onclick="closeScreenshotLightbox()">&times;</button>
					<button class="screenshot-lightbox-nav prev" onclick="navigateScreenshot(-1)">&#8249;</button>
					<button class="screenshot-lightbox-nav next" onclick="navigateScreenshot(1)">&#8250;</button>
					<img class="screenshot-lightbox-image" src="" alt="Screenshot" />
					<div class="screenshot-lightbox-info">
						<div class="screenshot-lightbox-title"></div>
					</div>
				</div>
			`;
			lightbox.addEventListener('click', function(e) {
				if (e.target === lightbox) closeScreenshotLightbox();
			});
			document.body.appendChild(lightbox);
		}
		
		// Store data globally for lightbox navigation
		window.screenshotGalleryData = data;
		window.currentScreenshotIndex = 0;
		
		// Keyboard navigation
		document.addEventListener('keydown', function(e) {
			if (!document.getElementById('screenshot-lightbox').classList.contains('active')) return;
			if (e.key === 'Escape') closeScreenshotLightbox();
			if (e.key === 'ArrowLeft') navigateScreenshot(-1);
			if (e.key === 'ArrowRight') navigateScreenshot(1);
		});
		
		// Populate filter dropdowns
		populateScreenshotFilters(data);
	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		console.error('Failed to load screenshots:', textStatus, errorThrown);
		$("#screenshot-loader").remove();
		container.innerHTML = `
			<div class="screenshot-empty-state">
				<i class="fe-alert-circle screenshot-empty-state-icon"></i>
				<h4>Failed to load screenshots</h4>
				<p>Error: ${textStatus}. Please try refreshing the page.</p>
			</div>`;
	});
}

function renderScreenshotGrid(data, grid) {
	grid.innerHTML = '';
	
	data.forEach((item, index) => {
		let statusClass = 'danger';
		if (item.http_status >= 200 && item.http_status < 300) statusClass = 'success';
		else if (item.http_status >= 300 && item.http_status < 400) statusClass = 'warning';
		
		let card = document.createElement('div');
		card.className = 'screenshot-item';
		card.setAttribute('data-index', index);
		card.setAttribute('data-search', `${item.name} ${item.page_title || ''} ${item.http_status || ''} ${item.http_url || ''}`.toLowerCase());
		card.onclick = function() { openScreenshotLightbox(index); };
		
		let badgesHtml = '';
		if (item.http_status) {
			badgesHtml += `<span class="screenshot-badge screenshot-badge-status ${statusClass}">${item.http_status}</span>`;
		}
		if (item.is_interesting) {
			badgesHtml += `<span class="screenshot-badge screenshot-badge-interesting">★</span>`;
		}
		
		card.innerHTML = `
			<img src="/media/${item.screenshot_path}" alt="${item.name}" loading="lazy" onerror="this.parentElement.style.display='none'" />
			<div class="screenshot-item-badges">${badgesHtml}</div>
			<div class="screenshot-item-overlay">
				<div class="screenshot-item-title">${htmlEncode(item.page_title || item.name)}</div>
				<div class="screenshot-item-subtitle">${item.name}</div>
			</div>
		`;
		
		grid.appendChild(card);
	});
}

function filterScreenshots(data, query) {
	let grid = document.getElementById('screenshot-grid');
	if (!grid) return;
	
	let filtered = query ? data.filter(item => {
		let searchStr = `${item.name} ${item.page_title || ''} ${item.http_status || ''} ${item.http_url || ''}`.toLowerCase();
		return searchStr.includes(query);
	}) : data;
	
	renderScreenshotGrid(filtered, grid);
	
	// Update count badge
	updateScreenshotCount(filtered.length);
	
	// Update global data for lightbox navigation
	window.screenshotGalleryData = filtered;
}

function updateScreenshotCount(count) {
	let badge = document.getElementById('screenshot-count-badge');
	if (badge) {
		badge.textContent = count;
	}
}

function openScreenshotLightbox(index) {
	let data = window.screenshotGalleryData;
	if (!data || !data[index]) return;
	
	window.currentScreenshotIndex = index;
	let item = data[index];
	
	let lightbox = document.getElementById('screenshot-lightbox');
	lightbox.querySelector('.screenshot-lightbox-image').src = '/media/' + item.screenshot_path;
	
	let url = item.http_url || `https://${item.name}`;
	lightbox.querySelector('.screenshot-lightbox-title').innerHTML = `
		<a href="${url}" target="_blank">${item.name}</a>
		${item.page_title ? `<br><span style="opacity: 0.7; font-size: 14px;">${htmlEncode(item.page_title)}</span>` : ''}
	`;
	
	lightbox.classList.add('active');
	document.body.style.overflow = 'hidden';
}

function closeScreenshotLightbox() {
	document.getElementById('screenshot-lightbox').classList.remove('active');
	document.body.style.overflow = '';
}

function navigateScreenshot(direction) {
	let data = window.screenshotGalleryData;
	if (!data) return;
	
	let newIndex = window.currentScreenshotIndex + direction;
	if (newIndex < 0) newIndex = data.length - 1;
	if (newIndex >= data.length) newIndex = 0;
	
	openScreenshotLightbox(newIndex);
}

function populateScreenshotFilters(data) {
	let port_array = [];
	let service_array = [];
	let tech_array = [];
	let ip_array = [];
	
	data.forEach(item => {
		// HTTP status
		let http_status = item.http_status;
		let http_status_select = document.getElementById('http_select_filter');
		if (http_status_select && http_status && !$('#http_select_filter').find("option:contains('" + http_status + "')").length) {
			let option = document.createElement('option');
			option.value = http_status;
			option.innerHTML = http_status;
			http_status_select.appendChild(option);
		}
		
		// IPs and ports
		let ips = item.ip_addresses || [];
		ips.forEach(ipData => {
			let ip_address = ipData.address;
			if (ip_address && ip_array.indexOf(ip_address) === -1) {
				ip_array.push(ip_address);
			}
			
			let ports = ipData.ports || [];
			ports.forEach(portData => {
				if (portData.number && port_array.indexOf(portData.number) === -1) {
					port_array.push(portData.number);
				}
				if (portData.service_name && service_array.indexOf(portData.service_name) === -1) {
					service_array.push(portData.service_name);
				}
			});
		});
		
		// Technologies
		let technologies = item.technologies || [];
		technologies.forEach(tech => {
			if (tech.name && tech_array.indexOf(tech.name) === -1) {
				tech_array.push(tech.name);
			}
		});
	});
	
	// Populate port select
	let port_select = document.getElementById('ports_select_filter');
	if (port_select) {
		port_array.sort((a, b) => a - b);
		port_array.forEach(port => {
			if (!$('#ports_select_filter').find("option:contains('" + port + "')").length) {
				let option = document.createElement('option');
				option.value = port;
				option.innerHTML = port;
				port_select.appendChild(option);
			}
		});
	}
	
	// Populate IP select
	let ip_select = document.getElementById('ips_select_filter');
	if (ip_select) {
		ip_array.forEach(ip => {
			if (!$('#ips_select_filter').find("option:contains('" + ip + "')").length) {
				let option = document.createElement('option');
				option.value = ip;
				option.innerHTML = ip;
				ip_select.appendChild(option);
			}
		});
	}
	
	// Populate service select
	let service_select = document.getElementById('services_select_filter');
	if (service_select) {
		service_array.sort();
		service_array.forEach(service => {
			if (!$('#services_select_filter').find("option:contains('" + service + "')").length) {
				let option = document.createElement('option');
				option.value = service;
				option.innerHTML = service;
				service_select.appendChild(option);
			}
		});
	}
	
	// Populate tech select
	let tech_select = document.getElementById('tech_select_filter');
	if (tech_select) {
		tech_array.sort();
		tech_array.forEach(tech => {
			if (!$('#tech_select_filter').find("option:contains('" + tech + "')").length) {
				let option = document.createElement('option');
				option.value = tech;
				option.innerHTML = tech;
				tech_select.appendChild(option);
			}
		});
	}
	
	// Initialize select2 on filter dropdowns
	$(".tagging").select2({
		tags: true,
		placeholder: "Select to filter..."
	});
}

function get_metadata(scan_id){
	// populate detail table
	$.getJSON(`/api/queryMetadata/?scan_id=${scan_id}&format=json`, function(data) {
		$('#metadata-count').empty();
		$('#metadata-table-body').empty();
		for (var val in data['metadata']){
			doc = data['metadata'][val];
			rand_id = get_randid();
			$('#metadata-table-body').append(`<tr id=${rand_id}></tr>`);
			if (doc['doc_name']) {
				filename = `<a href=${doc['url']} target="_blank" class="text-primary">${truncate(doc['doc_name'], 30)}</a>`;
			}
			else{
				filename = ''
			}
			subdomain = `<span class='text-muted bs-tooltip' title='Subdomain'>${doc['subdomain']['name']}</span>`;
			$(`#${rand_id}`).append(`<td class="td-content">${filename}</br>${subdomain}</td>`);
			if (doc['author']){
				$(`#${rand_id}`).append(`<td class="td-content text-center">${doc['author']}</td>`);
			}
			else{
				$(`#${rand_id}`).append('<td></td>')
			}
			if (doc['producer'] || doc['creator'] || doc['os']) {
				metadata = '';
				metadata += doc['producer'] ? 'Software: ' + doc['producer'] : '';
				metadata += doc['creator'] ? '/' + doc['creator'] : 'dsdd';
				metadata += doc['os'] ? `<br> <span class='badge badge-soft-danger'> OS: ` + doc['os'] + '</span>': '';
				if (doc['creation_date']) {
					metadata += `<br>Created On: ${doc['creation_date']}`;
				}
				if (doc['modified_date']) {
					metadata += `<br>Modified On: ${doc['modified_date']}`;
				}
				$(`#${rand_id}`).append(`<td class="td-content">${metadata}</td>`);
			}
			else{
				$(`#${rand_id}`).append('<td></td>')
			}
		}
		$('#metadata-count').html(`<span class="badge badge-soft-primary">${data['metadata'].length}</span>`);
		$('.bs-tooltip').tooltip();
	});
}


function get_emails(scan_id){
	var exposed_count = 0;
	$.getJSON(`/api/queryEmails/?scan_id=${scan_id}&format=json`, function(data) {
		$('#emails-count').empty();
		$('#email-table-body').empty();
		for (var val in data['emails']){
			email = data['emails'][val];
			rand_id = get_randid();
			$('#email-table-body').append(`<tr id=${rand_id}></tr>`);
			$(`#${rand_id}`).append(`<td class="td-content">${email['address']}</td>`);
			if (email['password']) {
				$(`#${rand_id}`).append(`<td class="td-content"><span class="badge badge-soft-danger">${email['password']}</span></td>`);
				exposed_count++;
			}
		}
		$('#emails-count').html(`<span class="badge badge-soft-primary">${data['emails'].length}</span>`);
		if (exposed_count > 0 ) {
			$('#exposed_summary').html(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-triangle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> <span class="badge badge-soft-danger">${exposed_count}</span> Exposed Credentials`);
		}
	});
}


function get_employees(scan_id){
	$.getJSON(`/api/queryEmployees/?scan_id=${scan_id}&format=json`, function(data) {
		$('#employees-count').empty();
		$('#employees-table-body').empty();
		for (var val in data['employees']){
			emp = data['employees'][val];
			rand_id = get_randid();
			$('#employees-table-body').append(`<tr id=${rand_id}></tr>`);
			$(`#${rand_id}`).append(`<td class="td-content">${emp['name']}</td>`);
			$(`#${rand_id}`).append(`<td class="td-content">${emp['designation']}</td>`);
		}
		$('#employees-count').html(`<span class="badge badge-soft-primary">${data['employees'].length}</span>`);
	});
}


function get_dorks(scan_id){
	$("#dorking_result_card").hide();
	$.getJSON(`/api/queryDorks/?scan_id=${scan_id}&format=json`, function(data) {
		if ($.isEmptyObject(data['dorks'])) {
			return
		}
		// unhide div
		$("#dorking_result_card").show();
		var is_first = true;
		for (var val in data['dorks']){
			var dorks = data['dorks'][val];
			if (is_first) {
				active = 'active show';
			}
			else {
				active = '';
			}
			$("#dork_type_vertical_tablist").append(`<a class="nav-link ${active} mb-1" id="v-${val}-tab" data-bs-toggle="pill" href="#v-${val}" role="tab" aria-controls="v-${val}" aria-selected="true"> ${convertToCamelCase(val)}</a>`);
			// create tab content
			var tab_content = `<div class="tab-pane fade ${active}" id="v-${val}" role="tabpanel" aria-labelledby="v-${val}-tab"><ul>`;
			for (var dork in dorks) {
				var dork_data = dorks[dork];
				tab_content += `<li><a href="${dork_data.url}" target="_blank">${dork_data.url}</a></li>`;
			}
			tab_content += `</ul></div>`;
			$('#dork_tab_content').append(tab_content);
			is_first = false;
		}
	});
}

//
// function get_dork_summary(scan_id){
// 	$.getJSON(`/api/queryDorkTypes/?scan_id=${scan_id}&format=json`, function(data) {
// 		$('#dork-category-count').empty();
// 		for (var val in data['dorks']){
// 			dork = data['dorks'][val]
// 			$("#osint-dork").append(`<span class='badge badge-soft-info  m-1' data-toggle="tooltip" title="${dork['count']} Results found in this dork category." onclick="get_dork_details('${dork['type']}', ${scan_id})">${dork['type']}</span>`);
// 		}
// 		$('#dork-category-count').html(`<span class="badge badge-soft-primary">${data['dorks'].length}</span>`);
// 		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
// 	});
// }


function get_dork_details(dork_type, scan_id){
	// render tab modal
	$('.modal-title').html('Dorking Results in category: <b>' + dork_type + '</b>');
	$('#modal_dialog').modal('show');
	$('.modal-text').empty(); $('#modal-footer').empty();
	$('.modal-text').append(`<div class='outer-div' id="modal-loader"><span class="inner-div spinner-border text-primary align-self-center loader-sm"></span></div>`);
	$.getJSON(`/api/queryDorks/?scan_id=${scan_id}&type=${dork_type}&format=json`, function(data) {
		$('#modal-loader').empty();
		$('#modal-content').append(`<b>${data['dorks'].length} results found in this dork category.</b>`);
		$('#modal-content').append(`<ul id="dork-detail-modal-ul"></ul>`);
		for (dork in data['dorks']){
			dork_obj = data['dorks'][dork];
			$("#dork-detail-modal-ul").append(`<li><a href="${dork_obj['url']}" target="_blank" class="text-primary">${dork_obj['description']}</a></li>`);
		}
	});
}


function get_vulnerability_modal(scan_id=null, severity=null, subdomain_id=null, subdomain_name=null){
	var url = `/api/listVulnerability/?&format=json`;

	if (scan_id) {
		url += `&scan_history=${scan_id}`;
	}

	if (severity != null) {
		url += `&severity=${severity}`;
	}

	if (subdomain_id) {
		url += `&subdomain_id=${subdomain_id}`;
	}


	// else{
	// 	url = `/api/listVulnerability/?severity=${severity}&subdomain_name=${subdomain_name}&format=json`;
	// }
	switch (severity) {
		case 0:
		severity_title = 'Informational'
		break;
		case 1:
		severity_title = 'Low'
		break;
		case 2:
		severity_title = 'Medium'
		break;
		case 3:
		severity_title = 'High'
		break;
		case 4:
		severity_title = 'Critical'
		break;
		default:
		severity_title = ''
	}

	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	Swal.fire({
		title: `Fetching ${severity_title} vulnerabilities for ${subdomain_name}...`
	});
	swal.showLoading();

	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		console.log(response);
		swal.close();
		$('#xl-modal_title').html(`${subdomain_name}`);
		render_vulnerability_in_xl_modal(response['count'], subdomain_name, response['results'])
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});

}


function get_endpoint_modal(project, scan_id, subdomain_id, subdomain_name){
	// This function will display a xl modal with datatable for displaying endpoints
	// associated with the subdomain
	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	if (scan_id) {
		url = `/api/listEndpoints/?project=${project}&scan_id=${scan_id}&subdomain_id=${subdomain_id}&format=json`
	}
	else{
		url = `/api/listEndpoints/?project=${project}&subdomain_id=${subdomain_id}&format=json`
	}

	Swal.fire({
		title: `Fetching Endpoints for ${subdomain_name}...`
	});
	swal.showLoading();

	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		console.log(response);
		swal.close();
		$('#xl-modal_title').html(`${subdomain_name}`);
		render_endpoint_in_xlmodal(response['count'], subdomain_name, response['results'])
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});

}

function get_directory_modal(scan_id=null, subdomain_id=null, subdomain_name=null){
	// This function will display a xl modal with datatable for displaying endpoints
	// associated with the subdomain
	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	if (scan_id) {
		url = `/api/listDirectories/?scan_id=${scan_id}&subdomain_id=${subdomain_id}&format=json`
	}
	else{
		url = `/api/listDirectories/?subdomain_id=${subdomain_id}&format=json`
	}

	Swal.fire({
		title: `Fetching Directories for ${subdomain_name}...`
	});
	swal.showLoading();

	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		console.log(response);
		swal.close();
		$('#xl-modal_title').html(`${subdomain_name}`);
		render_directories_in_xl_modal(response['count'], subdomain_name, response['results'])
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});

}

function create_log_element(log) {
	let logElement = document.createElement("p");
	innerHTML = `
	<p>
	  <p data-bs-toggle="collapse" data-bs-target="#collapse${log.id}" class="text-primary">
		<i class="fe-terminal"></i>${log.command}
	  </p>
	</p>`
	if (log.output != ''){
		innerHTML += `<div class="collapse" id="collapse${log.id}"><code style="white-space: pre-line" class="card card-body">${log.output}</code></div>`;
	}
	logElement.innerHTML = innerHTML;
	return logElement;
}

function get_logs_modal(scan_id=null, activity_id=null) {

	// This function will display a xl modal with datatable for displaying endpoints
	// associated with the subdomain
	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	if (scan_id) {
		url = `/api/listScanLogs?scan_id=${scan_id}&format=json`
		title = `Fetching logs for scan ${scan_id}`
	}
	else{
		url = `/api/listActivityLogs?activity_id=${activity_id}&format=json`
		title = `Fetching logs for activity ${activity_id}`
	}

	Swal.fire({
		title: title
	});
	swal.showLoading();

	// Get the initial logs
	fetch(url)
	.then(response => response.json())
	.then(data => {
		console.log(data);
		swal.close();
		$('#xl-modal_title').html(`Logs for scan #${scan_history_id}`);
		data.results.forEach(log => {
			$('#xl-modal-content').append(create_log_element(log));
		})
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});
}

function add_todo_for_scanhistory_modal(scan_history_id){
	$("#todoTitle").val('');
	$("#todoDescription").val('');

	$('#addTaskModal').modal('show');
	subdomain_dropdown = document.getElementById('todoSubdomainDropdown');
	$.getJSON(`/api/querySubdomains?scan_id=${scan_history_id}&no_lookup_interesting&format=json`, function(data) {
		document.querySelector("#selectedSubdomainCount").innerHTML = data['subdomains'].length + ' Subdomains';
		for (var subdomain in data['subdomains']){
			subdomain_obj = data['subdomains'][subdomain];
			var option = document.createElement('option');
			option.value = subdomain_obj['id'];
			option.innerHTML = subdomain_obj['name'];
			subdomain_dropdown.appendChild(option);
		}
	});
}

// listen to save todo event

$(".add-scan-history-todo").click(function(){
	var title = document.getElementById('todoTitle').value;

	var description = document.getElementById('todoDescription').value;

	data = {
		'title': title,
		'description': description
	}


	scan_id = parseInt(document.getElementById('summary_identifier_val').value);
	data['scan_history_id'] = scan_id;

	if ($("#todoSubdomainDropdown").val() != 'Choose Subdomain...') {
		data['subdomain_id'] = parseInt($("#todoSubdomainDropdown").val());
	}

	fetch('/api/add/recon_note/', {
		method: 'post',
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	}).then(res => res.json())
	.then(function (response) {
		console.log(response);
		if (response.status) {
			Snackbar.show({
				text: 'Todo Added.',
				pos: 'top-right',
				duration: 1500,
			});
		}
		else{
			swal.fire("Error!", "Could not add recon note, " + response.message, "warning", {
				button: "Okay",
			});
		}
		$('#addTaskModal').modal('hide');
		get_recon_notes(null, scan_id);
	});
});


function add_note_for_subdomain(subdomain_id, subdomain_name){
	console.log(subdomain_name);
	$('#todo-modal-subdomain-name').html(subdomain_name);
	$("#subdomainTodoTitle").val('');
	$("#subdomainTodoDescription").val('');

	$('#add-todo-subdomain-submit-button').attr('onClick', `add_note_for_subdomain_handler(${subdomain_id});`);


	$('#addSubdomainTaskModal').modal('show');

}


function add_note_for_subdomain_handler(subdomain_id){
	var title = document.getElementById('subdomainTodoTitle').value;
	var description = document.getElementById('subdomainTodoDescription').value;
	var project = document.querySelector('input[name="current_project"]').value;

	data = {
		'title': title,
		'description': description,
		'subdomain_id': subdomain_id,
		'project': project,
	}

	console.log(data);

	fetch('/api/add/recon_note/', {
		method: 'post',
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	}).then(res => res.json())
	.then(function (response) {

		if (response.status) {
			Snackbar.show({
				text: 'Todo Added.',
				pos: 'top-right',
				duration: 1500,
			});
		}
		else{
			swal.fire("Error!", response.message, "warning", {
				button: "Okay",
			});
		}
		$('#subdomain_scan_results').DataTable().ajax.reload();
		$('#addSubdomainTaskModal').modal('hide');
	});

}

function download_subdomains(scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/querySubdomains?format=json&no_lookup_interesting`;
	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	if (domain_name) {
		$('.modal-title').html(count + ' Subdomains for : <b>' + domain_name + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Subdomains');
	}

	$('.modal-text').empty(); $('#modal-footer').empty();
	$('.modal-text').append(`<div class='outer-div' id="modal-loader"></div>`);
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data['subdomains'].length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data['subdomains'].length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data['subdomains']){
				subdomain_obj = data['subdomains'][subdomain];
				subdomains += subdomain_obj['name'] + '\n'
			}
			$('#all_subdomains_text_area').append(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('subdomains-${domain_name}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Subdomains", "Could not find any subdomains.", "warning", {
				button: "Okay",
			});
		}
	}).fail(function(){
		swal.fire("No Subdomains", "Could not find any subdomains.", "warning", {
			button: "Okay",
		});
	});
}

function download_interesting_subdomains(project, scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Interesting Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/queryInterestingSubdomains/?format=json&project=${project}`;
	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	if (domain_name) {
		$('.modal-title').html( count + ' Interesting Subdomains for : <b>' + domain_name + '</b>');
	}
	else{
		$('.modal-title').html( count + ' Interesting Subdomains');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close()
		if (data.length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data.length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="interesting_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data){
				subdomains += data[subdomain]['name'] + '\n'
			}
			$('#interesting_subdomains_text_area').append(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('interesting_subdomains-${domain_name}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#interesting_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Interesting Subdomains", "Could not find any interesting subdomains.", "warning", {
				button: "Okay",
			});
		}

	}).fail(function(){
		swal.fire("No Interesting Subdomains", "Could not find any interesting subdomains.", "warning", {
			button: "Okay",
		});
	});
}

function download_interesting_endpoints(scan_id, domain_name){
	Swal.fire({
		title: 'Querying Interesting Endpoints...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	if (scan_id) {
		url = `/api/listInterestingEndpoints/?scan_id=${scan_id}&format=json&no_page`;
	}
	else{
		url = `/api/listInterestingEndpoints/?format=json&no_page`;
	}
	if (domain_name) {
		$('.modal-title').html( count + ' Interesting Endpoints for : <b>' + domain_name + '</b>');
	}
	else{
		$('.modal-title').html( count + ' Interesting Endpoints');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data.length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data.length);
			$('#modal-content').empty();
			endpoints = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="interesting_endpoints_text_area" rows="10" spellcheck="false"></textarea>`);
			for (endpoint in data){
				endpoints += data[endpoint]['http_url'] + '\n'
			}
			$('#interesting_endpoints_text_area').append(endpoints);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('interesting_endpoints-${domain_name}.txt', endpoints);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Endpoints!" data-clipboard-target="#interesting_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`);
		}
		else{
			swal.fire("No Interesting Endpoints", "Could not find any interesting Endpoints.", "warning", {
				button: "Okay",
			});
		}

	}).fail(function(){
		swal.fire("No Interesting Endpoints", "Could not find any interesting Endpoints.", "warning", {
			button: "Okay",
		});
	});
}


function download_important_subdomains(scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Interesting Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important`;
	if (scan_id) {
		url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important&scan_id=${scan_id}`;
	}
	else if (domain_id){
		url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important&target_id=${domain_id}`;
	}
	if (domain_name) {
		$('.modal-title').html(count + ' Subdomains marked as important : <b>' + domain_name + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Subdomains marked as important');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data['subdomains'].length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data['subdomains'].length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data['subdomains']){
				subdomain_obj = data['subdomains'][subdomain];
				subdomains += subdomain_obj['name'] + '\n'
			}
			$('#all_subdomains_text_area').append(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('important-subdomains-${domain_name}.txt', subdomains);" class="m-1 btn btn-primary copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-dark copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Important Endpoints", "No subdomains has been marked as important.", "warning", {
				button: "Okay",
			});
		}
	}).fail(function(){
		swal.fire("No Important Endpoints", "No subdomains has been marked as important.", "warning", {
			button: "Okay",
		});
	});
}

function download_endpoints(scan_id=null, domain_id=null, domain_name='', pattern=null){
	Swal.fire({
		title: 'Querying Endpoints...'
	});
	swal.showLoading();
	var count = `<span class="modal_count">Loading... </span>`;

	var url = `/api/queryEndpoints/?format=json&only_urls`;

	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if (domain_id) {
		url += `&target_id=${domain_id}`;
	}

	if (pattern) {
		url += `&pattern=${pattern}`;
	}

	if (domain_name) {
		$('.modal-title').html( count + ' Endpoints for : <b>' + domain_name + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Endpoints');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		$('#modal_dialog').modal('show');
		$('.modal_count').html(data['endpoints'].length);
		$('#modal-content').empty();
		endpoints = '';
		$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_endpoints_text_area" rows="10" spellcheck="false"></textarea>`);
		for (endpoint in data['endpoints']){
			endpoint_obj = data['endpoints'][endpoint];
			endpoints += endpoint_obj['http_url'] + '\n'
		}
		$('#all_endpoints_text_area').append(endpoints);
		$("#modal-footer").empty();
		if (domain_name) {
			$("#modal-footer").append(`<a href="javascript:download('endpoints-${domain_name}.txt', endpoints);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
		}
		else{
			$("#modal-footer").append(`<a href="javascript:download('endpoints-all.txt', endpoints);" class="m-1 btn btn-primary copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
		}
		$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`);
	}).fail(function(){
	});
}

function initiate_subscan(subdomain_ids){
	var engine_id = $('#subtaskScanEngine').val();
	var tasks = []
	var $engine_tasks = $('#engineTasks').find('input')
	$engine_tasks.each(function(i){
		if ($(this).is(':checked')){
			tasks.push(this.id)
		}
	})
	console.log(tasks)
	if (tasks.length === 0) {
		Swal.fire({
			title: 'Oops!',
			text: 'No subtasks selected. Please choose at least one subtask !',
			icon: 'error'
		});
		return;
	}
	var data = {
		'subdomain_ids': subdomain_ids,
		'tasks': tasks,
		'engine_id': engine_id,
	};
	Swal.fire({
		title: 'Initiating subtask...',
		allowOutsideClick: false
	});
	swal.showLoading();
	fetch('/api/action/initiate/subtask/', {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(function (response) {
		swal.close();
		if (response['status']) {
			Snackbar.show({
				text: 'Subtask initiated successfully!',
				pos: 'top-right',
				duration: 2500
			});
		}
		else{
			Swal.fire({
				title:  'Could not initiate subtask!',
				icon: 'fail',
			});
		}
	});

}


// initiate sub scan
$('#btn-initiate-subtask').on('click', function(){
	$('#subscan-modal').modal('hide');
	if ($('#btn-initiate-subtask').attr('multiple-subscan') === 'true') {
		var subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		var subdomain_ids = [];
		for (var i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		initiate_subscan(subdomain_ids);
	}
	else{
		var subdomain_id = $('#subtask_subdomain_id').val();
		initiate_subscan([subdomain_id]);
	}
});


// Load engine tasks on modal load and engine input change
function load_engine_tasks(engine_name){
	var tasks = []
	var html = ''
	var url = `/api/listEngines/?format=json`;
	console.log(url);
	$.getJSON(url, function(data) {
		console.log(data);
		var engines = data.engines
		console.log(engines);
		console.log(engine_name);
		$.each(engines, function(i, engine){
			console.log(`${engine.engine_name} == ${engine_name}`)
			if (engine.engine_name === engine_name){
				tasks = engine.tasks
				console.log(tasks)
			}
		})
		$.each(tasks, function(i, task){
			html += `
			<div class="mt-1">
				<div class="form-check">
					<input type="checkbox" class="form-check-input" id="${task}">
					<label class="form-check-label" for="${task}">${task}</label>
				</div>
			</div>`
		});
		console.log(html)
		$('#engineTasks').html(html);
	})
}

$('#subscan-modal').on('shown.bs.modal', function () {
	var engine_name = $('#subtaskScanEngine option:selected').text();
	load_engine_tasks(engine_name);
})

$('#subtaskScanEngine').on('change', function(){
	var engine_name = $('#subtaskScanEngine option:selected').text();
	load_engine_tasks(engine_name);
})

// download subdomains
function downloadSelectedSubdomains(domain_name){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		})
	} else {
		Swal.fire({
			title: 'Querying Selected Subdomains...'
		});
		swal.showLoading();

		subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		var subdomain_ids = [];
		for (var i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		var data = {'subdomain_ids': subdomain_ids};
		fetch('/api/querySubdomains/', {
			method: 'POST',
			credentials: "same-origin",
			headers: {
				"X-CSRFToken": getCookie("csrftoken"),
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(data)
		})
		.then(response => response.json())
		.then(function (response) {
			swal.close();
			if (response['status']) {
				$('#modal_dialog').modal('show');
				$('.modal_count').html(response['results'].length);
				$('#modal-content').empty();
				subdomains = '';
				$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="selected_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
				for (subdomain in response['results']){
					subdomain_obj = response['results'][subdomain];
					subdomains += subdomain_obj + '\n'
				}
				$('#selected_subdomains_text_area').append(subdomains);
				$("#modal-footer").empty();
				$("#modal-footer").append(`<a href="javascript:download('subdomains-${domain_name}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
				$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#selected_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
			}
			else{
				Swal.fire({
					title: 'Oops! Could not download selected subdomains.',
					icon: 'error',
					padding: '2em'
				});
			}
		});
	}
}


function deleteMultipleSubdomains(){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		});
	} else {
		// atleast one target is selected
		Swal.fire({
			showCancelButton: true,
			title: 'Are you sure you want to delete ' + checkedCount() + ' Subdomains?',
			text: 'Do you really want to delete these subdomains? This action cannot be undone.',
			icon: 'error',
			confirmButtonText: 'Delete',
		}).then((result) => {
			if (result.isConfirmed) {
				Swal.fire({
					title: 'Deleting Subdomain...',
					allowOutsideClick: false
				});
				swal.showLoading();

				subdomain_item = document.getElementsByClassName("subdomain_checkbox");
				var subdomain_ids = [];
				for (var i = 0; i < subdomain_item.length; i++) {
					if (subdomain_item[i].checked) {
						subdomain_ids.push($(subdomain_item[i]).val());
					}
				}
				var data = {'subdomain_ids': subdomain_ids};
				fetch('/api/action/subdomain/delete/', {
					method: 'POST',
					credentials: "same-origin",
					headers: {
						"X-CSRFToken": getCookie("csrftoken"),
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(data)
				})
				.then(response => response.json())
				.then(function (response) {
					swal.close();
					if (response['status']) {
						// remove all rows
						var table = $('#subdomain_scan_results').DataTable();
						for (var id in subdomain_ids) {
							table.row('#subdomain_row_' + id).remove().draw();
						}
						Snackbar.show({
							text: 'Subdomain successfully deleted!',
							pos: 'top-right',
							duration: 2500
						});
					}
					else{
						Swal.fire({
							title:  'Could not delete Subdomain!',
							icon: 'fail',
						});
					}
				});
			}
		});
	}
}


function initiateMultipleSubscan(){
		$('#subscan-modal').modal('show');
		$('a[data-toggle="tooltip"]').tooltip("hide")
		// to distinguish multiple subscan or single, put a extra attribute on button
		$('#btn-initiate-subtask').attr('multiple-subscan', true);
}


function detect_subdomain_cms(http_url, http_status){
	if (http_status == 0) {
		var message = `reNgine has earlier identified that this subdomain did not return any HTTP status and likely the subdomain is not alive. reNgine may not be able to detect any CMS, would you still like to continue?`;
	}
	else if (http_status != 200) {
		var message = `reNgine has earlier identified that this subdomain has HTTP status as ${http_status} and likely that reNgine will not detect any CMS, would you still like to continue?`;
	}

	if (http_status != 200 || http_status == 0) {
		Swal.fire({
			showCancelButton: true,
			title: 'Detect CMS',
			text: message,
			icon: 'warning',
			confirmButtonText: 'Detect CMS',
		}).then((result) => {
			if (result.isConfirmed) {
				cms_detector_api_call(http_url);
			}
		});
	}
	else{
		cms_detector_api_call(http_url);
	}
}
