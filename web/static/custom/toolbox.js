function show_whois_lookup_modal(){
	$('#modal_title').html('WHOIS Lookup');
	$('#modal-content').empty();
	$('#modal-content').append(`
		<div class="mb-3">
			<label for="whois_domain_name" class="form-label">Domain Name/IP Address</label>
			<input class="form-control" type="text" id="whois_domain_name" required="" placeholder="yourdomain.com">
		</div>
		<div class="mb-3 text-center">
			<button class="btn btn-primary float-end" type="submit" id="search_whois_toolbox_btn">Search Whois</button>
		</div>
	`);
	$('#modal_dialog').modal('show');
}

$(document).on('click', '#search_whois_toolbox_btn', function(){
	var domain = document.getElementById("whois_domain_name").value;
	if (domain) {
		get_domain_whois(domain, show_add_target_btn=true);
	}
	else{
		swal.fire("Error!", 'Please enter the domain/IP Address!', "warning", {
			button: "Okay",
		});
	}
});


function cms_detector(){
	$('#modal_title').html('CMS Detector');
	$('#modal-content').empty();
	$('#modal-content').append(`
		<div class="mb-1">
			<label for="cms_detector_input_url" class="form-label">HTTP URL/Domain Name</label>
			<input class="form-control" type="text" id="cms_detector_input_url" required="" placeholder="https://yourdomain.com">
		</div>
		<small class="mb-3 float-end text-muted">(reNgine uses <a href="https://github.com/Tuhinshubhra/CMSeeK" target="_blank">CMSeeK</a> to detect CMS.)</small>
		<div class="mt-3 mb-3 text-center">
			<button class="btn btn-primary float-end" type="submit" id="detect_cms_submit_btn">Detect CMS</button>
		</div>
	`);
	$('#modal_dialog').modal('show');
}


$(document).on('click', '#detect_cms_submit_btn', function(){
	var url = document.getElementById("cms_detector_input_url").value;
	if (!validURL(url)) {
		swal.fire("Error!", 'Please enter a valid URL!', "warning", {
			button: "Okay",
		});
		return;
	}
	cms_detector_api_call(url);
});


function cms_detector_api_call(url){
	var api_url = `/api/tools/cms_detector/?format=json&url=${url}`;
	
	// Show loading in the same modal
	$('#modal_title').html('CMS Detector');
	$('#modal-content').html(`
		<div class="text-center py-5">
			<div class="spinner-border text-primary" role="status"></div>
			<p class="mt-2 text-muted">Detecting CMS on ${url}...</p>
			<p class="text-muted small">This may take a while, please wait.</p>
		</div>
	`);
	
	if (!$('#modal_dialog').hasClass('show')) {
		$('#modal_dialog').modal('show');
	}
	
	fetch(api_url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": "application/json"
		},
	}).then(response => response.json()).then(function(response) {
		if (response.status) {
			$('#modal_title').html('CMS Details: ' + url);
			
			// Build search bar for new lookups
			let searchBar = `
				<div class="input-group mb-3">
					<input class="form-control" type="text" id="cms_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
					<button class="btn btn-primary" type="button" id="detect_cms_submit_btn">
						<i class="fe-search"></i> Detect
					</button>
				</div>
			`;

			let content = searchBar + `
				<div class="d-flex align-items-start mb-3">
					<img class="d-flex me-3 rounded-circle avatar-lg" src="${response.cms_url}/favicon.ico" alt="${response.cms_name}" onerror="this.style.display='none'">
					<div class="w-100">
						<h4 class="mt-0 mb-1">${response.cms_name}</h4>
						<a href="${response.cms_url}" class="btn btn-xs btn-primary" target="_blank">Visit CMS</a>
					</div>
				</div>

				<div data-simplebar style="max-height: 400px;">
					<h5 class="mb-3 mt-4 text-uppercase bg-light p-2"><i class="fe-info"></i>&nbsp;CMS Details</h5>
					<table class="table table-sm table-borderless">
						<tbody>
							<tr>
								<td class="fw-bold" style="width: 180px;">CMS Name</td>
								<td>${response.cms_name}</td>
							</tr>
							<tr>
								<td class="fw-bold">CMS URL</td>
								<td><a href="${response.cms_url}" target="_blank">${response.cms_url}</a></td>
							</tr>
							<tr>
								<td class="fw-bold">Detection Method</td>
								<td>${response.detection_param}</td>
							</tr>
							<tr>
								<td class="fw-bold">URL</td>
								<td><a href="${response.url}" target="_blank">${response.url}</a> <small class="text-muted">(includes redirects)</small></td>
							</tr>
						</tbody>
					</table>`;

			// WordPress specific details
			if (response.wp_license) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress License:</span> <a href="${response.wp_license}" target="_blank">${response.wp_license}</a></div>`;
			}
			if (response.wp_readme_file) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Readme:</span> <a href="${response.wp_readme_file}" target="_blank">${response.wp_readme_file}</a></div>`;
			}
			if (response.wp_uploads_directory) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Uploads:</span> <a href="${response.wp_uploads_directory}" target="_blank">${response.wp_uploads_directory}</a></div>`;
			}
			if (response.wp_users) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Users:</span> ${response.wp_users}</div>`;
			}
			if (response.wp_version) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Version:</span> <span class="badge badge-soft-info">${response.wp_version}</span></div>`;
			}
			if (response.wp_plugins) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Plugins:</span> ${response.wp_plugins}</div>`;
			}
			if (response.wp_themes) {
				content += `<div class="mb-2"><span class="fw-bold">WordPress Themes:</span> ${response.wp_themes}</div>`;
			}

			// Joomla specific details
			if (response.joomla_version) {
				content += `<div class="mb-2"><span class="fw-bold">Joomla Version:</span> <span class="badge badge-soft-info">${response.joomla_version}</span></div>`;
			}
			if (response.joomla_debug_mode) {
				content += `<div class="mb-2"><span class="fw-bold">Joomla Debug Mode:</span> ${response.joomla_debug_mode}</div>`;
			}
			if (response.joomla_readme_file) {
				content += `<div class="mb-2"><span class="fw-bold">Joomla Readme:</span> <a href="${response.joomla_readme_file}" target="_blank">${response.joomla_readme_file}</a></div>`;
			}
			if (response.joomla_backup_files) {
				content += `<div class="mb-2"><span class="fw-bold">Joomla Backup Files:</span> <a href="${response.joomla_backup_files}" target="_blank">${response.joomla_backup_files}</a></div>`;
			}
			if (response.directory_listing) {
				content += `<div class="mb-2"><span class="fw-bold">Directory Listing:</span> <a href="${response.directory_listing}" target="_blank">${response.directory_listing}</a></div>`;
			}
			if (response.joomla_config_files) {
				content += `<div class="mb-2"><span class="fw-bold">Joomla Config Files:</span> <a href="${response.joomla_config_files}" target="_blank">${response.joomla_config_files}</a></div>`;
			}
			if (response.user_registration_url) {
				content += `<div class="mb-2"><span class="fw-bold">User Registration:</span> <a href="${response.user_registration_url}" target="_blank">${response.user_registration_url}</a></div>`;
			}

			content += `
				<div class="mt-3">
					<a data-bs-toggle="collapse" href="#cms_response_json" aria-expanded="false" aria-controls="cms_response_json">
						<i class="fe-terminal"></i> View Raw Response
					</a>
					<div class="collapse mt-2" id="cms_response_json">
						<pre class="bg-dark text-light p-2 rounded" style="max-height: 200px; overflow: auto;"><code>${htmlEncode(JSON.stringify(response, null, 2))}</code></pre>
					</div>
				</div>
			</div>`;

			$('#modal-content').html(content);
		} else {
			$('#modal-content').html(`
				<div class="alert alert-danger" role="alert">
					<i class="fe-alert-circle me-1"></i> ${response.message || 'CMS detection failed'}
				</div>
				<div class="mb-1">
					<label for="cms_detector_input_url" class="form-label">HTTP URL/Domain Name</label>
					<input class="form-control" type="text" id="cms_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
				</div>
				<small class="mb-3 float-end text-muted">(reNgine uses <a href="https://github.com/Tuhinshubhra/CMSeeK" target="_blank">CMSeeK</a> to detect CMS.)</small>
				<div class="mt-3 mb-3 text-center">
					<button class="btn btn-primary float-end" type="submit" id="detect_cms_submit_btn">Detect CMS</button>
				</div>
			`);
		}
	}).catch(function(error) {
		$('#modal-content').html(`
			<div class="alert alert-danger" role="alert">
				<i class="fe-alert-circle me-1"></i> Error: ${error.message || 'Failed to detect CMS'}
			</div>
			<div class="mb-1">
				<label for="cms_detector_input_url" class="form-label">HTTP URL/Domain Name</label>
				<input class="form-control" type="text" id="cms_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
			</div>
			<small class="mb-3 float-end text-muted">(reNgine uses <a href="https://github.com/Tuhinshubhra/CMSeeK" target="_blank">CMSeeK</a> to detect CMS.)</small>
			<div class="mt-3 mb-3 text-center">
				<button class="btn btn-primary float-end" type="submit" id="detect_cms_submit_btn">Detect CMS</button>
			</div>
		`);
	});
}


function toolbox_cve_detail(){
	$('#modal_title').html('CVE Details Lookup');
	$('#modal-content').empty();
	$('#modal-content').append(`
		<div class="mb-1">
			<label for="cve_id" class="form-label">CVE ID</label>
			<input class="form-control" type="text" id="cve_id" required="" placeholder="CVE-XXXX-XXXX">
		</div>
		<div class="mt-3 mb-3 text-center">
			<button class="btn btn-primary float-end" type="submit" id="cve_detail_submit_btn">Lookup CVE</button>
		</div>
	`);
	$('#modal_dialog').modal('show');
}


$(document).on('click', '#cve_detail_submit_btn', function(){
	var cve_id = document.getElementById("cve_id").value;
	if (cve_id) {
		get_and_render_cve_details(cve_id);
	}
	else{
		swal.fire("Error!", 'Please enter CVE ID!', "warning", {
			button: "Okay",
		});
	}
});


function toolbox_waf_detector(){
	$('#modal_title').html('WAF Detector');
	$('#modal-content').empty();
	$('#modal-content').append(`
		<div class="mb-1">
			<label for="waf_detector_input_url" class="form-label">HTTP URL/Domain Name</label>
			<input class="form-control" type="text" id="waf_detector_input_url" required="" placeholder="https://yourdomain.com">
		</div>
		<small class="mb-3 float-end text-muted">(reNgine uses <a href="https://github.com/EnableSecurity/wafw00f" target="_blank">wafw00f</a> to detect WAF.)</small>
		<div class="mt-3 mb-3 text-center">
			<button class="btn btn-primary float-end" type="submit" id="detect_waf_submit_btn">Detect WAF</button>
		</div>
	`);
	$('#modal_dialog').modal('show');
}


$(document).on('click', '#detect_waf_submit_btn', function(){
	var url = document.getElementById("waf_detector_input_url").value;
	if (!validURL(url)) {
		swal.fire("Error!", 'Please enter a valid URL!', "warning", {
			button: "Okay",
		});
		return;
	}
	waf_detector_api_call(url);
});


function waf_detector_api_call(url){
	var api_url = `/api/tools/waf_detector/?format=json&url=${url}`;
	
	// Show loading in the same modal
	$('#modal_title').html('WAF Detector');
	$('#modal-content').html(`
		<div class="text-center py-5">
			<div class="spinner-border text-primary" role="status"></div>
			<p class="mt-2 text-muted">Detecting WAF on ${url}...</p>
			<p class="text-muted small">This may take a while, please wait.</p>
		</div>
	`);
	
	if (!$('#modal_dialog').hasClass('show')) {
		$('#modal_dialog').modal('show');
	}
	
	fetch(api_url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": "application/json"
		},
	}).then(response => response.json()).then(function(response) {
		if (response.status) {
			$('#modal_title').html('WAF Detection Results');
			
			// Build search bar for new lookups
			let searchBar = `
				<div class="input-group mb-3">
					<input class="form-control" type="text" id="waf_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
					<button class="btn btn-primary" type="button" id="detect_waf_submit_btn">
						<i class="fe-search"></i> Detect
					</button>
				</div>
			`;

			let content = searchBar + `
				<div class="text-center py-4">
					<div class="mb-3">
						<i class="fe-shield text-primary" style="font-size: 48px;"></i>
					</div>
					<h4 class="text-success"><i class="fe-check-circle me-1"></i> WAF Detected!</h4>
					<p class="text-muted mb-3">The following WAF was identified on <strong>${url}</strong></p>
					<div class="alert alert-info d-inline-block px-4">
						<h5 class="mb-0"><i class="fe-shield me-2"></i>${response.results}</h5>
					</div>
				</div>
			`;

			$('#modal-content').html(content);
		} else {
			$('#modal_title').html('WAF Detection Results');
			
			let searchBar = `
				<div class="input-group mb-3">
					<input class="form-control" type="text" id="waf_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
					<button class="btn btn-primary" type="button" id="detect_waf_submit_btn">
						<i class="fe-search"></i> Detect
					</button>
				</div>
			`;

			let message = response.message || 'No WAF detected or detection failed';
			let isNoWaf = message.toLowerCase().includes('no waf') || message.toLowerCase().includes('not detected');
			
			let content = searchBar + `
				<div class="text-center py-4">
					<div class="mb-3">
						<i class="fe-shield-off ${isNoWaf ? 'text-warning' : 'text-danger'}" style="font-size: 48px;"></i>
					</div>
					<h4 class="${isNoWaf ? 'text-warning' : 'text-danger'}">
						<i class="fe-${isNoWaf ? 'alert-triangle' : 'x-circle'} me-1"></i>
						${isNoWaf ? 'No WAF Detected' : 'Detection Failed'}
					</h4>
					<p class="text-muted">${message}</p>
				</div>
			`;

			$('#modal-content').html(content);
		}
	}).catch(function(error) {
		$('#modal-content').html(`
			<div class="alert alert-danger" role="alert">
				<i class="fe-alert-circle me-1"></i> Error: ${error.message || 'Failed to detect WAF'}
			</div>
			<div class="mb-1">
				<label for="waf_detector_input_url" class="form-label">HTTP URL/Domain Name</label>
				<input class="form-control" type="text" id="waf_detector_input_url" value="${url}" placeholder="https://yourdomain.com">
			</div>
			<small class="mb-3 float-end text-muted">(reNgine uses <a href="https://github.com/EnableSecurity/wafw00f" target="_blank">wafw00f</a> to detect WAF.)</small>
			<div class="mt-3 mb-3 text-center">
				<button class="btn btn-primary float-end" type="submit" id="detect_waf_submit_btn">Detect WAF</button>
			</div>
		`);
	});
}
