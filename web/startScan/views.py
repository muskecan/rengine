import markdown

from celery import group
from weasyprint import HTML, CSS
from datetime import datetime
from django.contrib import messages
from django.db import models
from django.db.models import Count, Case, When, IntegerField
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone
from django_celery_beat.models import (ClockedSchedule, IntervalSchedule, PeriodicTask)
from rolepermissions.decorators import has_permission_decorator


from reNgine.celery import app
from reNgine.charts import *
from reNgine.common_func import *
from reNgine.definitions import ABORTED_TASK, SUCCESS_TASK
from reNgine.tasks import create_scan_activity, initiate_scan, run_command
from scanEngine.models import EngineType
from startScan.models import *
from targetApp.models import *
from dashboard.models import Project


def scan_history(request, slug):
    host = ScanHistory.objects.filter(domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "scan_history": host}
    return render(request, 'startScan/history.html', context)


def subscan_history(request, slug):
    subscans = SubScan.objects.filter(scan_history__domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "subscans": subscans}
    return render(request, 'startScan/subscan_history.html', context)


def detail_scan(request, id, slug):
    ctx = {}

    # Get scan objects
    scan = get_object_or_404(ScanHistory, id=id)
    domain_id = scan.domain.id
    scan_engines = EngineType.objects.order_by('engine_name').all()
    recent_scans = ScanHistory.objects.filter(domain__id=domain_id)
    last_scans = (
        ScanHistory.objects
        .filter(domain__id=domain_id)
        .filter(tasks__overlap=['subdomain_discovery'])
        .filter(id__lte=id)
        .filter(scan_status=2)
    )

    # Get all kind of objects associated with our ScanHistory object
    emails = Email.objects.filter(emails__in=[scan])
    employees = Employee.objects.filter(employees__in=[scan])
    subdomains = Subdomain.objects.filter(scan_history=scan)
    endpoints = EndPoint.objects.filter(scan_history=scan)
    vulns = Vulnerability.objects.filter(scan_history=scan)
    vulns_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulns)
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains)
    geo_isos = CountryISO.objects.filter(ipaddress__in=ip_addresses)
    scan_activity = ScanActivity.objects.filter(scan_of__id=id).order_by('time')
    cves = CveId.objects.filter(cve_ids__in=vulns)
    cwes = CweId.objects.filter(cwe_ids__in=vulns)

    # HTTP statuses
    http_statuses = (
        subdomains
        .exclude(http_status=0)
        .values('http_status')
        .annotate(Count('http_status'))
    )

    # CVEs / CWes
    common_cves = (
        cves
        .annotate(nused=Count('cve_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )
    common_cwes = (
        cwes
        .annotate(nused=Count('cwe_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )

    # Tags
    common_tags = (
        vulns_tags
        .annotate(nused=Count('vuln_tags'))
        .order_by('-nused')
        .values('name', 'nused')
        [:7]
    )

    # Countries
    asset_countries = (
        geo_isos
        .annotate(count=Count('iso'))
        .order_by('-count')
    )

    # Subdomains
    subdomain_count = (
        subdomains
        .values('name')
        .distinct()
        .count()
    )
    alive_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(http_status__exact=200)
        .count()
    )
    important_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(is_important=True)
        .count()
    )

    # Endpoints
    endpoint_count = (
        endpoints
        .values('http_url')
        .distinct()
        .count()
    )
    endpoint_alive_count = (
        endpoints
        .filter(http_status__exact=200) # TODO: use is_alive() func as it's more precise
        .values('http_url')
        .distinct()
        .count()
    )

    # Vulnerabilities
    common_vulns = (
        vulns
        .exclude(severity=0)
        .values('name', 'severity')
        .annotate(count=Count('name'))
        .order_by('-count')
        [:10]
    )
    info_count = vulns.filter(severity=0).count()
    low_count = vulns.filter(severity=1).count()
    medium_count = vulns.filter(severity=2).count()
    high_count = vulns.filter(severity=3).count()
    critical_count = vulns.filter(severity=4).count()
    unknown_count = vulns.filter(severity=-1).count()
    total_count = vulns.count()
    total_count_ignore_info = vulns.exclude(severity=0).count()

    # Emails
    exposed_count = emails.exclude(password__isnull=True).count()

    # Build render context
    ctx = {
        'scan_history_id': id,
        'history': scan,
        'scan_activity': scan_activity,
        'subdomain_count': subdomain_count,
        'alive_count': alive_count,
        'important_count': important_count,
        'endpoint_count': endpoint_count,
        'endpoint_alive_count': endpoint_alive_count,
        'info_count': info_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'unknown_count': unknown_count,
        'total_vulnerability_count': total_count,
        'total_vul_ignore_info_count': total_count_ignore_info,
        'vulnerability_list': vulns.order_by('-severity').all(),
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'exposed_count': exposed_count,
        'email_count': emails.count(),
        'employees_count': employees.count(),
        'most_recent_scans': recent_scans.order_by('-start_scan_date')[:1],
        'http_status_breakdown': http_statuses,
        'most_common_cve': common_cves,
        'most_common_cwe': common_cwes,
        'most_common_tags': common_tags,
        'most_common_vulnerability': common_vulns,
        'asset_countries': asset_countries,
    }

    # Find number of matched GF patterns
    if scan.used_gf_patterns:
        count_gf = {}
        for gf in scan.used_gf_patterns.split(','):
            count_gf[gf] = (
                endpoints
                .filter(matched_gf_patterns__icontains=gf)
                .count()
            )
            ctx['matched_gf_count'] = count_gf

    # Find last scan for this domain
    if last_scans.count() > 1:
        last_scan = last_scans.order_by('-start_scan_date')[1]
        ctx['last_scan'] = last_scan

    return render(request, 'startScan/detail_scan.html', ctx)


def all_subdomains(request, slug):
    subdomains = Subdomain.objects.filter(target_domain__project__slug=slug)
    scan_engines = EngineType.objects.order_by('engine_name').all()
    alive_subdomains = subdomains.filter(http_status__exact=200) # TODO: replace this with is_alive() function
    important_subdomains = (
        subdomains
        .filter(is_important=True)
        .values('name')
        .distinct()
        .count()
    )
    context = {
        'scan_history_id': id,
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'subdomain_count': subdomains.values('name').distinct().count(),
        'alive_count': alive_subdomains.values('name').distinct().count(),
        'important_count': important_subdomains
    }
    return render(request, 'startScan/subdomains.html', context)

def detail_vuln_scan(request, slug, id=None):
    if id:
        history = get_object_or_404(ScanHistory, id=id)
        history.filter(domain__project__slug=slug)
        context = {'scan_history_id': id, 'history': history}
    else:
        context = {'vuln_scan_active': 'true'}
    return render(request, 'startScan/vulnerabilities.html', context)


def all_endpoints(request, slug):
    context = {
        'scan_history_active': 'active'
    }
    return render(request, 'startScan/endpoints.html', context)

@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_scan_ui(request, slug, domain_id):
    domain = get_object_or_404(Domain, id=domain_id)
    if request.method == "POST":
        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        # Get engine type
        engine_id = request.POST['scan_mode']
        
        # Get ntfy notification preference for this scan
        ntfy_enabled = request.POST.get('ntfy_enabled') == 'on'

        # Create ScanHistory object
        scan_history_id = create_scan_object(
            host_id=domain_id,
            engine_id=engine_id,
            initiated_by_id=request.user.id
        )
        scan = ScanHistory.objects.get(pk=scan_history_id)
        scan.ntfy_enabled = ntfy_enabled
        scan.save()

        # Start the celery task
        kwargs = {
            'scan_history_id': scan.id,
            'domain_id': domain.id,
            'engine_id': engine_id,
            'scan_type': LIVE_SCAN,
            'results_dir': '/usr/src/scan_results',
            'imported_subdomains': subdomains_in,
            'out_of_scope_subdomains': subdomains_out,
            'starting_point_path': starting_point_path,
            'excluded_paths': excluded_paths,
            'initiated_by_id': request.user.id
        }
        initiate_scan.apply_async(kwargs=kwargs)

        # Send start notif
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {domain.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request

    is_rescan = request.GET.get('rescan', 'false').lower() == 'true'
    history_id = request.GET.get('history_id', None)

    # default values
    subdomains_in = []
    subdomains_out = []
    starting_point_path = None
    excluded_paths = []
    selected_engine_id = None

    if is_rescan and history_id:
        previous_scan = get_object_or_404(ScanHistory, id=history_id)
        selected_engine_id = getattr(previous_scan.scan_type, 'id', None)
        subdomains_in = getattr(previous_scan, 'cfg_imported_subdomains', None)
        subdomains_out = getattr(previous_scan, 'cfg_out_of_scope_subdomains', None)
        starting_point_path = getattr(previous_scan, 'cfg_starting_point_path', None)
        excluded_paths = getattr(previous_scan, 'cfg_excluded_paths', None)

    engines = EngineType.objects.order_by('engine_name')
    custom_engines_count = (
        EngineType.objects
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS) if not excluded_paths else ','.join(excluded_paths)

    # context values
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engines,
        'custom_engines_count': custom_engines_count,
        'excluded_paths': excluded_paths,
        'subdomains_in': subdomains_in,
        'subdomains_out': subdomains_out,
        'starting_point_path': starting_point_path,
        'selected_engine_id': selected_engine_id,
        'user_preferences': getattr(request, 'user_preferences', None),
    }
    return render(request, 'startScan/start_scan_ui.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    # domain = get_object_or_404(Domain, id=host_id)
    if request.method == "POST":
        if request.POST.get('scan_mode', 0):
            # if scan mode is available, then start the scan
            # get engine type
            engine_id = request.POST['scan_mode']
            list_of_domain_ids = request.POST['domain_ids']
            subdomains_in = request.POST['importSubdomainTextArea'].split()
            subdomains_in = [s.rstrip() for s in subdomains_in if s]
            subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
            subdomains_out = [s.rstrip() for s in subdomains_out if s]
            starting_point_path = request.POST['startingPointPath'].strip()
            excluded_paths = request.POST['excludedPaths'] # string separated by ,
            # split excluded paths by ,
            excluded_paths = [path.strip() for path in excluded_paths.split(',')]
            
            # Get ntfy notification preference for this batch
            ntfy_enabled = request.POST.get('ntfy_enabled') == 'on'

            grouped_scans = []
            scan_ids = []  # Track scan IDs for batch notification

            for domain_id in list_of_domain_ids.split(","):
                # Start the celery task
                scan_history_id = create_scan_object(
                    host_id=domain_id,
                    engine_id=engine_id,
                    initiated_by_id=request.user.id
                )
                scan_ids.append(scan_history_id)
                
                # Set ntfy_enabled on the scan
                scan = ScanHistory.objects.get(pk=scan_history_id)
                scan.ntfy_enabled = ntfy_enabled
                scan.save()

                kwargs = {
                    'scan_history_id': scan_history_id,
                    'domain_id': domain_id,
                    'engine_id': engine_id,
                    'scan_type': LIVE_SCAN,
                    'results_dir': '/usr/src/scan_results',
                    'initiated_by_id': request.user.id,
                    'imported_subdomains': subdomains_in,
                    'out_of_scope_subdomains': subdomains_out,
                    'starting_point_path': starting_point_path,
                    'excluded_paths': excluded_paths,
                    'batch_mode': True,  # Skip individual start notifications
                }

                _scan_task = initiate_scan.si(**kwargs)
                grouped_scans.append(_scan_task)

            # Send batch start notification
            engine = EngineType.objects.filter(pk=engine_id).first()
            engine_name = engine.engine_name if engine else None
            send_batch_scan_notif(scan_ids, request.user, engine_name=engine_name)

            celery_group = group(grouped_scans)
            celery_group.apply_async()

            # Send start notif
            messages.add_message(
                request,
                messages.INFO,
                'Scan Started for multiple targets')

            return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

        else:
            # this else condition will have post request from the scan page
            # containing all the targets id
            list_of_domain_name = []
            list_of_domain_id = []
            for key, value in request.POST.items():
                if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                    domain = get_object_or_404(Domain, id=value)
                    list_of_domain_name.append(domain.name)
                    list_of_domain_id.append(value)
            domain_ids = ",".join(list_of_domain_id)

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'engines': engines,
        'domain_list': list_of_domain_name,
        'domain_ids': domain_ids,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'startScan/start_multiple_scan_ui.html', context)

def export_subdomains(request, scan_id):
    subdomain_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for domain in subdomain_list:
        response_body += response_body + domain.name + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="subdomains_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


def export_endpoints(request, scan_id):
    endpoint_list = EndPoint.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for endpoint in endpoint_list:
        response_body += endpoint.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="endpoints_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


def export_urls(request, scan_id):
    urls_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for url in urls_list:
        if url.http_url:
            response_body += response_body + url.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="urls_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scan(request, id):
    obj = get_object_or_404(ScanHistory, id=id)
    if request.method == "POST":
        delete_dir = obj.results_dir
        run_command('rm -rf ' + delete_dir)
        obj.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scan history successfully deleted!'
        )
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!'
        )
    return JsonResponse(messageData)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scan(request, id):
    if request.method == "POST":
        scan = get_object_or_404(ScanHistory, id=id)
        try:
            for task_id in scan.celery_ids:
                app.control.revoke(task_id, terminate=True, signal='SIGKILL')
            
            # after celery task is stopped, update the scan status
            scan.scan_status = ABORTED_TASK
            scan.save()
            tasks = (
                ScanActivity.objects
                .filter(scan_of=scan)
                .filter(status=RUNNING_TASK)
                .order_by('-pk')
            )
            for task in tasks:
                app.control.revoke(task.celery_id, terminate=True, signal='SIGKILL')
                task.status = ABORTED_TASK
                task.time = timezone.now()
                task.save()
            create_scan_activity(scan.id, "Scan aborted", ABORTED_TASK)
            response = {'status': True}
            messages.add_message(
                request,
                messages.INFO,
                'Scan successfully stopped!'
            )
        except Exception as e:
            logger.error(e)
            response = {'status': False}
            messages.add_message(
                request,
                messages.ERROR,
                f'Scan failed to stop ! Error: {str(e)}'
            )
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key == 'scan_history_table_length' or key == 'csrfmiddlewaretoken':
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            try:
                for task_id in scan.celery_ids:
                    app.control.revoke(task_id, terminate=True, signal='SIGKILL')
                tasks = (
                    ScanActivity.objects
                    .filter(scan_of=scan)
                    .filter(status=RUNNING_TASK)
                    .order_by('-pk')
                )
                for task in tasks:
                    app.control.revoke(task.celery_id, terminate=True, signal='SIGKILL')
                    task.status = ABORTED_TASK
                    task.time = timezone.now()
                    task.save()
                create_scan_activity(scan.id, "Scan aborted", ABORTED_TASK)
                messages.add_message(
                    request,
                    messages.INFO,
                    'Multiple scans successfully stopped!'
                )
            except Exception as e:
                logger.error(e)
                messages.add_message(
                    request,
                    messages.ERROR,
                    f'Scans failed to stop ! Error: {str(e)}'
                )
    return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))



@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_scan(request, host_id, slug):
    domain = Domain.objects.get(id=host_id)
    if request.method == "POST":
        scheduled_mode = request.POST['scheduled_mode']
        engine_type = int(request.POST['scan_mode'])

        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        # Get engine type
        engine = get_object_or_404(EngineType, id=engine_type)
        timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
        task_name = f'{engine.engine_name} for {domain.name}: {timestr}'
        if scheduled_mode == 'periodic':
            frequency_value = int(request.POST['frequency'])
            frequency_type = request.POST['frequency_type']
            if frequency_type == 'minutes':
                period = IntervalSchedule.MINUTES
            elif frequency_type == 'hours':
                period = IntervalSchedule.HOURS
            elif frequency_type == 'days':
                period = IntervalSchedule.DAYS
            elif frequency_type == 'weeks':
                period = IntervalSchedule.DAYS
                frequency_value *= 7
            elif frequency_type == 'months':
                period = IntervalSchedule.DAYS
                frequency_value *= 30
            schedule, _ = IntervalSchedule.objects.get_or_create(
                every=frequency_value,
                period=period)
            kwargs = {
                'domain_id': host_id,
                'engine_id': engine.id,
                'scan_history_id': 1,
                'scan_type': SCHEDULED_SCAN,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'starting_point_path': starting_point_path,
                'excluded_paths': excluded_paths,
                'initiated_by_id': request.user.id
            }
            PeriodicTask.objects.create(
                interval=schedule,
                name=task_name,
                task='initiate_scan',
                kwargs=json.dumps(kwargs)
            )
        elif scheduled_mode == 'clocked':
            schedule_time = request.POST['scheduled_time']
            clock, _ = ClockedSchedule.objects.get_or_create(
                clocked_time=schedule_time)
            kwargs = {
                'scan_history_id': 0,
                'domain_id': host_id,
                'engine_id': engine.id,
                'scan_type': SCHEDULED_SCAN,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'starting_point_path': starting_point_path,
                'excluded_paths': excluded_paths,
                'initiated_by_id': request.user.id
            }
            PeriodicTask.objects.create(
                clocked=clock,
                one_off=True,
                name=task_name,
                task='initiate_scan',
                kwargs=json.dumps(kwargs)
            )
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Scheduled for {domain.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engines,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'startScan/schedule_scan_ui.html', context)


def scheduled_scan_view(request, slug):
    scheduled_tasks = (
        PeriodicTask.objects
        .all()
        .exclude(name='celery.backend_cleanup')
    )
    context = {
        'scheduled_scan_active': 'active',
        'scheduled_tasks': scheduled_tasks,
    }
    return render(request, 'startScan/schedule_scan_list.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_task(request, id):
    task_object = get_object_or_404(PeriodicTask, id=id)
    if request.method == "POST":
        task_object.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scheduled Scan successfully deleted!')
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if 'task' in key or key == 'csrfmiddlewaretoken':
                continue
            try:
                scan = get_object_or_404(PeriodicTask, id=value)
                scan.delete()
            except Exception as e:
                logger.error(e)
        messages.add_message(
            request,
            messages.INFO,
            'Multiple scheduled scans successfully deleted!')
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def change_scheduled_task_status(request, id):
    if request.method == 'POST':
        task = PeriodicTask.objects.get(id=id)
        task.enabled = not task.enabled
        task.save()
    return HttpResponse('')


def change_vuln_status(request, id):
    if request.method == 'POST':
        vuln = Vulnerability.objects.get(id=id)
        vuln.open_status = not vuln.open_status
        vuln.save()
    return HttpResponse('')


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_scan_results(request):
    if request.method == 'POST':
        ScanHistory.objects.all().delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'All Scan History successfully deleted!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request):
    if request.method == 'POST':
        run_command('rm -rf /usr/src/scan_results/*')
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Screenshots successfully deleted!')
    return JsonResponse(messageData)


def visualise(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'startScan/visualise.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_organization_scan(request, id, slug):
    organization = get_object_or_404(Organization, id=id)
    if request.method == "POST":
        engine_id = request.POST['scan_mode']
        ntfy_enabled = request.POST.get('ntfy_enabled') == 'on'

        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        scan_ids = []  # Track scan IDs for batch notification
        
        # Start Celery task for each organization's domains
        for domain in organization.get_domains():
            scan_history_id = create_scan_object(
                host_id=domain.id,
                engine_id=engine_id,
                initiated_by_id=request.user.id
            )
            scan_ids.append(scan_history_id)
            
            scan = ScanHistory.objects.get(pk=scan_history_id)
            scan.ntfy_enabled = ntfy_enabled
            scan.save()

            kwargs = {
                'scan_history_id': scan.id,
                'domain_id': domain.id,
                'engine_id': engine_id,
                'scan_type': LIVE_SCAN,
                'results_dir': '/usr/src/scan_results',
                'initiated_by_id': request.user.id,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'starting_point_path': starting_point_path,
                'excluded_paths': excluded_paths,
                'batch_mode': True,  # Skip individual start notifications
            }
            initiate_scan.apply_async(kwargs=kwargs)

        # Send batch start notification
        engine = EngineType.objects.filter(pk=engine_id).first()
        engine_name = engine.engine_name if engine else None
        send_batch_scan_notif(scan_ids, request.user, engine_name=engine_name)

        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {ndomains} domains in organization {organization.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects.order_by('engine_name')
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    domain_list = organization.get_domains()
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)

    context = {
        'organization_data_active': 'true',
        'list_organization_li': 'active',
        'organization': organization,
        'engines': engine,
        'domain_list': domain_list,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'organization/start_scan.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_organization_scan(request, slug, id):
    organization =Organization.objects.get(id=id)
    if request.method == "POST":
        engine_type = int(request.POST['scan_mode'])
        engine = get_object_or_404(EngineType, id=engine_type)

        # post vars
        scheduled_mode = request.POST['scheduled_mode']
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        for domain in organization.get_domains():
            timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
            task_name = f'{engine.engine_name} for {domain.name}: {timestr}'

            # Period task
            if scheduled_mode == 'periodic':
                frequency_value = int(request.POST['frequency'])
                frequency_type = request.POST['frequency_type']
                if frequency_type == 'minutes':
                    period = IntervalSchedule.MINUTES
                elif frequency_type == 'hours':
                    period = IntervalSchedule.HOURS
                elif frequency_type == 'days':
                    period = IntervalSchedule.DAYS
                elif frequency_type == 'weeks':
                    period = IntervalSchedule.DAYS
                    frequency_value *= 7
                elif frequency_type == 'months':
                    period = IntervalSchedule.DAYS
                    frequency_value *= 30

                schedule, _ = IntervalSchedule.objects.get_or_create(
                    every=frequency_value,
                    period=period
                )
                _kwargs = json.dumps({
                    'domain_id': domain.id,
                    'engine_id': engine.id,
                    'scan_history_id': 0,
                    'scan_type': SCHEDULED_SCAN,
                    'initiated_by_id': request.user.id,
                    'imported_subdomains': subdomains_in,
                    'out_of_scope_subdomains': subdomains_out,
                    'starting_point_path': starting_point_path,
                    'excluded_paths': excluded_paths,
                })
                PeriodicTask.objects.create(
                    interval=schedule,
                    name=task_name,
                    task='initiate_scan',
                    kwargs=_kwargs
                )

            # Clocked task
            elif scheduled_mode == 'clocked':
                schedule_time = request.POST['scheduled_time']
                clock, _ = ClockedSchedule.objects.get_or_create(
                    clocked_time=schedule_time
                )
                _kwargs = json.dumps({
                    'domain_id': domain.id,
                    'engine_id': engine.id,
                    'scan_history_id': 0,
                    'scan_type': LIVE_SCAN,
                    'initiated_by_id': request.user.id,
                    'imported_subdomains': subdomains_in,
                    'out_of_scope_subdomains': subdomains_out,
                    'starting_point_path': starting_point_path,
                    'excluded_paths': excluded_paths,
                })
                PeriodicTask.objects.create(clocked=clock,
                    one_off=True,
                    name=task_name,
                    task='initiate_scan',
                    kwargs=_kwargs
                )

        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan started for {ndomains} domains in organization {organization.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'organization': organization,
        'domain_list': organization.get_domains(),
        'engines': engine,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'organization/schedule_scan_ui.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key == 'scan_history_table_length' or key == 'csrfmiddlewaretoken':
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            delete_dir = scan.results_dir
            run_command('rm -rf ' + delete_dir)
            scan.delete()
        messages.add_message(
            request,
            messages.INFO,
            'Multiple scans successfully deleted!')
    return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def customize_report(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'startScan/customize_report.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def create_report(request, id):
    primary_color = '#FFB74D'
    secondary_color = '#212121'
    # get report type
    report_type = request.GET['report_type'] if 'report_type' in request.GET  else 'full'
    report_template = request.GET['report_template'] if 'report_template' in request.GET else 'default'

    is_ignore_info_vuln = True if 'ignore_info_vuln' in request.GET else False
    if report_type == 'recon':
        show_recon = True
        show_vuln = False
        report_name = 'Reconnaissance Report'
    elif report_type == 'vulnerability':
        show_recon = False
        show_vuln = True
        report_name = 'Vulnerability Report'
    else:
        # default
        show_recon = True
        show_vuln = True
        report_name = 'Full Scan Report'

    scan = ScanHistory.objects.get(id=id)
    vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .order_by('-severity')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .order_by('-severity')
    )
    unique_vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    )

    subdomains = (
        Subdomain.objects
        .filter(scan_history=scan)
        .order_by('-content_length')
    )
    subdomain_alive_count = (
        Subdomain.objects
        .filter(scan_history__id=id)
        .values('name')
        .distinct()
        .filter(http_status__exact=200)
        .count()
    )
    interesting_subdomains = get_interesting_subdomains(scan_history=id)
    interesting_subdomains = interesting_subdomains.annotate(
        sort_order=Case(
            When(http_status__gte=200, http_status__lt=300, then=1),
            When(http_status__gte=300, http_status__lt=400, then=2),
            When(http_status__gte=400, http_status__lt=500, then=3),
            default=4,
            output_field=IntegerField(),
        )
    ).order_by('sort_order', 'http_status')

    subdomains = subdomains.annotate(
        sort_order=Case(
            When(http_status__gte=200, http_status__lt=300, then=1),
            When(http_status__gte=300, http_status__lt=400, then=2),
            When(http_status__gte=400, http_status__lt=500, then=3),
            default=4,
            output_field=IntegerField(),
        )
    ).order_by('sort_order', 'http_status')




    ip_addresses = (
        IpAddress.objects
        .filter(ip_addresses__in=subdomains)
        .distinct()
    )
    data = {
        'scan_object': scan,
        'unique_vulnerabilities': unique_vulns,
        'all_vulnerabilities': vulns,
        'all_vulnerabilities_count': vulns.count(),
        'subdomain_alive_count': subdomain_alive_count,
        'interesting_subdomains': interesting_subdomains,
        'subdomains': subdomains,
        'ip_addresses': ip_addresses,
        'show_recon': show_recon,
        'show_vuln': show_vuln,
        'report_name': report_name,
        'is_ignore_info_vuln': is_ignore_info_vuln,
    }

    # Get report related config
    vuln_report_query = VulnerabilityReportSetting.objects.all()
    if vuln_report_query.exists():
        report = vuln_report_query[0]
        data['company_name'] = report.company_name
        data['company_address'] = report.company_address
        data['company_email'] = report.company_email
        data['company_website'] = report.company_website
        data['show_rengine_banner'] = report.show_rengine_banner
        data['show_footer'] = report.show_footer
        data['footer_text'] = report.footer_text
        data['show_executive_summary'] = report.show_executive_summary

        # Replace executive_summary_description with template syntax
        description = report.executive_summary_description
        description = description.replace('{scan_date}', scan.start_scan_date.strftime('%d %B, %Y'))
        description = description.replace('{company_name}', report.company_name)
        description = description.replace('{target_name}', scan.domain.name)
        description = description.replace('{subdomain_count}', str(subdomains.count()))
        description = description.replace('{vulnerability_count}', str(vulns.count()))
        description = description.replace('{critical_count}', str(vulns.filter(severity=4).count()))
        description = description.replace('{high_count}', str(vulns.filter(severity=3).count()))
        description = description.replace('{medium_count}', str(vulns.filter(severity=2).count()))
        description = description.replace('{low_count}', str(vulns.filter(severity=1).count()))
        description = description.replace('{info_count}', str(vulns.filter(severity=0).count()))
        description = description.replace('{unknown_count}', str(vulns.filter(severity=-1).count()))
        if scan.domain.description:
            description = description.replace('{target_description}', scan.domain.description)

        # Convert to Markdown
        data['executive_summary_description'] = markdown.markdown(description)

        primary_color = report.primary_color
        secondary_color = report.secondary_color

    data['primary_color'] = primary_color
    data['secondary_color'] = secondary_color

    data['subdomain_http_status_chart'] = generate_subdomain_chart_by_http_status(subdomains)
    data['vulns_severity_chart'] = generate_vulnerability_chart_by_severity(vulns) if vulns.count() > 0 else ''

    if report_template == 'modern':
        template = get_template('report/modern.html')
    else:
        template = get_template('report/default.html')

    html = template.render(data)
    pdf = HTML(string=html).write_pdf()

    if 'download' in request.GET:
        response = HttpResponse(pdf, content_type='application/octet-stream')
    else:
        response = HttpResponse(pdf, content_type='application/pdf')

    return response


#---------------------------#
# Scheduled Scan Views      #
#---------------------------#


def scheduled_scans_list(request, slug):
    """List all scheduled scans for the current project.
    
    Admins see all scheduled scans, regular users only see their own.
    """
    from startScan.models import ScheduledScan
    
    # Get project
    project = get_object_or_404(Project, slug=slug)
    
    # Filter scans based on user role
    if request.user.is_superuser:
        scheduled_scans = ScheduledScan.objects.filter(
            models.Q(domain__project=project) | models.Q(organization__project=project)
        ).select_related('domain', 'organization', 'scan_engine', 'created_by').order_by('-created_at')
    else:
        scheduled_scans = ScheduledScan.objects.filter(
            models.Q(domain__project=project) | models.Q(organization__project=project),
            created_by=request.user
        ).select_related('domain', 'organization', 'scan_engine', 'created_by').order_by('-created_at')
    
    context = {
        'scheduled_scans': scheduled_scans,
        'scheduled_scan_active': 'active',
    }
    return render(request, 'startScan/scheduled_scans_list.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def create_scheduled_scan(request, slug, domain_id=None, organization_id=None):
    """Create a new scheduled scan for a domain or organization."""
    from startScan.models import ScheduledScan
    
    project = get_object_or_404(Project, slug=slug)
    domain = None
    organization = None
    
    if domain_id:
        domain = get_object_or_404(Domain, id=domain_id, project=project)
    elif organization_id:
        organization = get_object_or_404(Organization, id=organization_id, project=project)
    
    if request.method == "POST":
        name = request.POST.get('name', '').strip()
        cron_expression = request.POST.get('cron_expression', '').strip()
        engine_id = request.POST.get('scan_mode')
        ntfy_enabled = request.POST.get('ntfy_enabled') == 'on'
        
        # Get scan options
        subdomains_in = request.POST.get('importSubdomainTextArea', '').split()
        subdomains_in = [s.strip() for s in subdomains_in if s.strip()]
        subdomains_out = request.POST.get('outOfScopeSubdomainTextarea', '').split()
        subdomains_out = [s.strip() for s in subdomains_out if s.strip()]
        starting_point_path = request.POST.get('startingPointPath', '').strip()
        excluded_paths = request.POST.get('excludedPaths', '')
        excluded_paths = [path.strip() for path in excluded_paths.split(',') if path.strip()]
        
        # Validate cron expression
        try:
            from croniter import croniter
            croniter(cron_expression)
        except Exception as e:
            messages.add_message(
                request,
                messages.ERROR,
                f'Invalid cron expression: {str(e)}'
            )
            return HttpResponseRedirect(request.path)
        
        # Create scheduled scan
        try:
            engine = get_object_or_404(EngineType, id=engine_id)
            
            # Calculate next run time
            cron = croniter(cron_expression, timezone.now())
            next_run = cron.get_next(datetime)
            
            scheduled_scan = ScheduledScan.objects.create(
                name=name or f"Scheduled Scan - {domain.name if domain else organization.name}",
                cron_expression=cron_expression,
                domain=domain,
                organization=organization,
                scan_engine=engine,
                imported_subdomains=subdomains_in,
                out_of_scope_subdomains=subdomains_out,
                starting_point_path=starting_point_path,
                excluded_paths=excluded_paths,
                created_by=request.user,
                ntfy_enabled=ntfy_enabled,
                next_run_at=next_run,
                status=0  # Active
            )
            
            target_name = domain.name if domain else organization.name
            
            # Check if user wants to run immediately
            run_immediately = request.POST.get('run_immediately') == 'on'
            if run_immediately:
                # Import and trigger the execute_scheduled_scan task
                from reNgine.tasks import execute_scheduled_scan
                execute_scheduled_scan.delay(scheduled_scan.id)
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    f'Scheduled scan created for {target_name} — First scan started immediately!'
                )
            else:
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    f'Scheduled scan created for {target_name}'
                )
            return HttpResponseRedirect(reverse('scheduled_scans_list', kwargs={'slug': slug}))
            
        except Exception as e:
            messages.add_message(
                request,
                messages.ERROR,
                f'Error creating scheduled scan: {str(e)}'
            )
            return HttpResponseRedirect(request.path)
    
    # GET request
    engines = EngineType.objects.order_by('engine_name')
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    
    context = {
        'scheduled_scan_active': 'active',
        'domain': domain,
        'organization': organization,
        'engines': engines,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths,
    }
    return render(request, 'startScan/create_scheduled_scan.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_scan(request, slug, id):
    """Delete a scheduled scan."""
    from startScan.models import ScheduledScan
    
    scheduled_scan = get_object_or_404(ScheduledScan, id=id)
    
    # Check permission - only owner or admin can delete
    if not request.user.is_superuser and scheduled_scan.created_by != request.user:
        messages.add_message(
            request,
            messages.ERROR,
            'You do not have permission to delete this scheduled scan'
        )
        return JsonResponse({'status': 'false'})
    
    if request.method == "POST":
        scheduled_scan.delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            'Scheduled scan deleted successfully'
        )
        return JsonResponse({'status': 'true'})
    
    return JsonResponse({'status': 'false'})


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def toggle_scheduled_scan_status(request, slug, id):
    """Toggle a scheduled scan between active and paused."""
    from startScan.models import ScheduledScan
    
    scheduled_scan = get_object_or_404(ScheduledScan, id=id)
    
    # Check permission - only owner or admin can toggle
    if not request.user.is_superuser and scheduled_scan.created_by != request.user:
        return JsonResponse({'status': 'error', 'message': 'Permission denied'})
    
    if request.method == "POST":
        # Toggle between Active (0) and Paused (1)
        if scheduled_scan.status == 0:
            scheduled_scan.status = 1  # Pause
            new_status = 'paused'
        else:
            scheduled_scan.status = 0  # Activate
            # Recalculate next run time
            try:
                from croniter import croniter
                cron = croniter(scheduled_scan.cron_expression, timezone.now())
                scheduled_scan.next_run_at = cron.get_next(datetime)
            except:
                pass
            new_status = 'active'
        
        scheduled_scan.save()
        return JsonResponse({'status': 'success', 'new_status': new_status})
    
    return JsonResponse({'status': 'error'})


def scheduled_scan_detail(request, slug, id):
    """View scheduled scan details and run history."""
    from startScan.models import ScheduledScan, ScheduledScanRun, ScheduledScanBaseline
    
    scheduled_scan = get_object_or_404(ScheduledScan, id=id)
    
    # Check permission - only owner or admin can view
    if not request.user.is_superuser and scheduled_scan.created_by != request.user:
        messages.add_message(
            request,
            messages.ERROR,
            'You do not have permission to view this scheduled scan'
        )
        return HttpResponseRedirect(reverse('scheduled_scans_list', kwargs={'slug': slug}))
    
    # Get run history
    runs = ScheduledScanRun.objects.filter(
        scheduled_scan=scheduled_scan
    ).select_related('scan_history').order_by('-started_at')[:50]
    
    # Get baselines
    baselines = ScheduledScanBaseline.objects.filter(
        scheduled_scan=scheduled_scan
    ).select_related('domain', 'baseline_scan')
    
    context = {
        'scheduled_scan': scheduled_scan,
        'runs': runs,
        'baselines': baselines,
        'scheduled_scan_active': 'active',
    }
    return render(request, 'startScan/scheduled_scan_detail.html', context)