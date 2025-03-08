import subprocess
import os
from django.http import JsonResponse
from django.shortcuts import render, redirect
from .forms import SignupForm
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import redirect
from django.contrib.auth import logout
from .models import ScanResult
from .models import NucleiResult  # Import your model
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from .models import ScanResult  # Make sure your ScanResult model is correctly imported
from .models import NucleiResult
from django.core.paginator import Paginator
from django.shortcuts import render
from django.db.models import Count  # Import Count function

# Paths to your tools
SUBFINDER_PATH = "subdominator"
NUCLEI_PATH = "nuclei"
BUG_CLASS_TEMPLATES = {
    "xss": "xss",
    "sqli": "sqli",
    "misconfig": "misconfiguration",
    "rce": "rce",
    "default-login": "default-logins",
    "exposed-panels": "exposed-panels",
    "exposures": "exposures",
    "takeovers": "takeovers",
    "technologies": "technologies",
    "token-spray": "token-spray",
    "osint": "osint",
    "cves": "cves",
}

# Path to your nuclei templates
NUCLEI_TEMPLATES_BASE_PATH = r"K:\ASM\ASM\nuclei-templates\http"    

BASE_RESULTS_DIR = "C:/Users/vamsi/bb/"


# Signup View
def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Log the user in after successful signup
            return redirect('/login')  # Redirect to a page, e.g., the home page
        else:
            messages.error(request, "Please correct the error below.")
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

@login_required
def scan_page(request):
    # Fetch distinct domains for the dropdown
    domains = ScanResult.objects.filter(user=request.user).values_list('target', flat=True).distinct()
    return render(request, 'scan_page.html', {'domains': domains})

# Login View
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('/view')  # Redirect to the home page after login
        else:
            messages.error(request, "Invalid username or password.")
    return render(request, 'login.html')

def logout_view(request):
    logout(request)  # This will log out the user
    return redirect('landing')


def run_command(command):
    try:
        result = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {command}\nError: {e.stderr}")
        return None

def landing(req):
    return render(req,'landing-page.html')

def about_us(req):
    return render(req,'about.html')

def create_results_folder(domain):
    folder_path = os.path.join(BASE_RESULTS_DIR, f"{domain}_results")
    os.makedirs(folder_path, exist_ok=True)
    return folder_path

def run_subfinder(target, folder_path):
    output_file = os.path.join(folder_path, "subdomains_subfinder.txt")
    return run_command(f"{SUBFINDER_PATH} -d {target} --silent -o {output_file}")

# def run_nuclei(folder_path):
#     # Scan all subdomains found by subfinder
#     subdomains_file = os.path.join(folder_path, "subdomains_subfinder.txt")
#     nuclei_output = os.path.join(folder_path, "nuclei_results.txt")
#     return run_command(f"{NUCLEI_PATH} -t C:\\Users\\vamsi\\nuclei-templates -l {subdomains_file} -o {nuclei_output}")

@login_required
def scan_page(request):
    # Fetch distinct domains for the dropdown
    domains = ScanResult.objects.filter(user=request.user).values_list('target', flat=True).distinct()
    subdomains = ScanResult.objects.filter(user=request.user).values_list('subdomains', flat=True).distinct()
    subdomains = '\n'.join(subdomains).split('\n')
    subdomains = list(set(subdomains)) 
    print(domains,subdomains)
    d={'domainresults':{'domains':domains,'subdomains':subdomains}}
    print(d)
    return render(request, 'scan.html', {'domainresults':{'domains':domains,'subdomains':subdomains}})

@login_required
def scans_page(request):
    domains = ScanResult.objects.filter(user=request.user).values_list('target', flat=True).distinct()
    return render(request, 'scan.html', {'domains': domains})

def get_subdomain(request, domain):
    # Fetch subdomains associated with the selected domain for the current user
    subdomains = ScanResult.objects.filter(user=request.user, target=domain).values_list('subdomains', flat=True)
    subdomains = '\n'.join(subdomains).split('\n')  # Split subdomains by newline
    subdomains = list(set(subdomains))  # Remove duplicates
    return JsonResponse({'subdomains': subdomains})

@csrf_exempt  # Remove this if you're using CSRF tokens in AJAX request
@login_required
def save_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            domain = data.get('domain')
            subdomain = data.get('subdomain')
            bug_class = data.get('bug_class', "Misconfig")  # Default to Misconfig

            if not domain or not subdomain or not bug_class:
                return JsonResponse({"status": "error", "message": "Missing fields"}, status=400)

            print(f"Received scan request: {data}")

            # Define scan output path
            output_path = f"{settings.TMP_RESULTS_PATH}/{subdomain}.json"

            # Determine Nuclei template path based on bug class selection
            if bug_class.lower() == "all":
                template_path = NUCLEI_TEMPLATES_BASE_PATH  # Scan all templates
            else:
                template_dir = BUG_CLASS_TEMPLATES.get(bug_class)
                if not template_dir:
                    return JsonResponse({"status": "error", "message": "Invalid bug class"}, status=400)

                template_path = os.path.join(NUCLEI_TEMPLATES_BASE_PATH, template_dir)

                # Ensure the template directory exists
                if not os.path.exists(template_path):
                    return JsonResponse({"status": "error", "message": f"Template path not found: {template_path}"}, status=400)

            # Run Nuclei scan with JSON output
            cmd = [
                settings.NUCLEI_PATH, "-t", template_path,
                "-u", subdomain, "-j", "-silent"
            ]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return JsonResponse({"error": f"Nuclei scan failed: {stderr.decode()}"}, status=500)

            # Parse JSON line by line
            results_list = []
            for line in stdout.decode().splitlines():
                try:
                    result = json.loads(line.strip())
                    results_list.append({
                        "template_id": result.get("template-id"),
                        "template_name": result["info"].get("name"),
                        "severity": result["info"].get("severity"),
                        "tags": ",".join(result["info"].get("tags", [])),
                        "url": result.get("url"),
                        "ip_address": result.get("ip"),
                        "protocol": result.get("type"),
                        "timestamp": result.get("timestamp"),
                        "curl_command": result.get("curl-command"),
                    })
                except json.JSONDecodeError:
                    print("Error parsing:", line)

            if not results_list:
                return JsonResponse({"message": "No vulnerabilities found.", "scan_id": None})

            if not request.user.is_authenticated:
                return JsonResponse({"error": "User must be logged in to save scan results."}, status=403)

            # Save scan results
            scan_result = NucleiResult.objects.create(
                user=request.user,
                target=domain,
                subdomain=subdomain,
                bug_class=bug_class,
                scan_results=json.dumps(results_list)
            )

            return JsonResponse({
                "message": "Scan completed successfully!",
                "results": results_list,
                "scan_id": scan_result.id
            })

        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@login_required
def view(request):
    if request.method == 'POST':
        target = request.POST.get('domain')
        if not target:
            return JsonResponse({"error": "Domain is required"}, status=400)

        folder_path = create_results_folder(target)
        results = {}

        # Run subfinder
        results['subfinder'] = run_subfinder(target, folder_path)
        
        if results['subfinder'] is None:
            return JsonResponse({"error": "Failed to run subfinder"}, status=500)

        subfinder_list = results['subfinder'].strip().split('\n') if results['subfinder'].strip() else []
        results['subfinder'] = subfinder_list
        
        # Save results in the database
        scan_result = ScanResult.objects.create(
            user=request.user,  # Associate the scan result with the logged-in user
            target=target,
            subdomains='\n'.join(results['subfinder'])  # Join subdomains into a single string
        )
        
        print(results)
        return render(request, 'index.html', {"results": results })
    
    return render(request, 'index.html')



# Replace this with your actual path to Nuclei executable if needed
NUCLEI_PATH = settings.NUCLEI_PATH 

@login_required
def perform_scan(request):
    if request.method == 'POST':
        selected_domain = request.POST.get('domain')
        selected_subdomain = request.POST.get('subdomain')
        bug_class = request.POST.get('bug_class')

        if not selected_domain or not selected_subdomain or not bug_class:
            return JsonResponse({"error": "All fields are required"}, status=400)

        # Determine nuclei template path based on bug class
        nuclei_template_path = (
            os.path.join(settings.NUCLEI_TEMPLATES_PATH, bug_class) 
            if bug_class != 'all' else settings.NUCLEI_TEMPLATES_PATH
        )

        # Run Nuclei with JSON output
        try:
            cmd = [
                NUCLEI_PATH, "-t", nuclei_template_path, "-u", selected_subdomain, 
                "-j", "-silent"
            ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return JsonResponse({"error": f"Nuclei scan failed: {stderr.decode()}"}, status=500)

            # Parse JSON line by line
            results_list = []
            for line in stdout.decode().splitlines():
                try:
                    result = json.loads(line.strip())  # Parse each JSON line
                    results_list.append({
                        "template_id": result.get("template-id"),
                        "template_name": result["info"].get("name"),
                        "severity": result["info"].get("severity"),
                        "tags": ",".join(result["info"].get("tags", [])),
                        "url": result.get("url"),
                        "ip_address": result.get("ip"),
                        "protocol": result.get("type"),
                        "timestamp": result.get("timestamp"),
                        "curl_command": result.get("curl-command"),
                    })
                except json.JSONDecodeError:
                    print("Error parsing:", line)

            if not results_list:
                return JsonResponse({"message": "No vulnerabilities found.", "scan_id": None})

            # Store results in the NucleiResult model
            scan_result = NucleiResult.objects.create(
                user=request.user,
                target=selected_domain,
                subdomain=selected_subdomain,  # Fixed field name
                bug_class=bug_class,  # Fixed field name
                scan_results=json.dumps(results_list)  # Store structured results
            )

            return JsonResponse({
                "message": "Scan completed successfully!",
                "results": results_list,
                "scan_id": scan_result.id
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return redirect('scan')


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return None  # If Nuclei exits with a non-zero code, return None
        return result.stdout  # Return the scan results
    except Exception as e:
        print(f"Error running command: {e}")
        return None


@login_required
def get_subdomains(request):
    domain = request.GET.get('domain')
    if domain:
        subdomains = ScanResult.objects.filter(user=request.user, target=domain).values_list('subdomains', flat=True)
        subdomain_list = subdomains[0].split("\n") if subdomains else []
        return JsonResponse({"subdomains": subdomain_list})
    return JsonResponse({"error": "Domain not found"}, status=400)


@login_required
def my_scans(request):
    scan_results = ScanResult.objects.filter(user=request.user) 
    results = list(scan_results.values()) 
    r=results[0]['subdomains'].split('\n')
    results[0]['r']=r
    print(results[0])
    return render(request, 'my_scans.html', {'results': results[0]})


@login_required

def dashboard_view(request):

    show_info = request.GET.get("show_info", "false").lower() == "true"
    # Fetch scan results only for the logged-in user
    scan_results = NucleiResult.objects.filter(user=request.user)

    # Extract unique scanned domains
    scanned_domains = list(scan_results.values_list("target", flat=True).distinct())

    # Initialize statistics
    total_scans = scan_results.count()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_vulnerabilities = 0

    parsed_results = []
    info_results = []  # Separate list for 'info' severity findings

    # Check if the user clicked the "Show Info Findings" button
    show_info = request.GET.get("show_info") == "true"

    # Process scan results
    for result in scan_results:
        try:
            results_data = json.loads(result.scan_results)  # Load JSON data

            for entry in results_data:
                severity = entry.get("severity", "info").lower()  # Normalize severity
                
                # Update severity counts
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                # Exclude 'info' from total_vulnerabilities count
                if severity != "info":
                    total_vulnerabilities += 1

                # Construct the vulnerability entry
                entry_dict = {
                    "target": result.target,
                    "subdomain": result.subdomain,
                    "bug_class": result.bug_class,
                    "severity": severity,
                    "url": entry.get("url", ""),  # Use 'url' instead of 'host'
                    "vulnerability": entry.get("template_name", "Unknown Vulnerability"),  # Meaningful name
                    "tags": entry.get("tags", ""),  # Extra categorization
                    "details": entry.get("curl_command", "No details available"),  # Fetch attack payload if available
                    "timestamp": entry.get("timestamp", result.created_at.isoformat()),  # Ensure timestamp format
                }

                # Store findings separately based on severity
                if severity == "info":
                    info_results.append(entry_dict)
                else:
                    parsed_results.append(entry_dict)

        except json.JSONDecodeError:
            continue  # Skip if scan_results is not a valid JSON

    # Pass data to template
    context = {
        "scanned_domains": scanned_domains,
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulnerabilities,  # Excluding 'info' from the count
        "severity_counts": severity_counts,
        "parsed_results": parsed_results,  # Non-info vulnerabilities
        "info_results": info_results if show_info else [],  # Show info findings only when requested
        "show_info": show_info,  # Track if info should be shown
    }
    return render(request, "dashboard.html", context)

def dashboard(request):
    
    scan_results = NucleiResult.objects.all().order_by('-created_at')

    context = {
        "total_scans": scan_results.count(),
        "total_vulnerabilities": scan_results.exclude(severity="info").count(),
        "severity_counts": {
            "critical": scan_results.filter(bug_class="critical").count(),
            "high": scan_results.filter(bug_class="high").count(),
            "medium": scan_results.filter(bug_class="medium").count(),
            "low": scan_results.filter(bug_class="low").count(),
            "info": scan_results.filter(bug_class="info").count(),
        },
        "scanned_domains": scan_results.values_list("target", flat=True).distinct(),
        "scan_results": scan_results,
    }

    return render(request, "dashboard.html", context)

