import datetime
import json
from prowler.lib.check.check import execute, import_check
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import logger, set_logging_config
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.providers.common.provider import Provider
from prowler.providers.common.models import Audit_Metadata

from scanner.models import Check, Finding as FindingModel

def scan(provider, severities):
    parser = ProwlerArgumentParser()
    args = parser.parse(args=["prowler", provider])
    set_logging_config(args.log_level, args.log_file, args.only_logs)
    bulk_checks_metadata = CheckMetadata.get_bulk(provider)
    bulk_compliance_frameworks = Compliance.get_bulk(provider)
    # Complete checks metadata with the compliance framework specification
    bulk_checks_metadata = update_checks_metadata_with_compliance(
        bulk_compliance_frameworks, bulk_checks_metadata
    )
    checks_to_execute = load_checks_to_execute(
        bulk_checks_metadata=bulk_checks_metadata,
        bulk_compliance_frameworks=bulk_compliance_frameworks,
        checks_file=None,
        check_list=None,
        service_list=None,
        severities=severities,
        compliance_frameworks=None,
        categories=[],
        provider=provider,
    )

    Provider.init_global_provider(args)
    global_provider = Provider.get_global_provider()
    checks_to_execute = sorted(checks_to_execute)
    checks_to_execute = checks_to_execute[:10]
    result = []
    if len(checks_to_execute):
        result = execute_checks(
            checks_to_execute,
            global_provider,
        )
    else:
        logger.error(
            "There are no checks to execute. Please, check your input arguments"
        )
    return result

def execute_checks(checks_to_execute, global_provider):
    # List to store all the check's findings
    global_provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=checks_to_execute,
        completed_checks=0,
        audit_progress=0,
    )
    result = {}

    for check_name in checks_to_execute:
        # Recover service from check name
        service = check_name.split("_")[0]
        checker = {}
        try:
            try:
                # Import check module
                check_module_path = f"prowler.providers.{global_provider.type}.services.{service}.{check_name}.{check_name}"
                lib = import_check(check_module_path)
                # Recover functions from check
                check_to_execute = getattr(lib, check_name)
                check = check_to_execute()
            except ModuleNotFoundError:
                logger.error(
                    f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                )
            check_findings = execute(
                check,
                global_provider,
                None,
                None,
            )
            checker['check'] = {"Check ID": check.CheckID, "ServiceName": check.ServiceName, "Severity": check.Severity.value}
            finding_outputs = []
            for finding in check_findings:
                try:
                    finding_outputs.append(
                        Finding.generate_output(global_provider, finding, None)
                    )
                except Exception:
                    continue
            json_output = OCSF(
                findings=finding_outputs,
                file_path=""
            )
            json_output = [finding.json() for finding in json_output.data]
            checker['findings'] = json_output
            result[check_name] = checker
            

        # If check does not exists in the provider or is from another provider
        except ModuleNotFoundError:
            print(
                f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
            )
        except Exception as error:
            print(
                f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    return result

def run_scan(scan_obj):
    scan_obj.start = datetime.datetime.now()
    scan_obj.status = "in_progress"
    scan_obj.save()
    result = scan(scan_obj.provider, scan_obj.severities)
    scan_obj.end = datetime.datetime.now()
    if len(result) > 0:
        checks = []
        for key, value in result.items():
            check = Check(scan=scan_obj, name=key, details=value["check"])
            checks.append(check)
        check_objs = Check.objects.bulk_create(checks)

        all_findings = []
        for obj in check_objs:
            for details in result[obj.name]['findings']:
                # Have to convert a json string back to a dictionary because the jsonfield can't directly serialize pydantic dict 
                all_findings.append(FindingModel(scan_check=obj, details=json.loads(details)))
        
        FindingModel.objects.bulk_create(all_findings)
    scan_obj.status = "completed"
    scan_obj.save()