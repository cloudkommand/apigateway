import boto3
import botocore
# import jsonschema
import json
import traceback
from botocore.exceptions import ClientError

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name, handle_common_errors, lambda_env
from util import get_default_cors_configuration, generate_openapi_definition

eh = ExtensionHandler()

# def validate_state(state):
# "prev_state": prev_state,
# "component_def": component_def, RENDERED
# "op": op,
# "s3_object_name": object_name,
# "pass_back_data": pass_back_data

apiv2 = boto3.client("apigatewayv2")

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        eh.capture_event(event)
        
        #Really should be getting region from "default region"
        region = account_context(context)['region']
        prev_state = event.get("prev_state", {})
        api_id = prev_state.get("props", {}).get("api_id")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")
        api_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname)
        log_group_name = api_name
        resources = cdef.get("resources")
        stage_name = cdef.get("stage_name") or "live"
        cors_configuration = cdef.get("cors_configuration") or get_default_cors_configuration(cdef.get("cors_enabled"))
        authorizers = cdef.get("authorizers")
        lambda_payload_version = cdef.get("lambda_payload_version") or "2.0"
        stage_variables = cdef.get("stage_variables")
        throttling_burst_limit = cdef.get("throttling_burst_limit")
        throttling_rate_limit = cdef.get("throttling_rate_limit")
        domain_name = cdef.get("domain_name") or \
            (f"{component_safe_name(project_code, repo_id, cname, no_underscores=True, max_chars=112)}.{cdef.get('base_domain')}" 
            if cdef.get("base_domain") else None)
        domain_names = cdef.get("domain_names") or ([domain_name] if domain_name else None)
        pass_back_data = event.get("pass_back_data", {})
        old_log_group_name = prev_state.get("props", {}).get("log_group_name")
        
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            eh.add_op("get_current_state")
            previous_domain_names = prev_state.get("props", {}).get("domain_names", [])
            all_domain_names = list(set(domain_names+previous_domain_names))
            print(f"previous_domain_names = {previous_domain_names}")
            print(f"desired domain_names = {domain_names}")
            if all_domain_names:
                eh.add_state({"all_domain_names": all_domain_names})
                eh.add_op("setup_route53_to_api", all_domain_names)
        elif event.get("op") == "delete":
            eh.add_op("delete_api", api_id)
            if domain_names:
                eh.add_state({"all_domain_names": domain_names})
                eh.add_op("setup_route53_to_api")
        
        get_current_state(log_group_name, api_id, old_log_group_name, stage_name, region)
        create_cloudwatch_log_group(region, account_number)
        create_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, custom_domain_name=None)
        update_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, api_id, prev_state, custom_domain_name=None)
        add_lambda_permissions(account_number)
        create_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        update_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        delete_stage()
        confirm_stage_deployment()
        setup_route53_to_api(domain_names, stage_name, event.get("op"))
        delete_api()
        remove_cloudwatch_log_group()

        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Uncovered Error", {"error": str(e)}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_current_state")
def get_current_state(log_group_name, api_id, old_log_group_name, stage_name, region):
    """ 
        Get API result:
        'ApiEndpoint': 'string',
        'ApiGatewayManaged': True|False,
        'ApiId': 'string',
        'ApiKeySelectionExpression': 'string',
        'CorsConfiguration': {
            'AllowCredentials': True|False,
            'AllowHeaders': [
                'string',
            ],
            'AllowMethods': [
                'string',
            ],
            'AllowOrigins': [
                'string',
            ],
            'ExposeHeaders': [
                'string',
            ],
            'MaxAge': 123
        },
        'CreatedDate': datetime(2015, 1, 1),
        'Description': 'string',
        'DisableSchemaValidation': True|False,
        'DisableExecuteApiEndpoint': True|False,
        'ImportInfo': [
            'string',
        ],
        'Name': 'string',
        'ProtocolType': 'WEBSOCKET'|'HTTP',
        'RouteSelectionExpression': 'string',
        'Tags': {
            'string': 'string'
        },
        'Version': 'string',
        'Warnings': [
            'string',
        ]
    """
    logs_client = boto3.client("logs")

    cursor = 'none'
    log_groups = []
    while cursor:
        payload = remove_none_attributes({
            "logGroupNamePrefix": log_group_name,
            "nextToken": cursor if cursor != 'none' else None
        })
        group_response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
        log_groups.extend(group_response.get("logGroups", []))
        cursor = group_response.get("nextToken")

    mine = list(filter(lambda x: x.get("logGroupName") == log_group_name, log_groups))
    print(f"this_log_group = {mine}")

    if old_log_group_name and (log_group_name != old_log_group_name):
        log_groups = []
        while cursor:
            payload = remove_none_attributes({
                "logGroupNamePrefix": old_log_group_name,
                "nextToken": cursor if cursor != 'none' else None
            })
            group_response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
            log_groups.extend(group_response.get("logGroups", []))
            cursor = group_response.get("nextToken")
        
        old = list(filter(lambda x: x.get("logGroupName") == old_log_group_name, log_groups))
        if old:
            eh.add_op("remove_log_group", old_log_group_name)

    if not mine:
        eh.add_log("No Log Group", {"log_group_name": log_group_name})
        eh.add_op("create_log_group", log_group_name)
    else:
        eh.add_log("Found Log Group", {"log_group_name": log_group_name})
        eh.add_props({
            "log_group_arn": mine[0].get("arn"),
            "log_group_name": mine[0].get("logGroupName")
        })
        eh.add_links({
            "Logs": f"https://console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{mine[0].get('logGroupName')}"
        })
    
    if api_id:
        apiv2 = boto3.client("apigatewayv2")

        try:
            response = apiv2.get_api(
                ApiId=api_id
            )
            eh.add_log("Got API", response)
            eh.add_op("update_api")
            try:
                response = apiv2.get_stages(ApiId=api_id)
                eh.add_log("Got Stages", response)
                items = response.get("Items") or []
                our_stage = list(filter(lambda x: x['StageName'] == stage_name, items))
                if our_stage:
                    eh.add_op("update_stage", stage_name)
                else:
                    eh.add_op("create_stage", stage_name)

                delete_stages = list(map(lambda x: x['StageName'], filter(lambda x: x['StageName'] != stage_name, items)))
                if delete_stages:
                    eh.add_op("delete_stage", delete_stages)

            except Exception as ex:
                eh.add_log("Unlikely Error", {"error": str(ex)}, is_error=True)
                eh.declare_return(200, 0, error_code=str(ex))

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NotFoundException':
                eh.add_log("API Does Not Exist", {"api_id": api_id})
                eh.add_op("create_api")
                eh.add_op("create_stage", stage_name)
            else:
                raise e
        except Exception as ex:
            eh.add_log("Unlikely Error", {"error": str(ex)}, is_error=True)
            eh.declare_return(200, 0, error_code=str(ex))

    else:
        eh.add_op("create_api")
        eh.add_op("create_stage", stage_name)

    eh.complete_op("get_current_state")
    

@ext(handler=eh, op="create_log_group")
def create_cloudwatch_log_group(region, account_number):
    logs_client = boto3.client("logs")

    log_group_name = eh.ops['create_log_group']

    try:
        logs_response = logs_client.create_log_group(
            logGroupName=log_group_name
        )
        eh.add_log("Created Log Group", logs_response)
        eh.add_links({
            "Logs": f"https://console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{log_group_name}"
        })
        eh.add_props({
            "log_group_arn": f"arn:aws:logs:{region}:{account_number}:log-group:{log_group_name}:*",
            "log_group_name": log_group_name
        })
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "ResourceAlreadyExistsException":
            eh.add_log("Log Group Already Exists", {"Log Group", log_group_name})
        else:
            eh.add_log("Log Group Create Error", {"error", str(e)}, is_error=True)
            # eh.declare_return()

    eh.complete_op("create_log_group")

@ext(handler=eh, op="remove_log_group")
def remove_cloudwatch_log_group():
    logs_client = boto3.client("logs")

    log_group_name = eh.ops['remove']

    try:
        logs_response = logs_client.delete_log_group(
            logGroupName=log_group_name
        )
        eh.add_log("Deleted Log Group", logs_response)
    except:
        eh.add_log("Log Group Doesn't Exist", {"log_group_name": log_group_name})

    eh.complete_op("remove_log_group")

@ext(handler=eh, op="create_api")
def create_api(name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, custom_domain_name=None):
    definition, lambdas = generate_openapi_definition(name, resources, cors_configuration, authorizers, account_number, payload_version=lambda_payload_version, region="us-east-1")
    print(f"definition = {definition}")
    print(type(definition))

    try:
        response = apiv2.import_api(
            Body = json.dumps(definition)
        )
        eh.add_log("Created API", response)
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == "BadRequestException":
            eh.add_log("Invalid API Specification", {"error": str(ex)})
            eh.perm_error(str(ex), 15)
            return 0
        else:
            print(str(ex))
            eh.add_log("Failed to Create API", {"error", str(ex)}, is_error=True)
            eh.retry_error(str(ex), 15)
            return 0

    eh.complete_op("create_api")
    eh.add_props({
        "api_id": response.get("ApiId"),
        "api_endpoint": response.get("ApiEndpoint"),
        "name": response.get("Name"),
        "lambdas": lambdas
    })

    eh.add_links({
        "API in AWS": gen_api_link(response.get('ApiId'), region),
        "API Endpoint": response.get("ApiEndpoint")
    })

    if custom_domain_name:
        eh.add_op("create_custom_domain", custom_domain_name)
    if lambdas:
        eh.add_op("add_lambda_permissions", lambdas)
    # elif not custom_domain_name:
    #     eh.declare_return(200, 100, success=True)

@ext(handler=eh, op="update_api")
def update_api(name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, api_id, prev_state, custom_domain_name=None):
    definition, lambdas = generate_openapi_definition(name, resources, cors_configuration, authorizers, account_number, payload_version=lambda_payload_version, region="us-east-1")
    print(f"definition = {definition}")

    try:
        response = apiv2.reimport_api(
            ApiId=api_id,
            Body = json.dumps(definition)
        )
        eh.add_log("Reimported API", response)
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == "BadRequestException":
            eh.add_log("Invalid API Specification", {"error": str(ex)})
            eh.perm_error(str(ex), 15)
            return 0
        else:
            print(str(ex))
            eh.add_log("Failed to Reimport API", {"error", str(ex)}, is_error=True)
            eh.declare_return(200, 15, error_code=str(ex))
            return 0

    eh.complete_op("update_api")
    # eh.add_op("update_stage")
    eh.add_props({
        "api_id": response.get("ApiId"),
        "api_endpoint": response.get("ApiEndpoint"),
        "name": response.get("Name"),
        "lambdas": lambdas
    })

    eh.add_links({
        "API in AWS": gen_api_link(response.get('ApiId'), region)
    })

    prev_state = prev_state or {}
    if set(lambdas) != set(prev_state.get("props", {}).get("lambdas", [])):
        eh.add_op("add_lambda_permissions", lambdas)

    # if custom_domain_name:
    #     eh.add_op("create_custom_domain", custom_domain_name)
    # else:
    #     eh.declare_return(200, 100, success=True)

def gen_api_link(api_id, region):
    return f"https://console.aws.amazon.com/apigateway/main/api-detail?api={api_id}&region={region}"

#Only gets called if we are removing the API completely
@ext(handler=eh, op="delete_api")
def delete_api():
    api_id = eh.ops['delete_api']

    try:
        response = apiv2.delete_api(
            ApiId=api_id
        )
        eh.add_log("Deleted API", response)

    except Exception as ex:
        eh.add_log("Failed to Delete API", {"error", str(ex)}, is_error=True)
        # eh.declare_return()
        return 0

    eh.complete_op("delete_api")
    eh.declare_return(200, 100, success=True)

@ext(handler=eh, op="add_lambda_permissions")
def add_lambda_permissions(account_number):
    lambda_client = boto3.client("lambda")

    lambdas = eh.ops['add_lambda_permissions']

    for l in lambdas:
        try:
            response = lambda_client.add_permission(
                FunctionName=l,
                StatementId="APIGATEWAYINVOKEFUNCTION",
                Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com",
                SourceAccount=str(account_number)
            )
            eh.add_log("Added Permission to Lambda", response)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceConflictException':
                pass
            else:
                raise e

    eh.complete_op("add_lambda_permissions")

@ext(handler=eh, op="create_stage")
def create_stage(stage_variables, throttling_burst_limit, throttling_rate_limit):
    stage_name = eh.ops['create_stage']

    print(f"props = {eh.props}")
    api_id = eh.props['api_id']
    log_group_arn = eh.props['log_group_arn']

    default_route_settings = None
    if throttling_burst_limit or throttling_rate_limit:
        default_route_settings = remove_none_attributes({
            "ThrottlingBurstLimit": throttling_burst_limit,
            "ThrottlingRateLimit": throttling_rate_limit
        })

    payload = remove_none_attributes({
        "AccessLogSettings": {
            "DestinationArn": log_group_arn,
            "Format": json.dumps({ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "caller":"$context.identity.caller", "user":"$context.identity.user","requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", "status":"$context.status","protocol":"$context.protocol", "responseLength":"$context.responseLength" })
        },
        "ApiId": api_id,
        "AutoDeploy": True,
        "DefaultRouteSettings": default_route_settings,
        "StageName": stage_name,
        "StageVariables": stage_variables
    })

    response = apiv2.create_stage(**payload)

    eh.add_log("Stage Created", {"params": payload})
    endpoint_with_stage = f"{eh.props['api_endpoint']}/{stage_name}/"
    eh.add_props({
        "stage_name": stage_name,
        "endpoint_with_stage": endpoint_with_stage
    })
    eh.add_links({
        "API Base URL": endpoint_with_stage
    })

    eh.add_op("confirm_stage_deployment", stage_name)
    eh.complete_op("create_stage")

@ext(handler=eh, op="update_stage")
def update_stage(stage_variables, throttling_burst_limit, throttling_rate_limit):
    stage_name = eh.ops['update_stage']

    print(f"props = {eh.props}")
    api_id = eh.props['api_id']
    log_group_arn = eh.props['log_group_arn']

    default_route_settings = None
    if throttling_burst_limit or throttling_rate_limit:
        default_route_settings = remove_none_attributes({
            "ThrottlingBurstLimit": throttling_burst_limit,
            "ThrottlingRateLimit": throttling_rate_limit
        })

    payload = remove_none_attributes({
        "AccessLogSettings": {
            "DestinationArn": log_group_arn
        },
        "ApiId": api_id,
        "AutoDeploy": True,
        "DefaultRouteSettings": default_route_settings,
        "StageName": stage_name,
        "StageVariables": stage_variables
    })

    response = apiv2.update_stage(**payload)

    eh.add_log("Stage Updated", {"params": payload})
    endpoint_with_stage = f"{eh.props['api_endpoint']}/{stage_name}/"
    eh.add_props({
        "stage_name": stage_name,
        "endpoint_with_stage": endpoint_with_stage
    })
    eh.add_links({
        "API Base URL": endpoint_with_stage
    })

    eh.add_op("confirm_stage_deployment", stage_name)
    eh.complete_op("update_stage")

@ext(handler=eh, op="delete_stage")
def delete_stage():
    stage_names = eh.ops['delete_stage']
    api_id = eh.props['api_id']

    for stage_name in stage_names:
        try:
            response = apiv2.delete_stage(ApiId=api_id, StageName=stage_name)
            eh.add_log(f"Deleted Stage {stage_name}", {"stage_name": stage_name})
        except Exception as e:
            eh.add_log(f"Unable to Delete Stage {stage_name}", {"error": e}, is_error=True)
            print(e)

    eh.complete_op("delete_stage")

@ext(handler=eh, op="confirm_stage_deployment")
def confirm_stage_deployment():
    stage_name = eh.ops['confirm_stage_deployment']
    api_id = eh.props['api_id']

    response = apiv2.get_stage(ApiId=api_id, StageName=stage_name)
    print(response)
    status = response.get("LastDeploymentStatusMessage")
    if status and status.startswith("Successfully deployed stage with deployment"):
        eh.add_log("Stage Deployed", {"stage_name": stage_name})
        eh.complete_op("confirm_stage_deployment")
    elif status and status in ['Deployment attempt failed: Unable to deploy API because no routes exist in this API']:
        eh.add_log("API Has No Routes", {"response": response}, True)
        eh.perm_error("No Routes in API Definition", 75)
    else:
        eh.add_log("Stage Still Deploying", {"stage_name": stage_name})
        eh.declare_return(200, 75, error_code="stage_deploying")

@ext(handler=eh, op="setup_route53_to_api")
def setup_route53_to_api(domain_names, stage_name, op):
    
    #Erase all old status, we start this from the beginning every time
    # for op in ["handle_custom_domain", "get_api_mapping", "create_api_mapping", "update_api_mapping", "remove_api_mappings"]:
    #     eh.complete_op(op)
    print(f"State = {eh.state}")
    all_domain_names = eh.state['all_domain_names']
    # new = False
    # if "initiated_route53" not in eh.state:
    #     new = True
    #     eh.state({"initiated_route53": True})

    for i, domain_name in enumerate(all_domain_names):
        to_deploy_domain_names = eh.ops['setup_route53_to_api']
        if domain_name not in to_deploy_domain_names:
            continue

        if f"initiated {domain_name}" not in eh.state:
            eh.add_op("handle_custom_domain")
            eh.add_op("handle_route53_alias")
            if domain_name in domain_names and op == "upsert":
                eh.add_op("get_api_mapping")
                r53op = "upsert"
            else:
                r53op = "remove"
            eh.add_state({f"initiated {domain_name}": True})

        handle_custom_domain(domain_name, r53op, (i+1))
        get_api_mapping(domain_name, domain_names)
        create_api_mapping(domain_name, stage_name)
        update_api_mapping(domain_name, stage_name)
        remove_api_mappings(domain_name)
        handle_route53_alias(domain_name, r53op, i)
        if eh.error:
            return 0
        eh.add_op("setup_route53_to_api", to_deploy_domain_names[1:])
        
    eh.add_props({"domain_names": domain_names})

@ext(handler=eh, op="handle_custom_domain")
def handle_custom_domain(domain_name, op, integer):

    component_def = {
        "name": domain_name
    }

    function_arn = lambda_env('domain_name_extension_arn')

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key=f"Domain {integer}", progress_start=85, progress_end=100,
        merge_props=False, op=op, links_prefix=f"Domain {integer}")

    print(f"Post invoke, extension props = {eh.props}")
    # if proceed:
    #     eh.add_links({"Website URL": f'http://{eh.props["Route53"].get("domain")}'})
    # print(f"proceed = {proceed}")       


@ext(handler=eh, op="get_api_mapping")
def get_api_mapping(domain_name, desired_domain_names):
    response = apiv2.get_api_mappings(DomainName=domain_name)
    these_mappings = list(filter(lambda x: x["ApiId"] == eh.props['api_id'], response['Items']))
    
    if these_mappings and (domain_name not in desired_domain_names):
        eh.add_op("remove_api_mappings", list(map(lambda x: x['ApiMappingId'], these_mappings)))

    elif not these_mappings and (domain_name in desired_domain_names):
        eh.add_op("create_api_mapping")

    elif domain_name in desired_domain_names:
        eh.add_op("update_api_mapping", these_mappings[0].get("ApiMappingId"))
        if len(these_mappings) > 1:
            eh.add_op("remove_api_mappings", list(map(lambda x: x['ApiMappingId'], these_mappings[1:])))

    else:
        print(f"Nothing to do for domain_name {domain_name}")

@ext(handler=eh, op="create_api_mapping")
def create_api_mapping(domain_name, stage_name):

    try:
        response = apiv2.create_api_mapping(
            ApiId=eh.props['api_id'],
            DomainName=domain_name,
            Stage=stage_name
        )

        api_mapping_props = eh.props.get("api_mappings") or {}
        api_mapping_props[domain_name] = response.get("ApiMappingId")
        eh.add_props({"api_mappings": api_mapping_props})
        eh.add_log("Created API Mapping", response)
    except ClientError as e:
        handle_common_errors(e, eh, "Create API Mapping Failed", 85)

@ext(handler=eh, op="update_api_mapping")
def update_api_mapping(domain_name, stage_name):

    try:
        response = apiv2.update_api_mapping(
            ApiId=eh.props['api_id'],
            ApiMappingId=eh.ops['update_api_mapping'],
            DomainName=domain_name,
            Stage=stage_name
        )

        api_mapping_props = eh.props.get("api_mappings") or {}
        api_mapping_props[domain_name] = response.get("ApiMappingId")
        eh.add_props({"api_mappings": api_mapping_props})
        eh.add_log("Updated API Mapping", response)
    except ClientError as e:
        handle_common_errors(e, eh, "Update API Mapping Failed", 85)

@ext(handler=eh, op="remove_api_mappings")
def remove_api_mappings(domain_name):

    for api_mapping_id in eh.ops['remove_api_mappings']:
        try:
            response = apiv2.delete_api_mapping(
                ApiMappingId=api_mapping_id,
                DomainName=domain_name
            )
            eh.add_log("Removed API Mapping", {"id": api_mapping_id, "domain_name": domain_name})

        except ClientError as e:
            if e.response['Error']['Code'] != "NotFoundException":
                handle_common_errors(e, eh, "Delete API Mapping Failed", 85)
            else:
                eh.add_log("API Mapping Not found", {"id": api_mapping_id})
                return 0

@ext(handler=eh, op="handle_route53_alias")
def handle_route53_alias(domain_name, op, integer):
    print(f"inside alias, props = {eh.props}")
    domain = eh.props.get(f"Domain {integer}", {})

    component_def = {
        "domain": domain_name,
        "target_api_hosted_zone_id": domain.get("hosted_zone_id"),
        "target_api_domain_name": domain.get("api_gateway_domain_name")
    }

    function_arn = lambda_env('route53_extension_arn')

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key=f"Route53 {integer}", progress_start=85, progress_end=95,
        merge_props=False, op=op, links_prefix=f"Route53 {integer}"
    )   

    # if proceed:
    #     eh.add_links({"Website URL": f'http://{eh.props["Route53"].get("domain")}'})
    print(f"proceed = {proceed}")
