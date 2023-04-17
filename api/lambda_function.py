import boto3
import botocore
# import jsonschema
import copy
import json
import traceback
from botocore.exceptions import ClientError

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name, handle_common_errors, lambda_env
from util import get_default_cors_configuration, generate_openapi_definition

eh = ExtensionHandler()

ROUTE53_KEY = "Route53"
CUSTOM_DOMAIN_KEY = "Domain"
CLOUDFRONT_DISTRIBUTION_KEY = "Distribution"

apiv2 = boto3.client("apigatewayv2")

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        eh.capture_event(event)
        
        #Really should be getting region from "default region"
        region = account_context(context)['region']
        prev_state = event.get("prev_state", {})
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")

        api_id = prev_state.get("props", {}).get("api_id") or cdef.get("existing_id")
        api_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname)
        log_group_name = f"/aws/vendedlogs/{api_name}"
        resources = cdef.get("resources")
        stage_name = cdef.get("stage_name") or "live"
        cors_configuration = cdef.get("cors_configuration") or get_default_cors_configuration(cdef.get("cors_enabled"))
        authorizers = cdef.get("authorizers")
        lambda_payload_version = cdef.get("lambda_payload_version") or "2.0"
        stage_variables = cdef.get("stage_variables")
        throttling_burst_limit = cdef.get("throttling_burst_limit")
        throttling_rate_limit = cdef.get("throttling_rate_limit")

        cloudfront_distribution_override_def = cdef.get(CLOUDFRONT_DISTRIBUTION_KEY) or {} #For cloudfront distribution overrides
        cloudfront = cdef.get("cloudfront") or bool(cloudfront_distribution_override_def)

        tags = cdef.get("tags") or {}
        domain_name = cdef.get("domain_name") or cdef.get("domain") or \
            (f"{component_safe_name(project_code, repo_id, cname, no_underscores=True, max_chars=112)}.{cdef.get('base_domain')}" 
            if cdef.get("base_domain") else None)
        domain_names = cdef.get("domain_names") or ([domain_name] if domain_name else [])
        if domain_names:
            domains = {str(i+1): {"domain": d} for i, d in enumerate(domain_names)}
        else:
            domains = cdef.get("domains")

        pass_back_data = event.get("pass_back_data", {})
        old_log_group_name = prev_state.get("props", {}).get("log_group_name")
        
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            eh.add_op("get_current_state")
            r53_keys = list(filter(lambda x: x.startswith(ROUTE53_KEY), prev_state.get("props", {}).keys()))
            if domains or r53_keys:
                domain_keys = list(domains.keys())
                prev_domain_keys = list(map(lambda x: x[8:], filter(lambda x: x.startswith(ROUTE53_KEY), prev_state.get("props", {}).keys())))
                print(prev_domain_keys)
                old_domains = {k: 
                    {
                        "domain": prev_state['props'][f"{ROUTE53_KEY}_{k}"]['domain'],
                        "hosted_zone_id": prev_state['props'][f"{ROUTE53_KEY}_{k}"]['route53_hosted_zone_id']
                    } for k in (set(prev_domain_keys) - set(domain_keys))
                }
                print(f"domains: {domains}")
                print(f"old_domains: {old_domains}")
                eh.add_op("setup_custom_domain", {"upsert": domains, "delete": old_domains})
                upsert_domains = {k:v for k,v in domains.items() if isinstance(v, str) or (not v.get("external_domain"))}
                print(f"upsert_domains: {upsert_domains}")
                if upsert_domains or old_domains:
                    eh.add_op("setup_route53", {"upsert": upsert_domains, "delete": copy.deepcopy(old_domains)})
            
                if cloudfront:
                    eh.add_op("setup_cloudfront_distribution", {"op": "upsert"})
                elif prev_state.get("props", {}).get(CLOUDFRONT_DISTRIBUTION_KEY):
                    # All this pain to get what the old domains were exactly.
                    prev_state_cdef = prev_state["rendef"]
                    prev_state_domain_name = prev_state_cdef.get("domain_name") or prev_state_cdef.get("domain") or \
                        (f"{component_safe_name(project_code, repo_id, cname, no_underscores=True, max_chars=112)}.{prev_state_cdef.get('base_domain')}" 
                        if prev_state_cdef.get("base_domain") else None)
                    prev_state_domain_names = prev_state_cdef.get("domain_names") or ([domain_name] if prev_state_domain_name else [])
                    if prev_state_domain_names:
                        prev_state_domains = {str(i+1): {"domain": d} for i, d in enumerate(prev_state_domain_names)}
                    else:
                        prev_state_domains = cdef.get("domains")

                    eh.add_op("setup_cloudfront_distribution", {
                        "op": "delete", "aliases": list(map(lambda x: x["domain"], prev_state_domains.values()))
                    })

        elif event.get("op") == "delete":
            eh.add_op("delete_api", api_id)
            if domains:
                # eh.add_state({"all_domain_names": domain_names})
                eh.add_op("setup_custom_domain", {"delete": domains})
                delete_domains = {k:v for k,v in domains.items() if not isinstance(v, str) or v.get("external_domain")}
                if delete_domains:
                    eh.add_op("setup_route53", {"delete": delete_domains})
                if cloudfront:
                    eh.add_op("setup_cloudfront_distribution", {"op":"delete"})


        get_current_state(log_group_name, api_id, old_log_group_name, stage_name, region, tags)
        create_cloudwatch_log_group(region, account_number)
        create_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region)
        update_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, api_id, prev_state)
        add_lambda_permissions(account_number)
        create_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        update_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        delete_stage()
        confirm_stage_deployment()
        remove_tags()
        add_tags()
        setup_custom_domain(stage_name, prev_state)
        setup_cloudfront_distribution(prev_state, domains, cloudfront_distribution_override_def, stage_name)
        setup_route53(prev_state, cloudfront)
        delete_api()
        remove_cloudwatch_log_group()

        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": str(e)}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_current_state")
def get_current_state(log_group_name, api_id, old_log_group_name, stage_name, region, tags):
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
            current_tags = response.get("Tags") or {}
            if tags != current_tags:
                remove_tags = [k for k in current_tags.keys() if k not in tags]
                add_tags = {k:v for k,v in tags.items() if k not in current_tags.keys()}
                if remove_tags:
                    eh.add_op("remove_tags", remove_tags)
                if add_tags:
                    eh.add_op("add_tags", add_tags)
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
                if tags:
                    eh.add_op("add_tags", tags) 
            else:
                raise e
        except Exception as ex:
            eh.add_log("Unlikely Error", {"error": str(ex)}, is_error=True)
            eh.declare_return(200, 0, error_code=str(ex))

    else:
        eh.add_op("create_api")
        eh.add_op("create_stage", stage_name)
        if tags:
            eh.add_op("add_tags", tags) 

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

@ext(handler=eh, op="create_api")
def create_api(name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, ):
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

    eh.add_props({
        "api_id": response.get("ApiId"),
        "arn": gen_apigateway_arn(response.get("ApiId"), region),
        "api_endpoint": response.get("ApiEndpoint"),
        "name": response.get("Name"),
        "lambdas": lambdas
    })

    eh.add_links({
        "API in AWS": gen_api_link(response.get('ApiId'), region),
        "API Endpoint": response.get("ApiEndpoint")
    })

    if lambdas:
        eh.add_op("add_lambda_permissions", lambdas)


@ext(handler=eh, op="update_api")
def update_api(name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, api_id, prev_state):
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

    # eh.add_op("update_stage")
    eh.add_props({
        "api_id": response.get("ApiId"),
        "arn": gen_apigateway_arn(response.get("ApiId"), region),
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

    except ClientError as e:
        if e.response['Error']['Code'] == "NotFoundException":
            eh.add_log("No API to delete", {"api_id": api_id})
        elif 'Please remove all API mappings for the API from your custom domain names.' in str(e):
            eh.add_log(f"Cannot delete API, mappings still present", {"api_id": api_id}, is_error=True)
            eh.perm_error("API mappings still present for this API", 60)
        else:
            handle_common_errors(e, eh, "Delete API Failed", 60)


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
            "Format": json.dumps({ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", "status":"$context.status","protocol":"$context.protocol", "responseLength":"$context.responseLength" })
        },
        "ApiId": api_id,
        "AutoDeploy": True,
        "DefaultRouteSettings": default_route_settings,
        "StageName": stage_name,
        "StageVariables": stage_variables
    })

    response = apiv2.create_stage(**payload)

    eh.add_log("Stage Created", {"params": payload})
    endpoint_with_stage = f"{eh.props['api_endpoint']}/{stage_name}"
    eh.add_props({
        "stage_name": stage_name,
        "endpoint_with_stage": endpoint_with_stage
    })
    eh.add_links({
        "API Base URL": endpoint_with_stage
    })

    eh.add_op("confirm_stage_deployment", stage_name)

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
            "DestinationArn": log_group_arn,
            "Format": json.dumps({ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", "status":"$context.status","protocol":"$context.protocol", "responseLength":"$context.responseLength" })
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


@ext(handler=eh, op="confirm_stage_deployment")
def confirm_stage_deployment():
    stage_name = eh.ops['confirm_stage_deployment']
    api_id = eh.props['api_id']

    response = apiv2.get_stage(ApiId=api_id, StageName=stage_name)
    print(response)
    status = response.get("LastDeploymentStatusMessage")
    if status and status.startswith("Successfully deployed stage with deployment"):
        eh.add_log("Stage Deployed", {"stage_name": stage_name})
    elif status and status in ['Deployment attempt failed: Unable to deploy API because no routes exist in this API']:
        eh.add_log("API Has No Routes", {"response": response}, True)
        eh.perm_error("No Routes in API Definition", 60)
    else:
        eh.add_log("Stage Still Deploying", {"stage_name": stage_name})
        eh.declare_return(200, 60, error_code="stage_deploying")

@ext(handler=eh, op="add_tags")
def add_tags():
    tags = eh.ops['add_tags']
    arn = eh.props['arn']

    try:
        apiv2.tag_resource(
            ResourceArn=arn,
            Tags=tags
        )
        eh.add_log("Tags Added", {"tags": tags})

    except ClientError as e:
        handle_common_errors(e, eh, "Add Tags Failed", 62, ['InvalidParameterValueException'])
        
@ext(handler=eh, op="remove_tags")
def remove_tags():
    arn = eh.props['arn']

    try:
        apiv2.untag_resource(
            ResourceArn=arn,
            TagKeys=eh.ops['remove_tags']
        )
        eh.add_log("Tags Removed", {"tags": eh.ops['remove_tags']})

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Remove Tags Failed", 65, ['InvalidParameterValueException'])


@ext(handler=eh, op="setup_custom_domain", complete_op=False)
def setup_custom_domain(stage_name, prev_state):
    
    #Erase all old status, we start this from the beginning every time
    # for op in ["handle_custom_domain", "get_api_mapping", "create_api_mapping", "update_api_mapping", "remove_api_mappings"]:
    #     eh.complete_op(op)
    # print(f"State = {eh.state}")
    # all_domain_names = eh.state['all_domain_names']
    # new = False
    # if "initiated_route53" not in eh.state:
    #     new = True
    #     eh.state({"initiated_route53": True})
    op_val = eh.ops["setup_custom_domain"]
    delete_domains = op_val.get("delete")
    upsert_domains = op_val.get("upsert")
    print(f"domain, delete_domains={delete_domains}, upsert_domains={upsert_domains}")

    if delete_domains:
        using_domains = delete_domains
        route53_op = "delete"
    elif upsert_domains:
        using_domains = upsert_domains
        route53_op = "upsert"
        # eh.add_op("get_api_mapping")
    
    domain_key = sorted(list(using_domains.keys()))[0]
    domain = using_domains[domain_key].get("domain")
    # hosted_zone_id = using_domains[domain_key].get("hosted_zone_id")
    if not domain:
        eh.perm_error("'domains' dictionary must contain a 'domain' key inside the domain key")
        return

    if f"initiated {domain_key}" not in eh.state:
        if route53_op == "upsert":
            eh.add_op("get_api_mapping")
        else:
            # This gets used by the R53 handler as well
            child_key = f"{CUSTOM_DOMAIN_KEY}_{domain_key}"
            eh.add_props({child_key: prev_state['props'].get(child_key, {})})

        eh.add_op("handle_custom_domain", route53_op)
        # eh.add_op("handle_route53_alias", route53_op)
        eh.add_state({f"initiated {domain_key}": True})

    handle_custom_domain(prev_state, domain, domain_key)
    get_api_mapping(domain, route53_op)
    create_api_mapping(domain, stage_name)
    update_api_mapping(domain, stage_name)
    remove_api_mappings(domain)
    # handle_route53_alias(domain, domain_key)
    if eh.error:
        return 0
    else:
        if route53_op == "delete":
            del delete_domains[domain_key]
            # del eh.props[child_key]
        else:            
            del upsert_domains[domain_key]
        if delete_domains or upsert_domains:
            eh.add_op("setup_custom_domain", {"delete": delete_domains, "upsert": upsert_domains})
            setup_custom_domain(stage_name, prev_state)
        else:
            eh.complete_op("setup_custom_domain")
        

@ext(handler=eh, op="handle_custom_domain")
def handle_custom_domain(prev_state, domain_name, domain_key):

    component_def = {
        "name": domain_name
    }

    function_arn = lambda_env('domain_name_extension_arn')

    child_key = f"{CUSTOM_DOMAIN_KEY}_{domain_key}"

    if eh.ops["handle_custom_domain"] == "upsert" and prev_state and prev_state.get("props", {}).get(child_key, {}):
        eh.add_props({child_key: prev_state.get("props", {}).get(child_key, {})})

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key=child_key, progress_start=85, progress_end=90,
        op=eh.ops["handle_custom_domain"], 
        links_prefix=f"{CUSTOM_DOMAIN_KEY} {domain_key}"
    )

    print(f"Post invoke, extension props = {eh.props}")
    # if proceed:
    #     eh.add_links({"Website URL": f'http://{eh.props["Route53"].get("domain")}'})
    # print(f"proceed = {proceed}")       


@ext(handler=eh, op="get_api_mapping")
def get_api_mapping(domain_name, route53_op):
    response = apiv2.get_api_mappings(DomainName=domain_name)
    these_mappings = list(filter(lambda x: x["ApiId"] == eh.props['api_id'], response['Items']))
    
    if these_mappings and route53_op == "delete":
        eh.add_op("remove_api_mappings", list(map(lambda x: x['ApiMappingId'], these_mappings)))

    elif not these_mappings and route53_op == "upsert":
        eh.add_op("create_api_mapping")

    elif route53_op == "upsert":
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
        if "ApiMapping key already exists for this domain name" in str(e):
            eh.add_log("Conflict, cannot Create API Mapping", {"api_id": eh.props['api_id'], "domain_name": domain_name, "stage_name": stage_name})
            eh.perm_error("API Mapping Already Exists for this Domain", 91)
        else:
            handle_common_errors(e, eh, "Create API Mapping Failed", 91)

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
        handle_common_errors(e, eh, "Update API Mapping Failed", 91)

@ext(handler=eh, op="remove_api_mappings")
def remove_api_mappings(domain_name):

    for api_mapping_id in eh.ops['remove_api_mappings']:
        try:
            apiv2.delete_api_mapping(
                ApiMappingId=api_mapping_id,
                DomainName=domain_name
            )
            eh.add_log("Removed API Mapping", {"id": api_mapping_id, "domain_name": domain_name})

        except ClientError as e:
            if e.response['Error']['Code'] != "NotFoundException":
                handle_common_errors(e, eh, "Delete API Mapping Failed", 91)
            else:
                eh.add_log("API Mapping Not found", {"id": api_mapping_id})
                return 0

@ext(handler=eh, op="setup_cloudfront_distribution")
def setup_cloudfront_distribution(prev_state, domains, cloudfront_distribution_override_def, stage_name):
    # This handles the case where we were using cloudfront and we stopped using it.
    cloudfront_op = eh.ops['setup_cloudfront_distribution'].get("op")
    cloudfront_aliases = list(set(map(lambda x: x['domain'], domains.values())))
    if not cloudfront_aliases:
        cloudfront_aliases = eh.ops['setup_cloudfront_distribution'].get("aliases")
    
    print(f"props = {eh.props}")

    # To maintain IDs
    if prev_state.get("props", {}).get(CLOUDFRONT_DISTRIBUTION_KEY, {}):
        eh.add_props({CLOUDFRONT_DISTRIBUTION_KEY: prev_state.get("props", {}).get(CLOUDFRONT_DISTRIBUTION_KEY, {})})

    domain_prop_key = list(filter(lambda x: x.startswith(CUSTOM_DOMAIN_KEY), eh.props.keys()))[0]
    target_endpoint = eh.props[domain_prop_key]["api_gateway_domain_name"]

    component_def = remove_none_attributes({
        "aliases": cloudfront_aliases,
        "target_domain_name": target_endpoint,
        "https_only": True,
        "cache_policy_name": "CachingDisabled",
        "origin_request_policy_name": "AllViewerExceptHostHeader"
    })

    component_def.update(cloudfront_distribution_override_def)

    function_arn = lambda_env('cloudfront_distribution_extension_arn')

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key=CLOUDFRONT_DISTRIBUTION_KEY, progress_start=85, progress_end=90,
        merge_props=False, op=cloudfront_op
    )

    if proceed and cloudfront_op == "delete":
        eh.props.pop(CLOUDFRONT_DISTRIBUTION_KEY, None)

    print(f"proceed = {proceed}")

@ext(handler=eh, op="setup_route53", complete_op=False)
def setup_route53(prev_state, cloudfront):
    print(f"props = {eh.props}")
    op_val = eh.ops["setup_route53"]
    print(f"op_val = {op_val}")
    delete_domains = op_val.get("delete")
    upsert_domains = op_val.get("upsert")
    print(f"delete_domains = {delete_domains}")
    print(f"upsert_domains = {upsert_domains}")

    if delete_domains:
        route53_op = "delete"
        using_domains = delete_domains
    elif upsert_domains:
        route53_op = "upsert"
        using_domains = upsert_domains
    
    domain_key = list(using_domains.keys())[0]
    domain = using_domains[domain_key].get("domain")
    hosted_zone_id = using_domains[domain_key].get("hosted_zone_id")
    if not domain:
        eh.perm_error("'domains' dictionary must contain a 'domain' key inside the domain key")
        return

    custom_domain = eh.props.get(f"{CUSTOM_DOMAIN_KEY}_{domain_key}")

    if cloudfront:
        component_def = remove_none_attributes({
            "domain": domain,
            "route53_hosted_zone_id": hosted_zone_id,
            "alias_target_type": "cloudfront",
            "target_cloudfront_domain_name": None if route53_op == "delete" else eh.props[CLOUDFRONT_DISTRIBUTION_KEY]["domain_name"]
        })

    else:
        component_def = remove_none_attributes({
            "domain": domain,
            "route53_hosted_zone_id": hosted_zone_id,
            "target_api_hosted_zone_id": custom_domain.get("hosted_zone_id"),
            "target_api_domain_name": custom_domain.get("api_gateway_domain_name")
        })

    function_arn = lambda_env('route53_extension_arn')
    
    child_key = f"{ROUTE53_KEY}_{domain_key}"

    if prev_state and prev_state.get("props", {}).get(child_key, {}):
        eh.add_props({child_key: prev_state.get("props", {}).get(child_key, {})})

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        links_prefix=f"{ROUTE53_KEY} {domain_key} ", child_key=child_key, 
        progress_start=90, progress_end=100, op=route53_op
    )

    if proceed:
        # if (i != 1) or (len(list(available_domains.keys())) > 1) else "Website URL"
        if route53_op == "delete":
            del delete_domains[domain_key]
            if eh.props.get(child_key):
                del eh.props[child_key]
            if eh.props.get(f"{CUSTOM_DOMAIN_KEY}_{domain_key}"):
                del eh.props[f"{CUSTOM_DOMAIN_KEY}_{domain_key}"]
        else:
            del upsert_domains[domain_key]
        if delete_domains or upsert_domains:
            eh.add_op("setup_route53", {"delete": delete_domains, "upsert": upsert_domains})
            setup_route53(prev_state, cloudfront)
        else:
            eh.complete_op("setup_route53")

def gen_apigateway_arn(api_id, region):
    return f"arn:aws:apigateway:{region}::/apis/{api_id}"
