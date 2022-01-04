import boto3
import botocore
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name
from util import get_default_cors_configuration, generate_openapi_definition

eh = ExtensionHandler()
# def validate_state(state):
# "prev_state": prev_state,
# "component_def": component_def, RENDERED
# "op": op,
# "s3_object_name": object_name,
# "pass_back_data": pass_back_data
#     jsonschema.validate()

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
        pass_back_data = event.get("pass_back_data", {})
        api_id = prev_state.get("props", {}).get("api_id")
        old_log_group_name = prev_state.get("props", {}).get("log_group_name")
        
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            eh.add_op("get_current_state")
        elif event.get("op") == "delete":
            eh.add_op("delete_api", api_id)
        
        get_current_state(log_group_name, api_id, old_log_group_name, stage_name, region)
        create_cloudwatch_log_group(region, account_number)
        create_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, custom_domain_name=None)
        update_api(api_name, resources, cors_configuration, authorizers, account_number, lambda_payload_version, region, api_id, prev_state, custom_domain_name=None)
        add_lambda_permissions(account_number)
        create_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        update_stage(stage_variables, throttling_burst_limit, throttling_rate_limit)
        delete_stage()
        confirm_stage_deployment()
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
    print(f"mine = {mine}")

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
    apiv2 = boto3.client("apigatewayv2")

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
    apiv2 = boto3.client("apigatewayv2")

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
    apiv2 = boto3.client("apigatewayv2")

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
    apiv2 = boto3.client("apigatewayv2")

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
    endpoint_with_stage = f"{eh.props['api_endpoint']}/{stage_name}"
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
    apiv2 = boto3.client("apigatewayv2")

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
    apiv2 = boto3.client("apigatewayv2")

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
    apiv2 = boto3.client("apigatewayv2")

    stage_name = eh.ops['confirm_stage_deployment']
    api_id = eh.props['api_id']

    response = apiv2.get_stage(ApiId=api_id, StageName=stage_name)
    print(response)
    status = response.get("LastDeploymentStatusMessage")
    if status and status.startswith("Successfully deployed stage with deployment"):
        eh.add_log("Stage Deployed", {"stage_name": stage_name})
        eh.complete_op("confirm_stage_deployment")
    else:
        eh.add_log("Stage Still Deploying", {"stage_name": stage_name})
        eh.declare_return(200, 75, error_code="stage_deploying")
