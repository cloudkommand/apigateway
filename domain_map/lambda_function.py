import boto3
import botocore
from botocore.exceptions import ClientError
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, gen_log, creturn, handle_common_errors, \
    account_context, component_safe_name, ExtensionHandler, ext, lambda_env, \
    random_id, ext_handler

eh = ExtensionHandler()

apiv2 = boto3.client("apigatewayv2")
apiv1 = boto3.client("apigateway")
acm = boto3.client("acm")

@ext_handler(handler=eh)
def lambda_handler(event, context):
    try:
        prev_state = event.get("prev_state") or {}
        op = event.get("op")

        cdef = event.get("component_def")

        pass_back_data = event.get("pass_back_data", {})
        api_id = cdef.get("api_id")
        stage_name = cdef.get("stage_name")
        domain_name = cdef.get("domain_name")
        base_path = cdef.get("base_path")

        if eh.state.get("version") == 2:
            print("V2 API")
        elif eh.state.get("version") == 1:
            print("V1 API")
        
        eh.add_props({"name": domain_name})
        if pass_back_data:
            pass
        elif op == "upsert":
            eh.add_op("get_api")
            eh.add_op("get_api_mapping")
        elif op == "delete":
            eh.add_op("remove_api_mappings", [prev_state.get("props", {}).get("mapping_identifier")])

        get_api(api_id)
        get_api_mapping(api_id, domain_name, stage_name, op, base_path)
        remove_api_mappings(api_id, domain_name)
        create_api_mapping(api_id, domain_name, stage_name, base_path)
        update_api_mapping(api_id, domain_name, stage_name)

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": str(e)}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))

@ext(handler=eh)
def get_api(api_id):
    try:
        response = apiv2.get_api(
            ApiId=api_id
        )
        eh.add_log("Got API", response)
        eh.add_state({"version": 2})
        print("V2 API")
    except ClientError as e:
        if "Invalid API identifier specified" in str(e):
            # This is not an HTTP API, try the V1 API
            try:
                response = apiv1.get_rest_api(
                    restApiId=api_id
                )
                eh.add_log("Got API", response)
                eh.add_state({"version": 1})
                print("V1 API")
            except ClientError as e:
                handle_common_errors(e, eh, "Get API Failed", 2)
        else:
            handle_common_errors(e, eh, "Get API Failed", 2)

@ext(handler=eh)
def get_api_mapping(api_id, domain_name, stage_name, op, base_path):
    try:
        if eh.state.get("version") == 2:
            if base_path:
                eh.add_log("Warning: base_path Not Supported for HTTP APIs", {"base_path": base_path}, True)
            response = apiv2.get_api_mappings(DomainName=domain_name)
            eh.add_log("Got Domain API Mappings", response)
            this_api_mappings = list(filter(lambda x: x["ApiId"] == api_id, response['Items']))
            this_stage_mappings = list(filter(lambda x: x["Stage"] == stage_name, this_api_mappings))

            print(f"this_api_mappings = {this_api_mappings}")
            print(f"this_stage_mappings = {this_stage_mappings}")


            # If no mappings at all for this API, we need to create one
            if not this_api_mappings:
                eh.add_op("create_api_mapping")

            # If we already have a mapping for this stage, we update it, and remove all other mappings from this domain
            elif this_stage_mappings:
                keep_mapping_id = this_stage_mappings[0].get("ApiMappingId")
                eh.add_op("update_api_mapping", keep_mapping_id)
                if len(this_api_mappings) > 1:
                    eh.add_op("remove_api_mappings", list(map(lambda x: x['ApiMappingId'], filter(lambda x: x["ApiMapingId"] != keep_mapping_id, this_api_mappings))))

            # If we have a mapping for this API, but for a different stage, we remove all mappings for this domain, and create a new one
            elif not this_stage_mappings and this_api_mappings:
                eh.add_op("remove_api_mappings", list(map(lambda x: x['ApiMappingId'], this_api_mappings)))
                eh.add_op("create_api_mapping")

        else:
            response = apiv1.get_base_path_mappings(domainName=domain_name)
            eh.add_log("Got Domain API Mappings", response)
            this_stage_mappings = list(filter(lambda x: ((x["stage"] == stage_name) and (x['restApiId'] == api_id)), response.get('items', [])))
            print(f"this_stage_mappings = {this_stage_mappings}")

            if this_stage_mappings:
                print(f"This stage mappings: {this_stage_mappings}")
                test_base_path = base_path or "(none)"
                if test_base_path != this_stage_mappings[0].get("basePath"):
                    eh.add_op("remove_api_mappings", list(map(lambda x: x['basePath'], this_stage_mappings)))
                    eh.add_op("create_api_mapping")
                else:
                    eh.add_log("API Mapping Already Exists, Exiting", {"api_id": api_id, "domain_name": domain_name, "stage_name": stage_name})
                    eh.add_props({"mapping_identifier": this_stage_mappings[0].get("basePath")})
            else:
                eh.add_op("create_api_mapping")

    
    except ClientError as e:
        if e.response['Error']['Code'] == "NotFoundException":
            eh.add_log("Domain Name Not Found", {"domain_name": domain_name}, is_error=True)
            eh.perm_error("Domain Name Not Found", 5)
        else:
            handle_common_errors(e, eh, "Get API Mappings Failed", 5)
    

@ext(handler=eh)
def create_api_mapping(api_id, domain_name, stage_name, base_path):
    print(base_path)
    if eh.state.get("version") == 2 or "/" in base_path:
        try:
            params = remove_none_attributes({
                "ApiId": api_id,
                "DomainName": domain_name,
                "Stage": stage_name,
                "ApiMappingKey": base_path
            })
            response = apiv2.create_api_mapping(**params)

            eh.add_props({"mapping_identifier": base_path or response.get("ApiMappingId")})
            eh.add_log("Created API Mapping", response)
        except ClientError as e:
            if "ApiMapping key already exists for this domain name" in str(e):
                eh.add_log("Conflict, cannot Create API Mapping", {"api_id": api_id, "domain_name": domain_name, "stage_name": stage_name})
                eh.perm_error("API Mapping Already Exists for this Domain", 20)
            else:
                handle_common_errors(e, eh, "Create API Mapping Failed", 20)
    else:
        try:
            parameters = remove_none_attributes({
                "basePath": base_path,
                "restApiId": api_id,
                "stage": stage_name
            })

            response = apiv1.create_base_path_mapping(domainName=domain_name, **parameters)
            eh.add_log("Created API Mapping", response)
            eh.add_props({"mapping_identifier": response.get("basePath")})

        except ClientError as e:
            if "already exists" in str(e):
                eh.add_log("Conflict, cannot Create API Mapping", {"api_id": api_id, "domain_name": domain_name, "stage_name": stage_name})
                eh.perm_error("API Mapping Already Exists for this Domain, Stage, and base_path", 20)
            elif e.response['Error']['Code'] == "BadRequestException":
                if "Invalid stage identifier specified" in str(e):
                    eh.add_log("Invalid Stage", {"api_id": api_id, "domain_name": domain_name, "stage_name": stage_name}, is_error=True)
                    eh.perm_error("Invalid Stage", 20)
                else:
                    handle_common_errors(e, eh, "Create API Mapping Failed", 20, perm_errors=["BadRequestException"])
            else:
                handle_common_errors(e, eh, "Create API Mapping Failed", 20)

# Only used with V2 APIs
@ext(handler=eh)
def update_api_mapping(api_id, domain_name, stage_name):
    try:
        response = apiv2.update_api_mapping(
            ApiId=api_id,
            ApiMappingId=eh.ops['update_api_mapping'],
            DomainName=domain_name,
            Stage=stage_name
        )

        eh.add_props({"mapping_identifier": response.get("ApiMappingId")})
        eh.add_log("Updated API Mapping", response)
    except ClientError as e:
        handle_common_errors(e, eh, "Update API Mapping Failed", 91)

@ext(handler=eh)
def remove_api_mappings(api_id, domain_name):

    for mapping_identifier in eh.ops['remove_api_mappings']:
        print(mapping_identifier)
        if eh.state.get("version") == 2:
            try:
                apiv2.delete_api_mapping(
                    ApiMappingId=mapping_identifier,
                    DomainName=domain_name
                )
                eh.add_log("Removed API Mapping", {"id": mapping_identifier, "domain_name": domain_name})

            except ClientError as e:
                if e.response['Error']['Code'] != "NotFoundException":
                    handle_common_errors(e, eh, "Delete API Mapping Failed", 91)
                else:
                    eh.add_log("API Mapping Not found", {"id": mapping_identifier})
        else:
            if "/" in mapping_identifier:
                try:
                    response = apiv2.get_api_mappings(
                        DomainName=domain_name
                    )
                    print(response)
                    delete_identifier = list(filter(lambda x: x["ApiMappingKey"] == mapping_identifier, response['Items']))[0].get("ApiMappingId")
                    
                    apiv2.delete_api_mapping(
                        ApiMappingId=delete_identifier,
                        DomainName=domain_name
                    )
                    eh.add_log("Removed API Mapping", {"id": mapping_identifier, "domain_name": domain_name})
                except ClientError as e:
                    if e.response['Error']['Code'] != "NotFoundException":
                        handle_common_errors(e, eh, "Get Special V2 API Mappings Failed", 91)
                    else:
                        eh.add_log("API Mapping Not Found", {"id": mapping_identifier, "domain_name": domain_name})
                        return 0
            else:        
                try:
                    apiv1.delete_base_path_mapping(
                        domainName=domain_name,
                        basePath=mapping_identifier
                    )
                    eh.add_log("Removed API Mapping", {"basePath": mapping_identifier, "domain_name": domain_name})

                except ClientError as e:
                    if e.response['Error']['Code'] != "NotFoundException":
                        handle_common_errors(e, eh, "Delete API Mapping Failed", 91)
                    else:
                        eh.add_log("API Mapping Not found", {"basePath": mapping_identifier})
