import boto3
import botocore
from botocore.exceptions import ClientError
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, gen_log, creturn, handle_common_errors, \
    account_context, component_safe_name, ExtensionHandler, ext, lambda_env

eh = ExtensionHandler()

v2 = boto3.client("apigatewayv2")
acm = boto3.client("acm")

def lambda_handler(event, context):
    try:
        print(event)
        eh.capture_event(event)

        region = account_context(context)['region']
        account_number = account_context(context)['number']
        prev_state = event.get("prev_state") or {}
        op = event.get("op")

        cdef = event.get("component_def")

        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        
        tags = cdef.get("tags") or {}
        # if role and (not "lambda" in role.get("role_services", [])) and (not "lambda.amazonaws.com" in role.get("role_services", [])):
        #     return creturn(200, 0, error=f"The referenced role must have lambda in its list of trusted services")

        # elif prev_state.get("props", {}).get("Role", {}).get("arn"):
        #     eh.add_state({"role_arn": prev_state.get("props", {}).get("Role", {}).get("arn")})
        # if not role_arn:
        #     return creturn(200, 0, error=f"Must provide a role_arn. Please use either the role or role_arn keywords")

        domain_name = cdef.get("name") or form_domain(component_safe_name(project_code, repo_id, cname, no_underscores=False), cdef.get("base_domain"))
        pass_back_data = event.get("pass_back_data", {})
        
        eh.add_props({"name": domain_name})
        if pass_back_data:
            pass
        elif op == "upsert":
            eh.add_op("get_acm_cert")
        elif op == "delete":
            eh.add_op("remove_old", {"name": domain_name})

        get_acm_cert(domain_name, region)

        if eh.props.get("certificate_arn"):
            desired_config = remove_none_attributes({
                "CertificateArn": eh.props['certificate_arn'],
                "EndpointType": "REGIONAL",
                "SecurityPolicy": "TLS_1_2"
            })

            desired_tls_config = remove_none_attributes({
                "TruststoreUri": cdef.get("truststore_uri"),
                "TruststoreVersion": cdef.get("truststore_version")
            })

            domain_name_arn = gen_apigateway_arn(domain_name, region)

            get_domain_name(prev_state, domain_name, desired_config, desired_tls_config, tags)
            create_domain_name(domain_name, desired_config, desired_tls_config, tags, region)
            update_domain_name(domain_name, desired_config, desired_tls_config, region)
            remove_tags(domain_name_arn)
            add_tags(domain_name_arn)
            remove_domain_name()

        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Uncovered Error", {"error": str(e)}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

def form_domain(subdomain, base_domain):
    if subdomain and base_domain:
        return f"{subdomain}.{base_domain}"
    else:
        return None

@ext(handler=eh, op="get_acm_cert")
def get_acm_cert(domain_name, region):
    cursor = 'none'
    certs = []
    while cursor:
        try:
            payload = remove_none_attributes({
                # "CertificateStatuses": ["ISSUED"],
                "NextToken": cursor if cursor != 'none' else None
            })
            cert_response = acm.list_certificates(**payload)
            print(f"cert_response = {cert_response}")
            certs.extend(cert_response.get("CertificateSummaryList", []))
            cursor = cert_response.get("nextToken")
        except ClientError as e:
            handle_common_errors(e, eh, "List Certificates Failed", 0)
    
    sorted_matching_certs = list(filter(lambda x: domain_name.endswith(x["DomainName"]), certs)).sort(key=lambda x:len(x['DomainName']))
    print(f"sorted_matching_certs = {sorted_matching_certs}")

    if not sorted_matching_certs:
        eh.perm_error("No Matching ACM Certificate Found, Cannot Create API Custom Domain")
        eh.add_log("No Matching ACM Certificates", {"all_certs": certs}, is_error=True)
        return 0

    eh.add_op("get_domain_name")
    certificate_arn = sorted_matching_certs[0]['CertificateArn']
    eh.add_props({"certificate_arn": certificate_arn})
    eh.add_links({"ACM Certificate": gen_certificate_link(certificate_arn, region)})

@ext(handler=eh, op="get_domain_name")
def get_domain_name(prev_state, domain_name, desired_config, desired_tls_config, tags):
    if prev_state and prev_state.get("props", {}).get("name"):
        old_domain_name = prev_state["props"]["name"]
        if old_domain_name and (old_domain_name != domain_name):
            eh.add_op("remove_old", {"name": old_domain_name, "create_and_remove": True})

    try:
        response = v2.get_domain_name(DomainName=domain_name)

        print(f'Selection Expression = {response.get("ApiMappingSelectionExpression")}')
        print(f"response = {response}")
        eh.add_log("Got Domain Name", response)
        config = response.get("DomainNameConfigurations")[0]
        tls_config = response.get("MutualTlsAuthentication")
        desired_config['CertificateArn'] = eh.props['certificate_arn']

        match = True
        for k, v in desired_config.items():
            if v != config[k]:
                eh.add_op("update_domain_name")
                match = False

        if match:
            for k,v in desired_tls_config.items():
                if v != tls_config[k]:
                    eh.add_op("update_domain_name")
                    match = False
        if match:
            eh.add_log("Domain Update Unncessary", {"config": config, "desired_config": desired_config})

        current_tags = response.get("Tags") or {}
        if tags != current_tags:
            remove_tags = [k for k in current_tags.keys() if k not in tags]
            add_tags = {k:v for k,v in tags.items() if k not in current_tags.keys()}
            if remove_tags:
                eh.add_op("remove_tags", remove_tags)
            if add_tags:
                eh.add_op("add_tags", add_tags)

    except ClientError as e:
        if e.response['Error']['Code'] == "NotFoundException":
            eh.add_op("create_domain_name")
            eh.add_log("Domain Name Does Not Exist", {"domain_name": domain_name})
        else:
            handle_common_errors(e, eh, "Get Domain Name Failed", 10)

    
@ext(handler=eh, op="create_domain_name")
def create_domain_name(domain_name, desired_config, desired_tls_config, tags, region):
    try:
        params = remove_none_attributes({
            "DomainName": domain_name,
            "DomainNameConfigurations": [desired_config],
            "MutualTlsAuthentication": desired_tls_config or None,
            "Tags": tags or None
        })

        response = v2.create_domain_name(**params)
        print(f"create response {response}")

        eh.add_log("Created Domain Name", response)
        config = response['DomainNameConfigurations'][0]
        eh.add_props({
            "hosted_zone_id": config.get("HostedZoneId"),
            "api_gateway_domain_name": config.get("ApiGatewayDomainName")
        })
        eh.add_links({
            "AWS Custom Domain Name": gen_custom_domain_link(domain_name, region)
        })

    except ClientError as e:
        handle_common_errors(e, eh, "Create Failure", 35, 
            ["NotFoundException", "BadRequestException", "AccessDeniedException"]
        )

@ext(handler=eh, op="update_domain_name")
def update_domain_name(domain_name, desired_config, desired_tls_config, region):
    try:
        params = remove_none_attributes({
            "DomainName": domain_name,
            "DomainNameConfigurations": [desired_config],
            "MutualTlsAuthentication": desired_tls_config or None,
        })

        response = v2.update_domain_name(**params)
        print(f"update response {response}")

        eh.add_log("Updated Domain Name", response)
        config = response['DomainNameConfigurations'][0]
        eh.add_props({
            "hosted_zone_id": config.get("HostedZoneId"),
            "api_gateway_domain_name": config.get("ApiGatewayDomainName")
        })
        eh.add_links({
            "AWS Custom Domain Name": gen_custom_domain_link(domain_name, region)
        })

    except ClientError as e:
        handle_common_errors(e, eh, "Update Failure", 35, 
            ["NotFoundException", "BadRequestException", "AccessDeniedException"]
        )

@ext(handler=eh, op="remove_old")
def remove_domain_name():
    op_def = eh.ops['remove_old']
    domain_name = op_def['name']
    create_and_delete = op_def.get("create_and_delete") or False

    try:
        response = v2.delete_domain_name(DomainName=domain_name)
        eh.add_log(f"Deleted Domain Name", response)

    except ClientError as e:
        if e.response['Error']['Code'] == 'NotFoundException':
            eh.add_log(f"Domain Name does not Exist", {"domain_name": domain_name})
        else:
            eh.retry_error(str(e), 90 if create_and_delete else 15)
            eh.add_log(f"Error Deleting Domain Name", {"domain_name": domain_name}, True)

@ext(handler=eh, op="add_tags")
def add_tags(domain_name_arn):
    tags = eh.ops['add_tags']

    try:
        v2.tag_resource(
            ResourceArn=domain_name_arn,
            Tags=tags
        )
        eh.add_log("Tags Added", {"tags": tags})

    except ClientError as e:
        handle_common_errors(e, eh, "Add Tags Failed", 70, ['InvalidParameterValueException'])
        
@ext(handler=eh, op="remove_tags")
def remove_tags(domain_name_arn):

    try:
        v2.untag_resource(
            ResourceArn=domain_name_arn,
            TagKeys=eh.ops['remove_tags']
        )
        eh.add_log("Tags Removed", {"tags": eh.ops['remove_tags']})

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Remove Tags Failed", 85, ['InvalidParameterValueException'])

def gen_apigateway_arn(domain_name, region):
    return f"arn:aws:apigateway:{region}::/domainnames/{domain_name}"

def gen_certificate_link(certificate_arn, region):
    return f"https://console.aws.amazon.com/acm/home?region={region}#/certificate/{certificate_arn.rsplit('/')[0]}"

def gen_custom_domain_link(domain_name, region):
    return f"https://console.aws.amazon.com/apigateway/main/publish/domain-names?domain={domain_name}&region={region}"

"""
{
    'CertificateSummaryList': [
        {
            'CertificateArn': 'arn:aws:acm:us-east-1:876786787:certificate/aaaaaaaaaaguid', 
            'DomainName': 'somedomain.link'
        }
    ], 
    'ResponseMetadata': {
        'RequestId': '69eeeec6-6a4e-4efd-b4a9-587e95a45aa4', 
        'HTTPStatusCode': 200, 
        'HTTPHeaders': {
            'x-amzn-requestid': '69eeeec6-6a4e-4efd-b4a9-587e95a45aa4', 
            'content-type': 'application/x-amz-json-1.1', 
            'content-length': '164', 
            'date': 'Sat, 01 Jan 2022 19:20:27 GMT'
        }, 
        'RetryAttempts': 0
    }
}
"""