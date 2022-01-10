import time
import json
import datetime
import boto3

def generate_openapi_definition(name, full_resources, cors_configuration, authorizers, account_number, payload_version="2.0", region="us-east-1"):
    """
    Args:
        name (string): Name of API
        resources (dict): {
            "/{proxy+}": {
                "GET": Either:
                    "<lambda_arn>"
                    ["<lambda_arn>", "<authorizer_name>"]
                    {"dict with lambda_arn as key}
            },
            "/agreatpath": {
                "ANY": "lambda-arn",
                "/soar": {
                    "GET": "lambda-arn",
                    "POST": ["lambda_arn", "<authorizer_name>"]
                }
            }
        }
        cors_configuration (dict): {
            "allowOrigins": [
                "*"
            ],
            "allowMethods": [
                "*"
            ],
            "allowHeaders": [
                "x-amzm-header",
                "x-apigateway-header",
                "x-api-key",
                "authorization",
                "x-amz-date",
                "content-type"
            ],
            "exposeHeaders": [
                "cache-control",
                "content-language",
                "content-type",
                "expires",
                "last-modified"
            ],
            "maxAge": 600
        }
        authorizers (dict): {
            "[name]": {
                ### FOR JWT
                "audience"/"audiences": JWT audience(s) to check. REQUIRED
                "issuer": The JWT Issuer. Either pass issuer of connect_url
                "connect_url": Cognito Endpoint to get Issuer from. Either pass issuer of connect_url
                "source": Only use this endpoint if the OAuth endpoint is supposed to use a different header other than Authorization
                ### FOR Lambda
                "function_arn"/"lambda_arn": The Lambda ARN. REQUIRED
                "payload_version": "2.0"/"1.0", defaults to "2.0"
                "enable_simple_responses": Defaults to True
                "cache_seconds": How long to cache this Authorizer result. Defaults to 300
            }
        }
        account_number ([type]): [description]
        region (str, optional): [description]. Defaults to "us-east-1".
    """
    def fix(key):
        if key.strip().lower() == "!proxy":
            return "/{proxy+}"
        else:
            return key

    def generate_path_section(data, parent_path=None):
        lambda_permissions = set()
        resources = {}
        data = {fix(k):v for k,v in data.items()}

        for k, v in data.items():
            path = k if k.startswith("/") else None
            if path:
                subresources, sub_lambda_permissions = generate_path_section(v, k)
                resources.update(subresources)
                lambda_permissions = lambda_permissions | sub_lambda_permissions

            elif not parent_path or k.upper() not in ['GET', "POST", "PUT", "PATCH", "OPTIONS", "HEAD", "DELETE", "ANY"]:
                raise Exception(f"Must pass at least one base path")

            else:
                method_key = k.lower() if k.lower() != "any" else "x-amazon-apigateway-any-method"
                integration_type, uri, function_name, auth_name = get_integration_parameters(v, account_number, region)
                print(f"integration_type {integration_type}, uri {uri}, auth_name {auth_name}")

                if function_name:
                    lambda_permissions.add(function_name)

                if integration_type != "http_proxy":
                    new_data = {
                        "x-amazon-apigateway-integration": remove_none_attributes({
                            "uri": uri,
                            "payloadFormatVersion": payload_version,
                            "httpMethod": "POST" if function_name else k.upper(),
                            "type": integration_type,
                            "timeoutInMillis": 29000
                        })
                    }
                else:
                    new_data = {
                        "x-amazon-apigateway-integration": remove_none_attributes({
                            "uri": uri,
                            "httpMethod": k.upper(),
                            "requestParameters": {
                                "integration.request.path.proxy": "method.request.path.proxy"
                            },
                            "passthroughBehavior": "when_no_match",
                            "type": integration_type,
                            "timeoutInMillis": 29000
                        })
                    }

                if auth_name:
                    new_data['security'] = [{auth_name: []}]

                if resources.get(parent_path):
                    resources[parent_path][method_key] = new_data
                else:
                    resources[parent_path] = {method_key: new_data}

        return resources, lambda_permissions

    paths, lambda_permissions = generate_path_section(full_resources)

    authorizers_formatted = None
    if authorizers:
        security_schemes = {}
        for key, value in authorizers.items():
            if value.get("connect_url"):
                security_schemes[key] = {
                    "type": "openIdConnect",
                    "openIdConnectUrl": value['connect_url'],
                    "x-amazon-apigateway-authorizer": {
                        "type": "jwt",
                        "jwtConfiguration": {
                            "audience": [value.get("audience")] or value.get("audiences")
                        },
                        "identitySource": value.get("source") or "$request.header.Authorization"
                    }
                }
            elif value.get("lambda_arn") or value.get("function-arn"):
                lambda_permissions.add(value.get("lambda_arn") or value.get("function-arn"))
                security_schemes[key] = {
                    "type": "apiKey",
                    "name": "Authorization",
                    "in": "header",
                    "x-amazon-apigateway-authorizer": {
                        "type": "request",
                        "identitySource": value.get("source") or "$request.header.Authorization",
                        "authorizerPayloadFormatVersion": value.get("payload_version") or "2.0",
                        "authorizerUri": f'arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{value.get("lambda_arn") or value.get("function-arn")}/invocations',
                        "enableSimpleResponses": value.get("enable_simple_responses", True),
                        "authorizerResultTtlInSeconds": value.get("cache_seconds", 300)
                    }
                }
            else:
                security_schemes[key] = {
                    "type": "oauth2",
                    "x-amazon-apigateway-authorizer": {
                        "type": "jwt",
                        "jwtConfiguration": {
                            "issuer": value['issuer'],
                            "audience": [value.get("audience")] or value.get("audiences")
                        },
                        "identitySource": value.get("source") or "$request.header.Authorization"
                    }
                }
        
        authorizers_formatted = {"securitySchemes": security_schemes}

    definition = remove_none_attributes({
        "openapi": "3.0.1",
        "info": {
            "title": name
        },
        "paths": paths,
        "x-amazon-apigateway-cors": cors_configuration,
        "components": authorizers_formatted
    })
    print(definition)
    print(lambda_permissions)

    return definition, list(lambda_permissions)

def remove_none_attributes(payload):
    """Assumes dict"""
    return {k: v for k, v in payload.items() if not v is None}

def get_lambda_name_from_arn(arn):
    return arn.split(':')[6]

def get_first_two_values(value, account_number, region):
    try:
        v = value.get("arn")
    except:
        v = value
    if v.startswith("http"):
        integration_type = "http_proxy"
        uri = v
        function_name = None
    else:
        integration_type = "aws_proxy"
        uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{v}/invocations"
        function_name = get_lambda_name_from_arn(v)

    return integration_type, uri, function_name

def get_integration_parameters(v, account_number, region):
    print(f"v = {v}")
    try:
        check_val = v[1][0]
        integration_type, uri, function_name = get_first_two_values(v[0], account_number, region)
        auth_name = v[1]
    except:
        integration_type, uri, function_name = get_first_two_values(v, account_number, region)
        auth_name = None

    return integration_type, uri, function_name, auth_name

def get_default_cors_configuration(cors_enabled):
    if cors_enabled:
        return {
            "allowOrigins": [
                "*"
            ],
            "allowMethods": [
                "*"
            ],
            "allowHeaders": [
                "x-amzm-header",
                "x-apigateway-header",
                "x-api-key",
                "authorization",
                "x-amz-date",
                "content-type"
            ],
            "exposeHeaders": [
                "cache-control",
                "content-language",
                "content-type",
                "expires",
                "last-modified"
            ],
            "maxAge": 600
        }

# def get_acm_certificate_arn