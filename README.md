# apigateway
API Gateway Plugins for CloudKommand. Deploy AWS API Gateway Resources

## Routing Using This Plugin

### Example 1:
This example routes all calls to a single Lambda function and sets up a Lambda custom authorizer for all calls to this API. It also sets up CORS to allow for browser calls.

In this example we have added this repository to our kommand.json with the key 'apigw'. Our kommand.json also includes two Lambda <https://github.com/cloudkommand/lambda> components, 'api_lambda' and 'authorizer'. In order for CORS to work with an authorizer, we need to route OPTIONS calls directly to api_lambda, while all other calls are handled by the ANY tag and will first be routed through the authorizer. By default, authorizers cache the authorization result for a given token for 5 minutes, which suits this basic case.


```json
{
    "type": "@apigw.api",
    "resources": {
        "/{proxy+}": {
            "OPTIONS": "@api_lambda",
            "ANY": ["@api_lambda:props.arn", "custom"]
        }
    },
    "authorizers": {
        "custom": {
            "lambda_arn": "@authorizer:props.arn"
        }
    },
    "cors_enabled": true
}
```

### Example 2:
This example routes calls to two different Lambdas depending on the version of the API. This is how cloudkommand recommends versioning your APIs, its much simpler than utilizing stages inside API Gateway with separate mappings (and duplicate code should be added to a Lambda layer). It also two additional endpoints setup to only receive POST calls from specific providers, receiving them without an Authorization header. Finally, it caches the authorizer response for the v2 authorizer based on both the token and the route.

```json
{
    "type": "@apigw.api",
    "resources": {
        "/api/v1/{proxy+}": {
            "OPTIONS": "@api_lambda",
            "ANY": ["@api_lambda", "custom"]
        },
        "/api/v2/{proxy+}": {
            "OPTIONS": "@api_lambda_v2",
            "ANY": ["@api_lambda_v2", "v2"]
        },
        "/api/webhooks/facebook": {
            "POST": "@fb_webhook_lambda"
        },
        "/api/webhooks/google": {
            "POST": "@g_webhook_lambda"
        }
    },
    "authorizers": {
        "custom": {
            "lambda_arn": "@authorizer:props.arn"
        },
        "v2": {
            "lambda_arn": "@authorizer_v2:props.arn",
            "source": " $request.header.Authorization,$context.path"
        }
    },
    "cors_enabled": true
}
```

### Example 3:
This example routes calls through the facebook OIDC authorizer. It also includes a set of endpoints provided with public access. It sets up two allowed audiences for the authorizer to validate against, and if the token provided in the authorization header doesn't match at least one of those audiences, the authorizer will reject the call. The resources section here shows how to nest paths inside other paths. All calls to api/v1/unauthenticated/... will route to public lambda, while all calls to api/v1/... will route to api_lambda.

```json
{
    "type": "@apigw.api",
    "resources": {
        "/api/v1": {
            "/unauthenticated/{proxy+}": {
                "GET": "@public_lambda"
            },
            "/{proxy+}": {
                "OPTIONS": "@api_lambda",
                "ANY": ["@api_lambda:props.arn", "fb"]
            }
        },
    },
    "authorizers": {
        "fb": {
            "audiences": ["allowed_audience_1", "allowed_audience_2"],
            "issuer": "https://www.facebook.com"
        }
    },
    "cors_enabled": true
}
```

