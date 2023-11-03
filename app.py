from aws_cdk import App
from aws_cdk import CfnOutput
from aws_cdk import Duration
from aws_cdk import Environment
from aws_cdk import Stack

from aws_cdk.aws_lambda import Runtime
from aws_cdk.aws_lambda import FunctionUrlAuthType

from aws_cdk.aws_lambda_python_alpha import PythonFunction

from constructs import Construct


US_WEST_2 = Environment(
    account='618537831167',
    region='us-west-2',
)


class GithubWebhook(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        python_function = PythonFunction(
            self,
            'PythonFunction',
            runtime=Runtime.PYTHON_3_10,
            entry='lambda',
            memory_size=512,
            timeout=Duration.seconds(60),
        )

        function_url = python_function.add_function_url(
            auth_type=FunctionUrlAuthType.NONE,
        )

        CfnOutput(
            self,
            'LambdaURL',
            value=function_url.url,
        )


app = App()

GithubWebhook
    app,
    'GithubWebhook',
    env=US_WEST_2,
)


app.synth()
