from aws_cdk import App
from aws_cdk import CfnOutput
from aws_cdk import Duration
from aws_cdk import Environment
from aws_cdk import Stack

from aws_cdk.aws_lambda import Runtime
from aws_cdk.aws_lambda import FunctionUrlAuthType

from aws_cdk.aws_lambda_python_alpha import PythonFunction

from aws_cdk.aws_secretsmanager import Secret

from aws_cdk.aws_sqs import DeadLetterQueue
from aws_cdk.aws_sqs import Queue

from constructs import Construct


US_WEST_2 = Environment(
    account='109189702753',
    region='us-west-2',
)


class GithubWebhook(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        secret = Secret.from_secret_complete_arn(
            self,
            'Secret',
            secret_arn='arn:aws:secretsmanager:us-west-2:109189702753:secret:github-webhook-secret-hz6JXf',
        )

        dead_letter_queue = Queue(
            self,
            'DeadLetterQueue',
            retention_period=Duration.days(14),
        )

        queue = Queue(
            self,
            'Queue',
            visibility_timeout=Duration.seconds(120),
            dead_letter_queue=DeadLetterQueue(
                queue=dead_letter_queue,
                max_receive_count=3,
            )
        )

        handler = PythonFunction(
            self,
            'Handler',
            runtime=Runtime.PYTHON_3_10,
            entry='lambda',
            memory_size=512,
            timeout=Duration.seconds(60),
            environment={
                'QUEUE_URL': queue.queue_url,
                'SECRET_ARN': secret.secret_arn,
            }
        )

        secret.grant_read(
           handler
        )

        queue.grant_send_messages(
            handler
        )

        function_url = handler.add_function_url(
            auth_type=FunctionUrlAuthType.NONE,
        )

        CfnOutput(
            self,
            'LambdaURL',
            value=function_url.url,
        )


app = App()


GithubWebhook(
    app,
    'GithubWebhook',
    env=US_WEST_2,
)


app.synth()
