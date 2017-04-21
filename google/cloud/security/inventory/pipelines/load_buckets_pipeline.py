# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pipeline to load buckets data into Inventory."""

# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class LoadProjectsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RESOURCE_NAME = 'buckets'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _load(self, resource_name, data):
        """ Load iam policies into cloud sql.

        Args:
            resource_name: String of the resource name.
            data: An iterable or a list of data to be uploaded.

        Returns:
            None

        Raises:
            LoadDataPipelineError: An error with loading data has occurred.
        """
        try:
            self.dao.load_data(resource_name, self.cycle_timestamp, data)
        except (data_access_errors.CSVFileError,
                data_access_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _transform(self, buckets):
        """Transform API response data into a format loadable by MySQL.

        Args:
            buckets: An iterable of buckets from the Storage API response.

        Yields:
            An iterable of buckets.
        """
        pass

    def _retrieve(self):
        """Retrieve the project resources from GCP.

        Returns:
            An iterable of resource manager project list response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body
        """
        try:
            project_ids = []
            return self.api_client.list_buckets(project_ids)
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the data pipeline."""
        pass
