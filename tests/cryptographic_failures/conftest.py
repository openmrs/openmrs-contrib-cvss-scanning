import pytest
import pytest_bdd
import docker
import io
import tarfile

### SHARED STEPS ###

@pytest_bdd.when('the runtime properties are accessed')
def when_the_runtime_properties_are_accessed(encryption_data):
    
    client = docker.from_env()
    container = client.containers.get("openmrs-contrib-cvss-scanning-backend-1")
    
    # read in file from docker
    bits, stat = container.get_archive("/openmrs/data/openmrs-runtime.properties")
    
    # convert stream to memory
    buffer = io.BytesIO()
    for chunk in bits:
        buffer.write(chunk)
    buffer.seek(0)
    
    content = ""
    
    with tarfile.open(fileobj=buffer) as tar:
        f = tar.extractfile(tar.getmembers()[0])
        content = f.read().decode("utf-8")
    
    encryption_data["runtime_properties"] = content
    
### PYTEST FIXTURES ###

@pytest.fixture(scope="function")
def encryption_data():
    return {}