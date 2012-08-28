gfipm-ws-metro
==============

A set of Java Metro example implementations of the GFIPM Web Services SIPs.

  This is a GFIPM Web Services Status System.  It is a java tool that uses Metro for
WS-* support and is built with maven.

  There are four main projects:
   - wscontract - This is the Web Services Contract that represents the sample web service.
       It specifies the WSDL interface and generates a good bit of automated code for use
       in the service and consumer.  This must be built first.

   - trustfabric - This is both a java library used by the Model1 and Model2 components and 
                   it is also a command line utility for working with SAML 2 Metadata.

   - Model1 - This is the web service consumer (WSC) and web service provider (WSP) necessary for implementing
              the GFIPM Consumer-Provider SIP.  The WSC is a command line java program.  The WSP is built as a
              Java war file and will need to be deployed to an appropriate configured version of Glassfish. 
              Detailed instructions on configuring Glassfish are included within the subprojects.

   - Model2 - This is a web service consumer (WSC), web service provider (WSP), assertion delegate service (ADS), 
              and a command-line test client for testing.  All of these components are necessary for implementing
              the GFIPM User-Consumer-Provider SIP, which also relies on the Assertion Delegate Service SIP.  Each
              of the WSC, WSP, and ADS are built as Java war files that need to be deployed to Glassfish.  Detailed
              instructions for how to deploy each component are available in the subprojects.

All of the included code and configuration files are  Copyright (c) 2012, Georgia Institute of Technology. All Rights Reserved.  This code was developed by Georgia Tech Research Institute (GTRI) under a grant from the U.S. Dept. of Justice, Bureau of Justice Assistance.  It is licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

