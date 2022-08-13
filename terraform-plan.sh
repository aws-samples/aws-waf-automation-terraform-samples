#!/bin/ksh
#set -e
Path=/home/ec2-user/environment/apgsolution1
cd $Path

read SNSEmail
echo "SNSEmail=\"$SNSEmail\"" > testing.tfvars

read ActivateHttpFloodProtectionParam
if [ $ActivateHttpFloodProtectionParam == "Lamda" ];
then
    echo 'HttpFloodAthenaLogParser="no"' >> testing.tfvars
    echo '"HttpFloodProtectionLogParserActivated=yes"' >> testing.tfvars
else
    echo 'HttpFloodAthenaLogParser="yes"' >> testing.tfvars
    echo 'HttpFloodProtectionLogParserActivated="yes"' >> testing.tfvars
fi

read ActivateScannersProbesProtectionParam
if [ $ActivateScannersProbesProtectionParam == "Lamda" ];
then
    echo 'ScannersProbesAthenaLogParser="no"' >> testing.tfvars
    echo 'ScannersProbesProtectionActivated="yes"' >> testing.tfvars
else
    echo 'ScannersProbesAthenaLogParser="yes"' >> testing.tfvars
    echo 'ScannersProbesProtectionActivated="yes"' >> testing.tfvars
fi

if [[ $ActivateScannersProbesProtectionParam == "Lamda" && $ActivateHttpFloodProtectionParam == "Lamda" ]];
then
    echo 'AthenaLogParser="no"' >> testing.tfvars
else
    echo 'AthenaLogParser="yes"' >> testing.tfvars
fi

if [[ -v ActivateHttpFloodProtectionParam || -v ActivateScannersProbesProtectionParam ]];
then
    echo 'LogParser="yes"' >> testing.tfvars
else
    echo 'LogParser="no"' >> testing.tfvars
fi

read BadBotProtectionActivated
echo "BadBotProtectionActivated=\"$BadBotProtectionActivated\"" >> testing.tfvars
read ReputationListsProtectionActivated
echo "ReputationListsProtectionActivated=\"$ReputationListsProtectionActivated\"" >> testing.tfvars

read IPRetentionPeriod
echo "IPRetentionPeriod=\"$IPRetentionPeriod\"" >> testing.tfvars

read Endpointtype
echo "SCOPE=\"$Endpointtype\"" >> testing.tfvars
echo "LOG_TYPE=\"$Endpointtype\"" >> testing.tfvars
echo "ENDPOINT=\"$Endpointtype\"" >> testing.tfvars

if [ $Endpointtype == "ALB" ];
then
    echo 'SCOPE="REGIONAL"' >> testing.tfvars
else
    echo 'SCOPE="CLOUDFRONT"' >> testing.tfvars
fi

if [[ $ActivateScannersProbesProtectionParam == "Lamda" && $Endpointtype == "ALB" ]];
then
    echo 'ALBScannersProbesAthenaLogParser="yes"' >> testing.tfvars
fi

if [[ $ActivateScannersProbesProtectionParam == "Lamda" && $Endpointtype == "cloudfront" ]];
then
    echo 'CloudFrontScannersProbesAthenaLogParser="yes"' >> testing.tfvars
fi


