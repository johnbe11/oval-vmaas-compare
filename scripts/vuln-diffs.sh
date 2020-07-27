#!/usr/bin/bash

# query the two indicated databases for vulnerability/feature data
# (intended to compare vmaas and oval vulnerability data)
# compare and print the results
# usage:
#    ./vuln-diffs.sh oval.database.host.name ovalDbPort vmaas.database.host.name vmaasDbPort

OVAL_HOST=$1
OVAL_PORT=$2

VMAAS_HOST=$3
VMAAS_PORT=$4

OVAL_LIST="query-results_oval"
VMAAS_LIST="query-results_vmaas"

DIFF_FILE_BASE="diff-vmaas-oval.txt"
DIFF_FILE_MISSING_FROM_VMAAS="missing-from-vmaas_${DIFF_FILE_BASE}"
DIFF_FILE_MISSING_FROM_OVAL="missing-from-oval_${DIFF_FILE_BASE}"
DIFF_FILE_FEATURES="features-diff_${DIFF_FILE_BASE}"

echo
date;

rm -f ${OVAL_LIST}
rm -f ${VMAAS_LIST}
rm -f ${DIFF_FILE_MISSING_FROM_VMAAS}
rm -f ${DIFF_FILE_MISSING_FROM_OVAL}
rm -f ${DIFF_FILE_FEATURES}

echo
echo "querying for oval data..."
psql --host=${OVAL_HOST} --port=${OVAL_PORT} --user=clair -c "select vulnerability.name, count(vulnerability_affected_feature.vulnerability_id) from vulnerability, vulnerability_affected_feature where vulnerability.id=vulnerability_affected_feature.vulnerability_id and vulnerability.name like 'CVE-% - R%' group by vulnerability.name;" > ${OVAL_LIST}
echo "oval query complete ($(tail -n 2 ${OVAL_LIST}))"

echo
echo "querying for vmaas data..."
psql --host=${VMAAS_HOST} --port=${VMAAS_PORT} --user=clair -c "select vulnerability.name, count(vulnerability_affected_feature.vulnerability_id) from vulnerability, vulnerability_affected_feature where vulnerability.id=vulnerability_affected_feature.vulnerability_id and vulnerability.name like 'CVE-% - R%' group by vulnerability.name;"> ${VMAAS_LIST}
echo "vmaas query complete ($(tail -n 2 ${VMAAS_LIST}))" 

if [ "${OVAL_LIST}" = "" ]; then
    # nothing to do
    echo
    echo "ERROR: missing oval list"
    echo
    exit 1
fi

if [ "${VMAAS_LIST}" = "" ]; then
    # nothing to do
    echo
    echo "ERROR: missing vmaas list"
    echo
    exit 1
fi

echo
echo "processing results..."

echo
echo "##########################################"
echo "#     OVAL"
echo "##########################################"
declare -A OvalVulns; 

while read DB_LINE; 
do 
	VULN_NAME="$(echo "${DB_LINE}" | awk '{split($0,a,"|"); print a[1]}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')";
	VAF_COUNT="$(echo "${DB_LINE}" | awk '{split($0,a,"|"); print a[2]}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')";
	if [ "${VAF_COUNT}" != "" ] && [ "${VAF_COUNT}" != "count" ];
	then 
		OvalVulns["${VULN_NAME}"]="${VAF_COUNT}";
		#echo "${VULN_NAME}:${OvalVulns["${VULN_NAME}"]}";
	fi;
done < ${OVAL_LIST}
echo "..."
echo "Oval: processed ${#OvalVulns[@]} total vuln names"

echo
echo "##########################################"
echo "#     VMAAS"
echo "##########################################"
declare -A VmaasVulns; 

while read DB_LINE; 
do 
	VULN_NAME="$(echo "${DB_LINE}" | awk '{split($0,a,"|"); print a[1]}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')";
	VAF_COUNT="$(echo "${DB_LINE}" | awk '{split($0,a,"|"); print a[2]}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')";
	if [ "${VAF_COUNT}" != "" ] && [ "${VAF_COUNT}" != "count" ];
	then 
		VmaasVulns["${VULN_NAME}"]="${VAF_COUNT}";
		#echo "${VULN_NAME}:${VmaasVulns["${VULN_NAME}"]}";
	fi;
done < ${VMAAS_LIST}
echo "..."
echo "Vmaas: processed ${#VmaasVulns[@]} total vuln names"

echo
echo "comparing..."

declare -a CommonVulns; 
declare -A DiffCommonVulnFeatures; 

echo
echo "##########################################"
echo "#     Missing Vulns from Vmaas"
echo "##########################################"

declare -a MissingVmaasVulns; 
for VULN_NAME in "${!OvalVulns[@]}";
do
	echo "{${VULN_NAME}}"
	NUMBERS_VMAAS="${VmaasVulns[${VULN_NAME}]}"
	if [[ "${NUMBERS_VMAAS}" = "" ]];
	then
		MissingVmaasVulns=( "${MissingVmaasVulns[@]}" "${VULN_NAME}" )
		#MissingVmaasVulns[${#MissingVmaasVulns[@]}]=${VULN_NAME};
	else
		CommonVulns+=("${VULN_NAME}");
		# compare numbers of features
		NUMBERS_OVAL="${OvalVulns[${VULN_NAME}]}"
		if [[ "${NUMBERS_VMAAS}" != "${NUMBERS_OVAL}" ]];
		then
			DiffCommonVulnFeatures["${VULN_NAME}"]=$((NUMBERS_VMAAS-NUMBERS_OVAL))
		fi
	fi
done;
echo "Vmaas: ${#MissingVmaasVulns[@]} missing vuln names"

for VULN_NAME in "${MissingVmaasVulns[@]}";
do
	echo "${VULN_NAME}">>"${DIFF_FILE_MISSING_FROM_VMAAS}";
done;

echo
echo "##########################################"
echo "#     Missing Vulns from Oval"
echo "##########################################"

declare -a MissingOvalVulns; 
for VULN_NAME in "${!VmaasVulns[@]}";
do
	echo "{${VULN_NAME}}"
	NUMBERS_OVAL="${OvalVulns[${VULN_NAME}]}"
	if [[ "${NUMBERS_OVAL}" = "" ]];
	then
		MissingOvalVulns=( "${MissingOvalVulns[@]}" "${VULN_NAME}" )
		#MissingOvalVulns[${#MissingOvalVulns[@]}]=${VULN_NAME}
	fi
done;
echo "Oval: ${#MissingOvalVulns[@]} missing vuln names"

for VULN_NAME in "${MissingOvalVulns[@]}";
do
	echo "${VULN_NAME}">>"${DIFF_FILE_MISSING_FROM_OVAL}";
done;

echo
echo "##########################################"
echo "#     Common Vulns"
echo "##########################################"

echo "Common: ${#CommonVulns[@]} common vuln names"

for VULN_NAME in "${!DiffCommonVulnFeatures[@]}";
do
	echo "${VULN_NAME}:${DiffCommonVulnFeatures[${VULN_NAME}]}">>${DIFF_FILE_FEATURES};
done;

echo
echo "features diff available in file: ${DIFF_FILE_FEATURES}"

echo
date;
echo

exit 0;
