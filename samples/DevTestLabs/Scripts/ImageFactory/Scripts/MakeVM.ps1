param
(
    [Parameter(Mandatory=$true, HelpMessage="The full path to the module to import")]
    [string] $ModulePath,
    
    [Parameter(Mandatory=$true, HelpMessage="The full path of the template file")]
    [string] $TemplateFilePath,
    
    [Parameter(Mandatory=$true, HelpMessage="The name of the lab")]
    [string] $DevTestLabName,
    
    [Parameter(Mandatory=$true, HelpMessage="The name of the VM to create")]
    [string] $vmName,
    
    [Parameter(Mandatory=$true, HelpMessage="The path to the image file")]
    [string] $imagePath,
    
    [Parameter(Mandatory=$true, HelpMessage="The admin username for the VM")]
    [string] $machineUserName,
    
    [Parameter(Mandatory=$true, HelpMessage="The admin password for the VM")]
    [System.Security.SecureString] $machinePassword,

    [Parameter(Mandatory=$true, HelpMessage="The name of the lab")]
    [string] $vmSize,

    [boolean] $includeSysprep = $false
)

function makeUpdatedTemplateFile ($origTemplateFile, $outputFile)
{
    $armTemplate= ConvertFrom-Json -InputObject (Get-Content $origTemplateFile -Raw -Encoding Ascii)

    #add the Sysprep or deprovision artifact to the list of artifacts for the VM
    $newArtifact = @{}
    if ($armTemplate.resources[0].properties.galleryImageReference.osType -eq 'Windows')
    {
        $artifactName = 'windows-sysprep'
    }
    else 
    {
        $artifactName = 'linux-deprovision'
    }

    $fullArtifactId = "[resourceId('Microsoft.DevTestLab/labs/artifactSources/artifacts', parameters('labName'), 'public repo', '$artifactName')]"
    $newArtifact.artifactId = $fullArtifactId
    $existingArtifacts = $null
    if ($null -ne ($armTemplate.resources[0].properties | Get-Member -MemberType NoteProperty -Name 'artifacts'))
    {
        $existingArtifacts = $armTemplate.resources[0].properties.artifacts
    }

    if (($null -eq $existingArtifacts) -or ($existingArtifacts.Count -eq 0))
    {
        Write-Output "$origTemplateFile has no artifacts. Adding the $artifactName artifact"
        $artifactCollection = New-Object System.Collections.ArrayList
        $artifactCollection.Add($newArtifact)
        $armTemplate.resources[0].properties | Add-Member -Type NoteProperty -Name 'artifacts' -Value $artifactCollection -Force
    }
    elseif ($existingArtifacts[$existingArtifacts.count - 1].artifactId -eq $fullArtifactId)
    {
        Write-Output "$origTemplateFile already has the Sysprep/Deprovision artifact. It will not be added again"
    }
    else
    {
        #The ARM template does not end with the sysprep/deprovision artifact. We will add it
        #this is the common case
        Write-Output "Adding $artifactName artifact to $origTemplateFile template for deployment"
        $armTemplate.resources[0].properties.artifacts += $newArtifact
    }

    Write-Output "Writing modified ARM template to $outputFile"
    ($armTemplate | ConvertTo-Json -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }).Replace('\', '\\') | Out-File $outputFile

}

$DebugPreference = "SilentlyContinue" 
Set-StrictMode -Version Latest

Import-Module $ModulePath

LoadProfile

Write-Output "Starting Deploy for $TemplateFilePath"

#if the VM already exists then we fail out.
$existingVms = Get-AzResource -ResourceType "Microsoft.DevTestLab/labs/virtualMachines" -Name $DevTestLabName | Where-Object { $_.Name -eq "$DevTestLabName/$vmName"}
if(($null -ne $existingVMs) -and ($existingVms.Count -ne 0)){
    Write-Error "Factory VM creation failed because there is an existing VM named $vmName in Lab $DevTestLabName"
}
else {
    $deployName = "Deploy-$vmName"
    $ResourceGroupName = (Get-AzResource -ResourceType 'Microsoft.DevTestLab/labs' | Where-Object { $_.Name -eq $DevTestLabName}).ResourceGroupName
    
    if($includeSysprep)
    {
        $updatedTemplateFilePath = [System.IO.Path]::GetTempFileName()
        makeUpdatedTemplateFile $TemplateFilePath $updatedTemplateFilePath
    }
    else
    {
        Write-Output "Skipping sysprep step"
        $updatedTemplateFilePath = $TemplateFilePath
    }

    $vmDeployResult = New-AzResourceGroupDeployment -Name $deployName -ResourceGroupName $ResourceGroupName -TemplateFile $updatedTemplateFilePath -labName $DevTestLabName -newVMName $vmName -userName $machineUserName -password $machinePassword -size $vmSize

    #delete the deployment information so that we dont use up the total deployments for this resource group
    Remove-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deployName -ErrorAction SilentlyContinue | Out-Null

    if($vmDeployResult.ProvisioningState -eq "Succeeded"){
        Write-Output "Determining artifact status."

        #Determine if artifacts succeeded
        $vmResource = Get-AzResource -ResourceType 'Microsoft.DevTestLab/labs/virtualmachines' -ODataQuery "name EQ '$DevTestLabName/$vmName'" -ExpandProperties
        $existingVmArtStatus = $vmResource.Properties.ArtifactDeploymentStatus

        Write-Output 'Dumping status from all artifacts'
        Write-Output ('  ArtifactDeploymentStatus: ' + $existingVmArtStatus.deploymentStatus)

        if ($existingVmArtStatus.totalArtifacts -eq 0 -or $existingVmArtStatus.deploymentStatus -eq "Succeeded")
        {
            Write-Output "##[section]Successfully deployed $vmName from $imagePath"
            Write-Output "Stamping the VM $vmName with originalImageFile $imagePath"

            $tags = $vmResource.Tags
            if((Get-Command -Name 'New-AzResourceGroup').Parameters["Tag"].ParameterType.FullName -eq 'System.Collections.Hashtable'){
                # Azure Powershell version 2.0.0 or greater - https://github.com/Azure/azure-powershell/blob/v2.0.1-August2016/documentation/release-notes/migration-guide.2.0.0.md#change-of-tag-parameters
                $tags += @{ImagePath=$imagePath}
            }
            else {
                # older versions of the cmdlets use a hashtable array to represent the Tags
                $tags += @{Name="ImagePath";Value="$imagePath"}
            }

            Write-Output "Getting resource ID from Existing Vm"
            $vmResourceId = $vmResource.ResourceId 
            Write-Output "Resource ID: $vmResourceId"
            Set-AzResource -ResourceId $vmResourceId -Tag $tags -Force | Out-Null
        }
        else
        {
            if ($existingVmArtStatus.deploymentStatus -ne "Succeeded")
            {
                Write-Error ("##[error]Artifact deployment status is: " + $existingVmArtStatus.deploymentStatus)
            }
            Write-Error "##[error]Deploying VM artifacts failed. $vmName from $TemplateFilePath. Failure details follow:"
            $failedArtifacts = ($vmResource.Properties.Artifacts | Where-Object {$_.status -ne "Succeeded"})
            if($null -ne $failedArtifacts)
            { 
                foreach($failedArtifact in $failedArtifacts)
                {
                    if($failedArtifact.status -eq 'Pending')
                    {
                        Write-Output ('Pending Artifact ID: ' + $failedArtifact.artifactId)
                    }
                    elseif($failedArtifact.status -eq 'Skipped')
                    {
                        Write-Output ('Skipped Artifact ID: ' + $failedArtifact.artifactId)
                    }
                    else 
                    {
                        Write-Output ('Failed Artifact ID: ' + $failedArtifact.artifactId)
                        Write-Output ('   Artifact Status: ' + $failedArtifact.status)
                        Write-Output ('   DeploymentStatusMessage:  ' + $failedArtifact.deploymentStatusMessage)
                        Write-Output ('   VmExtensionStatusMessage: ' + $failedArtifact.vmExtensionStatusMessage)
                        Write-Output ''
                    }
                }
            }

            Write-Output "Deleting VM $vmName after failed artifact deployment"
            Remove-AzResource -ResourceId $vmResource.ResourceId -ApiVersion 2016-05-15 -Force
        }
    }
    else {
        Write-Error "##[error]Deploying VM failed:  $vmName from $TemplateFilePath"
    }

    return $vmName
}
