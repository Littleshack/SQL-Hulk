############################################
############  Variable library #############
############################################

$db_summary_db = "databaseserver1.corp.com;Database=DB_Summary"
$too_old = 365 ## How many days a server has to be down before being deleted
$corpdomain = "corp.yourcorp.com"

#########  End variable libray  ############
####### DO NOT EDIT BELOW THIS LINE! #######

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null

Write-Host "*******************************"
Write-Host "**                           **"
Write-Host "** SQL Enumeration Tool V1.0 **"
write-host "**                           **"
Write-Host "**        Written by:        **"
Write-Host "**                           **"
Write-Host "**      Sean Greathouse      **"
Write-Host "**  sdgreathouse@ashland.com **"
Write-Host "**                           **"
Write-Host "**       Assisted by:        **"
Write-Host "**      Wesley Gaunce        **"
write-host "**     Markus Williams       **"
write-host "**                           **"
write-host "*******************************"

#Create a sqlconnection object
$con = New-Object System.Data.SqlClient.SqlConnection
$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"

$array = Get-Content C:\servers.txt

######################
## DoStuff function ##
######################

function DoStuff {

	$con = New-Object System.Data.SqlClient.SqlConnection
	$con.ConnectionString = "Server=$instance;Database=master;Integrated Security=true;"
	#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"	

	#########################################
	##  Begin enumeration of the Instance  ##
	#########################################	
				
	write-host "Pulling patch level from: " $instance
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
    	$cmd.connection = $con
    	$cmd.CommandText = "SELECT @@version"
    	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $patchlevel = $reader.GetString(0) }
	$con.close()

	write-host "Pulling database count from: " $instance
	$con.open()
    	$cmd = New-Object System.Data.SqlClient.SqlCommand
    	$cmd.connection = $con
	$cmd.CommandText = "SELECT count(1) FROM sysdatabases"
	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $dbcount = $reader.GetInt32(0) }
	$con.close()

	## Reduce the total count by 4 to ignore model, master, tempdb and msdb
	if($dbcount) {
		$dbcount = $dbcount - 4
		if($dbcount -lt 0) {
			$dbcount = 0
		}
	}
	if(!$dbcount) {
		$dbcount = "Unknown"
	}
	write-host "Pulling max-memory from: " $instance
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.CommandText = "SELECT value FROM sys.configurations 
		WHERE name like '%server memory%'"
	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $maxmem = $reader.GetInt32(0) }
	$maxmem = $maxmem/1KB
	$maxmem = "{0:N0}" -f $maxmem
	$con.close()	

	write-host "Pulling Audit Level from: " $instance
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.commandText = "declare @AuditLevel int exec master..xp_instance_regread @rootkey='HKEY_LOCAL_MACHINE', @key='SOFTWARE\Microsoft\MSSQLServer\MSSQLServer', @value_name='AuditLevel', @value=@AuditLevel output select @AuditLevel"
	#write-host $cmd.commandText
 	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $audit_level = $reader.GetInt32(0) }
	$con.close()
	write-host "Audit Level for $instance is: " $audit_level
 

	write-host "Pulling default collation from: " $instance
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.CommandText = "sp_helpsort"
	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $default_collation = $reader.GetString(0) }
	$default_collation = $default_collation -replace "\,.+", ""
	Write-Host "Default collation: " $default_collation 
	$con.close()	

	write-host "Pulling DAC Access from: " $instance
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.CommandText = "select value from sys.configurations where name = 'remote admin connections'"
	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $remote_dac_enabled = $reader.GetInt32(0) }
	Write-Host "Has DAC Access: " $remote_dac_enabled 
	$con.close()	

	write-host "Checking if: " $instance " will allow updates"
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.CommandText = "select value from sys.configurations where name = 'allow updates'"
	$reader = $cmd.ExecuteReader()
	while($reader.Read()){ $has_allow_updates = $reader.GetInt32(0) }
	Write-Host "Has allow updates: " $has_allow_updates 
	$con.close()


	$con = New-Object System.Data.SqlClient.SqlConnection
	$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
	#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"

	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con

	$cmd.commandText = " `UPDATE Instances SET sid= (SELECT Servers.sid FROM Servers WHERE Servers.server_name = '$server'), instance_name='$instance', database_count='$dbcount', max_memory='$maxmem', user_running_service='$startname', default_collation='$default_collation', remote_dac_enabled='$remote_dac_enabled', has_allow_updates='$has_allow_updates', audit_level='$audit_level', last_seen='$date' 
			      	WHERE instance_name = '$instance' 
				IF @@ROWCOUNT=0
					INSERT INTO Instances (sid, instance_name, patch_level, database_count, max_memory, user_running_service, default_collation, remote_dac_enabled, has_allow_updates, audit_level, last_seen) SELECT Servers.sid, '$instance', '$patchlevel', '$dbcount', '$maxmem', '$startname', '$default_collation', '$remote_dac_enabled', '$has_allow_updates', '$audit_level', '$date' FROM Servers WHERE Servers.server_name = '$server'
			   	   ` "
	#write-host $cmd.commandtext

	write-host "----> Storing Instance: " $instance
	$catch = $cmd.ExecuteNonQuery()
	$con.close()

	#####################################
	##    End of Instance enumeration  ##
	#####################################

	#####################################
	##       Begin Login enumeration   ##
	#####################################

		##################################################
		## Clear variables from previous iteration
		##################################################

		$create_date = ""
		$modify_date = ""
		$default_database_name = ""
		$default_language_name = ""
		$has_access = ""
		$is_nt_name = ""
		$is_nt_group = ""
		$is_nt_user = ""
		$is_sysadmin = ""
		$is_securityadmin = ""
		$is_serveradmin = ""
		$is_setupadmin = ""
		$is_processadmin = ""
		$is_diskadmin = ""
		$is_dbcreator = ""
		$is_bulkadmin = ""
		$is_blank = ""
			
		###################################################
		## Done clearing variables from previous iterations
		###################################################
 
	### Connect to instance and pull back all logins
	$con = New-Object System.Data.SqlClient.SqlConnection
	$con.ConnectionString = "Server=$instance;Integrated Security=true;"
	#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
	#write-host "CONNECTION STRING IS: " $con.ConnectionString
	
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.commandText = "select * from master..syslogins order by name asc"
	write-host "Pulling logins"
	#write-host $cmd.commandText
	$DataSet = New-Object System.Data.Dataset
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $cmd
	$SqlAdapter.Fill($DataSet)
		
	$i=0
	foreach ($row in $DataSet.Tables[0].Rows) {
		$has_password_policy = ""
		#write-host "******" $i "******"
		$create_date = $row[3].ToString().Trim()
		#write-host "Create Date: " $create_date
		$modify_date = $row[4].ToString()
		#write-host "Modify Date: " $modify_date
		$loginname = $row[10].ToString().Trim()
		#write-host "Login name: " $loginname
		$default_database_name = $row[11].ToString().Trim()
		#write-host "Default database: " $default_database_name
		$default_language_name = $row[13].ToString().Trim()
		#write-host "Default language: " $default_language_name
		$has_access = $row[15].ToString().Trim()
		#write-host "Has access: " $has_access
		$is_nt_name = $row[16].ToString().Trim()
		#write-host "Is NT Name: " $is_nt_name
		$is_nt_group = $row[17].ToString().Trim()	
		#write-host "Is NT Group: " $is_nt_group
		$is_nt_user = $row[18].ToString().Trim()
		#write-host "Is NT User: " $is_nt_user
		$is_sysadmin = $row[19].ToString().Trim() 
		#write-host "Is a Sysadmin: " $is_sysadmin
		$is_securityadmin = $row[20].ToString().Trim()
		#write-host "Is Security admin: " $is_securityadmin
		$is_serveradmin = $row[21].ToString().Trim()
		#write-host "Is server admin: " $is_serveradmin
		$is_setupadmin = $row[22].ToString().Trim()
		#write-host "Is Setup admin: " $is_setupadmin
		$is_processadmin = $row[23].ToString().Trim()
		#write-host "Is process admin: " $is_processadmin
		$is_diskadmin = $row[24].ToString().Trim()
		#write-host "Is disk admin: " $is_diskadmin
		$is_dbcreator = $row[25].ToString().Trim()
		#write-host "Is DB Creator: " $is_dbcreator
		$is_bulkadmin = $row[26].ToString().Trim()
		#write-host "Is Bulk admin: " $is_bulkadmin
		
		if($create_date) {	
			try {
				$cmd.commandText = "select name from sys.sql_logins WHERE name = '$loginname' AND PWDCOMPARE('', password_hash) = 1"
				write-host "Blank password command: " $cmd.commandText
				$reader = $cmd.ExecuteReader()
				#write-host "IM HEEEEEEEEEEEEEEEEEEEEEEEEEEERE!"
				while($reader.Read()) { $is_blank = $reader.GetString(0) }
				if($is_blank) {
					$is_blank = 1
				}
				else {
					$is_blank = 0
				}
			}
			catch {
				write-host "I'm in the catch, is it SQL 2000? (Won't work!)"
			}
			$con.close()
			write-host "Password blank for" $loginname ":" $is_blank
			write-host "-----------------------------"
			$i = $i + 1

			## Check if password policy is enabled for login
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$cmd.commandText = "select is_policy_checked from master.sys.sql_logins where name = '$loginname'"
			write-host $cmd.commandText
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $has_password_policy = $reader.GetInt32(0) }
			write-host "Login: " $loginname " password policy value: " $has_password_policy
			$con.close()
			

			## Pull back iid of instance
			$con = New-Object System.Data.SqlClient.SqlConnection
			$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
			#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$iid = "";
			$cmd.commandText = "SELECT iid from Instances where instance_name = '$instance'"
			#write-host "Pulling iid: " $cmd.commandText
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $iid = $reader.GetInt32(0) }
			#write-host "-------------------> IID is: " $iid
			$con.close()

			## Pull back the lid of the login if it's already in the system
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$lid = "";
			$cmd.commandText = "SELECT lid from Logins WHERE iid = '$iid' and loginname = '$loginname'"
			#write-host "Pulling lid: " $cmd.commandText
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $lid = $reader.GetInt32(0) }
			#write-host "-------------------> LID is: " $lid
			$con.close()

			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con 	 

			$cmd.commandText = " `UPDATE Logins SET iid='$iid', loginname='$loginname', realname='$realname', databases='$databases', create_date='$create_date', modify_date='$modify_date', default_database_name='$default_database_name', default_language_name='$default_language_name', has_access='$has_access', is_nt_name='$is_nt_name', is_nt_group='$is_nt_group', is_nt_user='$is_nt_user', is_sysadmin='$is_sysadmin', is_securityadmin='$is_securityadmin', is_serveradmin='$is_serveradmin', is_setupadmin='$is_setupadmin', is_processadmin='$is_processadmin', is_diskadmin='$is_diskadmin', is_dbcreator='$is_dbcreator', is_bulkadmin='$is_bulkadmin', blank_password='$is_blank',  last_seen='$date'
      						WHERE lid = '$lid'
						IF @@ROWCOUNT=0
							INSERT INTO Logins VALUES ('$iid', '$loginname', '$realname', '$databases', '$create_date', '$modify_date', '$default_database_name', '$default_language_name', '$has_access', '$is_nt_name', '$is_nt_group', '$is_nt_user', '$is_sysadmin', '$is_securityadmin', '$is_serveradmin', '$is_setupadmin', '$is_processadmin', '$is_diskadmin', '$is_dbcreator', '$is_bulkadmin', '$is_blank', '$date')
				     ` "

		
			#write-Host "DATABASE INJEEEEEEEEEECTIIIIIIOOOOOOON: " $cmd.commandtext
			#write-host $cmd.commandtext
			write-host "----> Storing Login: " $loginname
			#$cmd.ExecuteNonQuery()
			$catch = $cmd.ExecuteNonQuery() 
		}
		$con.close()
	}
		

	##########################################
	##         End of Login enumeration     ##
	########################################## 

	##########################################
	##       Begin database enumeration     ##
	##########################################

	# Create an SMO connection to the instance
	$s = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "$instance"
	$dbs = $s.Databases
	ForEach ($db in $dbs) {

		$cleaned_db = $db -replace "\[","" 
		$cleaned_db = $cleaned_db -replace "\]",""
		$backup_type = ""
		
		## Clean up $pot_users and $usermail so they don't land in bad databases
		$pot_users = ""
		$usermail = ""

		$dbname = $db.Name

		if($dbname -notlike "master" -and $dbname -notlike "model" -and $dbname -notlike "msdb" -and $dbname -notlike "tempdb") {

			write-host "Working on database: " $dbname
			$san_bkup_check = ""
			$local_bkup_check = ""
			$backup_type = ""
			### Connect to database and determine backup type (Either SAN or Local Server)
			$con = New-Object System.Data.SqlClient.SqlConnection
			$con.ConnectionString = "Server=$instance;Integrated Security=true;"
			#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
			#write-host "CONNECTION STRING IS: " $con.ConnectionString

			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$cmd.commandText = "select top 10 m.physical_device_name FROM msdb.dbo.backupset s INNER JOIN msdb.dbo.backupmediafamily m ON s.media_set_id = m.media_set_id WHERE s.database_name = '$cleaned_db' and s.type = 'D' and m.physical_device_name like '(local%' and s.backup_finish_date > DATEADD(dd, -7, GETDATE()) order by backup_finish_date desc" 
			write-host "Pulling backup type: " $cmd.commandText
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $san_bkup_check = $reader.GetString(0) }
			$con.close()
			$con.open()
			$cmd.commandText = "select top 10 m.physical_device_name FROM msdb.dbo.backupset s INNER JOIN msdb.dbo.backupmediafamily m ON s.media_set_id = m.media_set_id WHERE s.database_name = '$cleaned_db' and s.type = 'D' and m.physical_device_name not like '(local%' and s.backup_finish_date > DATEADD(dd, -7, GETDATE()) order by backup_finish_date desc"
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $local_bkup_check = $reader.GetString(0) }
			$con.close()	
			write-host "SAN OUT: " $san_bkup_check
			write-host "LOCAL OUT: " $local_bkup_check					
			
			if(($san_bkup_check) -and ($local_bkup_check)) {
				write-host "Seems to have both SAN and Local backup!  DOUBLE DIPPED!"
				$backup_type = "SAN and LOCAL"
			}
			elseif(($san_bkup_check) -and (!$local_bkup_check)) {
				write-host "Seems to be SAN backup."
				$backup_type = "SAN"
			}
			elseif((!$san_bkup_check) -and ($local_bkup_check)) {
				write-host "Seems to be local backup."
				$backup_type = "LOCAL"
			}
			else { 
				write-host "NO BACKUP DETECTED!"
				$backup_type = "NONE"
			}
			write-host "BACKUP TYPE is: " $backup_type
			
		
			$status = $db.Status
			#Write-Host "Status is: " $status		

			#Divide the value of SpaceAvailable by 1KB 
			$dbSpaceAvailable = $db.SpaceAvailable/1KB 
			write-host "************************ RAW SPACE AVAILABLE: " $dbSpaceAvailable

			#Format the results to a number with three decimal places 
			$dbSpaceAvailable = "{0:f2}" -f $dbSpaceAvailable 
			Write-Host "************************ Space available: " $dbSpaceAvailable

			write-host "************************ RAW DB SIZE: " $db.Size
			#$dbSize = $db.Size/1KB
			$dbSize = "{0:f2}" -f $db.Size
			Write-Host "************************ Database size: " $dbsize

			if($db.Version -eq "515") {
				$Version = "SQL Server 7.0"
			}
			if($db.Version -eq "539") {
       				$Version = "SQL Server 2000"
			}
			if(($db.Version -eq "611") -or ($db.Version -eq "612")) {
       				$Version = "SQL Server 2005"
			}
			if($db.Version -eq "655") {
				$Version = "SQL Server 2008"
			}
			if(($db.Version -eq "660") -or ($db.Version -eq "661")) {
       				$Version = "SQL Server 2008 R2"
			} 

			write-host "Database version: " $Version
			write-host "HEY HEY HEY HEY HEY Database owner: " $db.Owner

			#############################
			## Begin User enumeration ##
			#############################

			try { 
				$dbUsers = $db.Users
				write-host $db.Users
				foreach ($user in $dbusers) {

					$user = $user -replace "\[","" 
					$user = $user -replace "\]",""
					$cleaned_user = $user
					$cleaned_user = $cleaned_user -replace "CORPASH\\",""
					write-host "User is: " $user
					if($user -notlike "dbo") { ## Ignore DBO user
						$realname = cscript ./id_enumerator.vbs $cleaned_user //Nologo
						#write-host "Real name is: " $realname
						
						$con = New-Object System.Data.SqlClient.SqlConnection
						$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
						#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
						
						## Pull back did of dbname
						$con.open()
						$cmd = New-Object System.Data.SqlClient.SqlCommand
						$cmd.connection = $con
						$did = "";
						$cmd.commandText = "SELECT d.did from Databases d inner join Instances i on d.iid = i.iid WHERE d.db_name = '$dbName' and i.instance_name = '$instance'"
						#write-host "Pulling did: " $cmd.commandText
						$reader = $cmd.ExecuteReader()
						while($reader.Read()) { $did = $reader.GetInt32(0) }
						#write-host "-------------------> DID is: " $did
						$con.close()

						## Pull back uid to see if it's already in system
						$con.open()
						$cmd = New-Object System.Data.SqlClient.SqlCommand
						$cmd.connection = $con
						$lid = "";
						$cmd.commandText = "SELECT uid from Users WHERE did = '$did' and username = '$user'"
						#write-host "Pulling lid: " $cmd.commandText
						$reader = $cmd.ExecuteReader()
						while($reader.Read()) { $uid = $reader.GetInt32(0) }
						#write-host "-------------------> UID is: " $uid
						$con.close()

						## Pull back iid of instance
						$con.open()
						$cmd = New-Object System.Data.SqlClient.SqlCommand
						$cmd.connection = $con
						$iid = "";
						$cmd.commandText = "SELECT iid from Instances where instance_name = '$instance'"
						#write-host "Pulling iid: " $cmd.commandText
						$reader = $cmd.ExecuteReader()
						while($reader.Read()) { $iid = $reader.GetInt32(0) }
						#write-host "-------------------> IID is: " $iid
						$con.close()

						## Pull back the lid of the matching login if it has one
						$con.open()
						$cmd = New-Object System.Data.SqlClient.SqlCommand
						$cmd.connection = $con
						$lid = "";
						$cmd.commandText = "SELECT lid from Logins WHERE iid = '$iid' and loginname = '$user'"
						#write-host "Pulling lid: " $cmd.commandText
						$reader = $cmd.ExecuteReader()
						while($reader.Read()) { $lid = $reader.GetInt32(0) }
						#write-host "-------------------> LID is: " $lid
						$con.close()

																
						$con.open()
						$cmd = New-Object System.Data.SqlClient.SqlCommand
						$cmd.connection = $con 	 

			
						$cmd.commandText = " `UPDATE Users SET did='$did', username='$user', lid='$lid', default_schema='$default_schema', owned_schemas='$owned_schemas', role_members='$role_members', last_seen='$date'
			      						WHERE uid = '$uid'
									IF @@ROWCOUNT=0
										INSERT INTO Users VALUES ('$did', '$user', '$lid', '$default_schema', '$owned_schemas', '$role_members', '$date')
								     ` "

						#write-Host "DATABASE INJEEEEEEEEEECTIIIIIIOOOOOOON: " $cmd.commandtext
						#write-host $cmd.commandtext
						write-host "----> Storing User: " $user
						#$cmd.ExecuteNonQuery()
						$catch = $cmd.ExecuteNonQuery() 
						$con.close()
					}
				}
			}
		
			catch {
				write-host "Couldn't get users."
				
			}

			###############################
			##    End user enumeration   ##
			############################### 

			$con = New-Object System.Data.SqlClient.SqlConnection
			$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
			#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"

			## Pull back the did of the database if it's already in the system
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$did = "";
			$cmd.commandText = "SELECT d.did from Databases d inner join Instances i on d.iid = i.iid WHERE d.db_name = '$dbName' and i.instance_name = '$instance'"
			#write-host "Pulling Did: " $cmd.commandText
			$reader = $cmd.ExecuteReader()
			while($reader.Read()) { $did = $reader.GetInt32(0) }
			#write-host "-------------------> DID is: " $did
			$con.close()

			

			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con 	 

			
			try {
				
				$cmd.commandText = " `UPDATE Databases SET iid= (SELECT Instances.iid FROM Instances WHERE Instances.instance_name = '$instance'), db_name='$dbName', status='$status', collation='" + $db.Collation + "', sql_database_owner='" + $db.Owner + "', compatibility_level='" + $db.CompatibilityLevel + "', autoshrink='" + $db.AutoShrink + "', recovery_model='" + $db.RecoveryModel + "', size='$dbSize', space_available='$dbSpaceAvailable', backup_type='$backup_type', last_backup='" + $db.LastBackupDate + "', users='" + $db.Users + "', potential_owners='$pot_users', potential_emails='$usermail', dbrs_version = '0', version='$Version', last_seen='$date'
			      				WHERE did = '$did' 
							IF @@ROWCOUNT=0
								INSERT INTO Databases (iid, db_name, status, collation, sql_database_owner, compatibility_level, autoshrink, recovery_model, size, space_available, backup_type, last_backup, users, potential_owners, potential_emails, dbrs_version, version, last_seen) 
								SELECT Instances.iid, '" + $db.Name + "','" + $status + "','" + $db.Collation + "','" + $db.Owner + "','" + $db.CompatibilityLevel + "','" + $db.AutoShrink + "','" + $db.RecoveryModel + "','" + $dbSize + "','" + $dbSpaceAvailable + "','" + $backup_type + "','" + $db.LastBackupDate + "','" + $db.Users + "','" + $pot_users + "','" + $usermail + "','0','" + $Version + "','" + $date + "' FROM Instances WHERE Instances.instance_name = '$instance'
			   	   ` "

				#write-Host "DATABASE INJEEEEEEEEEECTIIIIIIOOOOOOON: " $cmd.commandtext
			}

			catch {	

				$cmd.commandText = " `UPDATE Databases SET iid= (SELECT Instances.iid FROM Instances WHERE Instances.instance_name = '$instance'), db_name='$dbName', status='$status', collation='" + $db.Collation + "', sql_database_owner='" + $db.Owner + "', compatibility_level='" + $db.CompatibilityLevel + "', autoshrink='" + $db.AutoShrink + "', recovery_model='" + $db.RecoveryModel + "', size='$dbSize', space_available='$dbSpaceAvailable', backup_type='$backup_type', last_backup='" + $db.LastBackupDate + "', users='ACCESS DENIED', potential_owners='$pot_users', potential_emails='$usermail', dbrs_version = '0', version='$Version', last_seen='$date'
			      				WHERE did = '$did' 
							IF @@ROWCOUNT=0
								INSERT INTO Databases (iid, db_name, status, collation, sql_database_owner, compatibility_level, autoshrink, recovery_model, size, space_available, backup_type, last_backup, users, potential_owners, potential_emails, dbrs_version, version, last_seen) 
								SELECT Instances.iid, '" + $db.Name + "','" + $status + "','" + $db.Collation + "','" + $db.Owner + "','" + $db.CompatibilityLevel + "','" + $db.AutoShrink + "','" + $db.RecoveryModel + "','" + $dbSize + "','" + $dbSpaceAvailable + "','" + $backup_type + "','" + $db.LastBackupDate + "','ACCESS DENIED','" + $pot_users + "','" + $usermail + "','0','" + $Version + "','" + $date + "' FROM Instances WHERE Instances.instance_name = '$instance'
			   	   ` "				

				#Write-Host "Catch: " $cmd.commandtext
			}

			finally { 
				#write-host $cmd.commandtext
				write-host "----> Storing Database: " $dbname
				$catch = $cmd.ExecuteNonQuery() 
			}
			$con.close()
		}
	}
}

#############################
## End of DoStuff function ##
#############################

#############################
###   MAIN FUNCTION BODY  ###
#############################

foreach($computer in $array) {

	$audit_value = ""
	$maxmem = ""
	$patchlevel = ""
	$dbcount = ""
	$diskinfo = ""
	$environment = ""
	$startname = ""
	$os_version = ""
	$IPAddress = ""
	$proc_name = ""
	$max_clock = ""
	$cores = ""
	$logi_proc = ""
	$is_blank = ""
	$diskid = ""
	$disksize = ""
	$usedspace = ""
	$freespace = ""
	$diskinfo = ""
	$displayGB = ""
	$phy_memory = ""
	$model = ""
	$domain = ""
	$server_status = ""
	$default_collation = ""
	$already_added = ""
	$has_allow_access = ""
	$has_allow_updates = ""
	$date = Get-Date -format M/d/yyyy
		

	## Try Ashland network first
	$server = "$computer.$corpdomain"
	write-host ""
	write-host ""
	write-host "----------------------------------------------"
	write-host "Pulling services from " $server
	$instances = Get-WmiObject -ComputerName $server win32_service | where {$_.name -like "MSSQL*"}
		
	if($?) {
		$server = "$computer.$corpdomain"
	}
	if(!$?) {
		Write-Host $server "did not respond on any network. Recording and skipping.."
		$con = New-Object System.Data.SqlClient.SqlConnection
		$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
		#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"

		## Here we want to see if we've successfully enumerated the server in the past.  If so
		## we increment its downtime by 1 so we can keep track how long its been offline.
		## If it gets older than the time given in $too_old, then we delete it. 
		$con.open()
		$cmd = New-Object System.Data.SqlClient.SqlCommand
		$cmd.connection = $con
		$cmd.commandText = "SELECT downtime_in_days FROM Servers WHERE server_name like '$computer%'"
		write-host "FAILED SERVER, checking servers table to see if it's in there"
		$reader = $cmd.ExecuteReader()
		while($reader.Read()) {
			$downtime = $reader.GetString(0)
		}
		$con.close()
		if(($downtime) -and ($downtime -le $too_old)) {
			write-host "Server is in table and not too old"
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$cmd.commandtext = "UPDATE Servers SET downtime_in_days = downtime_in_days + 1 WHERE server_name like '$computer%'"
			$catch = $cmd.ExecuteNonQuery()
			$con.close()
			continue				
		}
		elseif(($downtime) -and ($downtime -gt $too_old)) {
			write-host "Deleting old server: " $server
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$cmd.commandtext = " `delete Databases from Databases d inner join Instances i on d.iid = i.iid inner join Servers s on i.sid = s.sid where s.server_name like '$computer%' 
      			      		delete Instances from Instances i inner join Servers s on i.sid = s.sid where s.server_name like '$computer%'
      	   		      		delete from Servers where server_name like '$computer%'
   			   		` " 
			$catch = $cmd.ExecuteNonQuery()
			$con.close()
			continue
		}
		else { ## At this point, we should have never connected to the server in question, so we'll
     		       			## add it to the noaccess table.
			write-host "Server is not in servers table, so added to no access"
			$con.open()
			$cmd = New-Object System.Data.SqlClient.SqlCommand
			$cmd.connection = $con
			$cmd.commandtext = "DELETE FROM NoAccess WHERE server_name = '$computer'"
			$cmd.ExecuteNonQuery()
			$cmd.commandtext = "INSERT INTO NoAccess (server_name) VALUES ('$computer')"
			#write-host $cmd.commandtext
			$cmd.ExecuteNonQuery()
			#$catch = $cmd.ExecuteNonQuery()
			$con.close()
			continue
		}
	}
}


	#############################################
	##  Begin enumeration of the actual server ##
	#############################################


	$colItems = Get-WmiObject -ComputerName $server win32_service
	foreach ($objItem in $colItems) {
		$startname = $objItem.StartName
	}
	write-host "Start name: " $startname
	write-host "Getting IP address for: " $server
	$Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $server| ? {$_.IPEnabled}

	foreach ($Network in $Networks) {
		$IPAddress  = $Network.IpAddress[0]
		$SubnetMask  = $Network.IPSubnet[0]
		$DefaultGateway = $Network.DefaultIPGateway
		$DNSServers  = $Network.DNSServerSearchOrder
		$IsDHCPEnabled = $false
		If($network.DHCPEnabled) {
			$IsDHCPEnabled = $true
		}
		$MACAddress  = $Network.MACAddress
	}
	write-host "IP Address: " $IPAddress

	$colItems = Get-WmiObject -ComputerName $server win32_ComputerSystem -Property NumberofProcessors | select-object -property NumberofProcessors
	foreach ($objItem in $colItems) {
		$sockets = $objItem.NumberofProcessors
	}
	
	$colItems = Get-WmiObject -ComputerName $server win32_ComputerSystem -property NumberofLogicalProcessors | select-object -property NumberofLogicalProcessors
	foreach ($objItem in $colItems) { $cores = $objItem.NumberofLogicalProcessors }
	
	if(!$cores) {
		$cores = $sockets
	}
	
	write-host "Sockets: " $sockets
	Write-host "Cores: " $cores
	
	$property = "name", "maxclockspeed"

	$colItems = Get-WmiObject -ComputerName $server win32_processor -Property  $property | Select-Object -Property $property
	
	foreach ($objItem in $colItems) {
		$proc_name = $objItem.name
		$max_clock = $objItem.maxclockspeed
	}
	
	write-host "Name: " $proc_name
	write-host "Max Clock Speed: " $max_clock
	

	$colItems = Get-WmiObject -Class Win32_logicaldisk -filter "drivetype=3" -computer $server 
	foreach ($objItem in $colItems) {
		$diskid = $objItem.DeviceID
		$disksize = $objItem.Size/1GB -as [int]
		$usedspace = "{0:N2}" -f (($objItem.Size - $objItem.Freespace)/1GB)
		$freespace = "{0:N2}" -f ($objItem.FreeSpace/1GB)
		$diskinfo = $diskinfo + "Drive " + $diskid + " Size " + $disksize + "GB Used " + $usedspace + "GB Free " + $freespace + "GB | "
	}
	write-host $diskinfo

	$colItems = get-wmiobject -class "Win32_ComputerSystem" -namespace "root\CIMV2" -computername $server
	foreach ($objItem in $colItems){
		$displayGB = [math]::round($objItem.TotalPhysicalMemory/1024/1024/1024, 0)
		$phy_memory = $displayGB, "GB"
		$model = $objItem.model
		$domain = $objItem.domain
		$server_status = $objItem.status
		
		write-host "Total Physical Memory: " $phy_memory
		write-host "Model: " $model
		write-host "Domain: " $domain
		write-host "Status: " $server_status
		
	}
	
	#write-host "Getting Operating System for: " $server
	$os_version = gwmi -Class Win32_OperatingSystem -Computer $server | select Name
	$os_version = $os_version -replace "\|.+",""
	$os_version = $os_version -replace ".+\=",""
	write-host "Operating System: " $os_version

	#############################################
	##         End enumeration of server       ##
	#############################################

	## At this point we know the server is live and we insert it into the Servers table with attributes
	$con = New-Object System.Data.SqlClient.SqlConnection
	$con.ConnectionString = "Server=$db_summary_db;Integrated Security=true;"
	#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
	
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.commandText = "DELETE from NoAccess WHERE server_name = '$computer'"
	$catch = $cmd.ExecuteNonQuery()
	$con.close()
	
		
	## Now insert it into the Servers table
	$con.open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand
	$cmd.connection = $con
	$cmd.commandText = " `UPDATE Servers SET server_name='$server', ip_address='$IPAddress', operating_system='$os_version', physical_mem='$phy_memory', model='$model', domain='$domain', proc_name='$proc_name', max_clock_speed='$max_clock', environment='$environment', num_cores='$cores', num_sockets='$sockets', logical_disks='$diskinfo', status='$server_status', downtime_in_days='0', last_seen='$date' 
			      	WHERE server_name = '$server' 
				IF @@ROWCOUNT=0
					INSERT INTO Servers (server_name, ip_address, operating_system, physical_mem, model, domain, proc_name, max_clock_speed, environment, num_cores, num_sockets, logical_disks, status, downtime_in_days, last_seen) VALUES ('$server','"  + $IPAddress + "','" + $os_version + "','" + $phy_memory + "','" + $model + "','" + $domain + "','" + $proc_name + "','" + $max_clock + "','" + $environment + "','" + $cores + "','" + $sockets + "','" + $diskinfo + "','" + $server_status + "','0','" + $date + "')
			   ` "
	#write-host "HOLY CRAP COMMAND: " $cmd.commandText
	#$cmd.commandtext = "INSERT INTO Servers (server_name, ip_address, operating_system, physical_mem, model, domain, proc_name, max_clock_speed, environment, num_cores, num_sockets, logical_disks, status, downtime_in_days, last_seen) VALUES ('$server','"  + $IPAddress + "','" + $os_version + "','" + $phy_memory + "','" + $model + "','" + $domain + "','" + $proc_name + "','" + $max_clock + "','" + $environment + "','" + $cores + "','" + $sockets + "','" + $diskinfo + "','" + $server_status + "','0','" + $date + "')"
	
	Write-Host "----> Storing server: " $server
	#$catch = $cmd.ExecuteNonQuery()
	$cmd.ExecuteNonQuery()
	$con.close()

	foreach ($name in $instances) {
		write-host "FOUND INSTANCE: " $name
		if($name.name -like "*##*") {
			continue
		}
		if($name.name -eq "MSSQLSERVER") {
			write-host "Found default instance of: " $name
			$server = $server -replace "\\.+",""
			$instance = $server
			write-host "Server is: " $server
			Write-host "Instances is: " $instance
			DoStuff
		}
		if($name.name -like "MSSQL$*") {
			write-host "Found instance: " $name
			$instance = $server -replace "\\.+",""
			$name.name = $name.name.Replace("MSSQL$", "")
			$instance = "$server\" + $name.name
			write-host "Server is: " $server
			write-host "Instance is: " $instance
			DoStuff
		}
	}
}
