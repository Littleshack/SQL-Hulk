$outfile = "C:\SQL_Website\monitor.htm"

while(1) {

#Create a sqlconnection object
$today = Get-Date -format M/d/yyyy
$yesterday = (get-date).AddDays(-1)
$yesterday = $yesterday.ToString("M/d/yyyy")

$con = New-Object System.Data.SqlClient.SqlConnection
$con.ConnectionString = "Server=nakylexsql105.ashland.ad.ai;Database=DB_Summary;Integrated Security=true;"
#$con.ConnectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"
$con.open()
$cmd = New-Object System.Data.SqlClient.SqlCommand
$cmd.connection = $con
$cmd.CommandText = "SELECT s.server_name, i.instance_name from Servers s inner join Instances i on s.sid = i.sid WHERE (s.last_seen = '$today' or s.last_seen = '$yesterday') and i.patch_level not like '%2000%' order by server_name asc"
write-host $cmd.CommandText
$DataSet = New-Object System.Data.Dataset
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
$SqlAdapter.SelectCommand = $cmd
$SqlAdapter.Fill($DataSet)
$con.close()

$i = 0
$site = @("yes","no","maybe")

foreach ($row in $DataSet.Tables[0].Rows) {

	$blocking = ""
	$server = $row[0].ToString().Trim()
	$instance = $row[1].ToString().Trim()
	#$instance = "nakylexeis501.ashland.ad.ai"

	write-host "Server: " $server "Instance: " $instance
	try {
		$con = New-Object System.Data.SqlClient.SqlConnection
		$con.ConnectionString = "Server=$instance;Database=master;Integrated Security=true;"
		#$con.ConnectionString = "Server=nakylexeis501.ashland.ad.ai;Database=master;Integrated Security=true;"
		$con.open()
		$cmd = New-Object System.Data.SqlClient.SqlCommand
		$cmd.connection = $con
		$cmd.CommandText = "select * from sys.dm_exec_requests where blocking_session_id <> 0"
		write-host $cmd.commandtext
		$BlockingSet = New-Object System.Data.Dataset
		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$SqlAdapter.SelectCommand = $cmd
		$SqlAdapter.Fill($BlockingSet)
		$con.close()
		if($BlockingSet) {
			foreach ($blocking_line in $BlockingSet.Tables[0].Rows) {
				$blocked_spid = $blocking_line[0].ToString().Trim()
				$request_id = $blocking_line[1].ToString().Trim()
				$start_time = $blocking_line[2].ToString().Trim()
				$status = $blocking_line[3].ToString().Trim()
				$command_type = $blocking_line[4].ToString().Trim()
				$blocking_spid = $blocking_line[12].ToString().Trim()
				$wait_time = $blocking_line[14].ToString().Trim()

				$con.open()
				$cmd = New-Object System.Data.SqlClient.SqlCommand
				$cmd.connection = $con
				$cmd.CommandText = "select * from sys.sysprocesses where spid = $blocking_spid"
				write-host $cmd.commandtext
				$BlockerSet = New-Object System.Data.Dataset
				$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
				$SqlAdapter.SelectCommand = $cmd
				$SqlAdapter.Fill($BlockerSet)
				$con.close()
				foreach ($blocker_line in $BlockerSet.Tables[0].Rows) {
					$blocker_hostname = $blocker_line[18]
					$blocker_program = $blocker_line[19]
					$blocker_login = $blocker_line[26]
				}
				$con.open()
				$cmd = New-Object System.Data.SqlClient.SqlCommand
				$cmd.connection = $con
				$cmd.CommandText = "dbcc inputbuffer ($blocking_spid)"
				write-host $cmd.commandtext
				$BlockerQuerySet = New-Object System.Data.Dataset
				$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
				$SqlAdapter.SelectCommand = $cmd
				$SqlAdapter.Fill($BlockerQuerySet)
				$con.close()
				foreach ($blocker_query in $BlockerQuerySet.Tables[0].Rows) {
					$query = $blocker_query[2]
				}
				$wait_time = ($wait_time / 1000) / 60
				$wait_time = "{0:f2}" -f $wait_time
				$current_time = get-date

				##Build the webpage!!!

				write-host "HEY!!!" $i

				"<html><head><meta http-equiv=refresh content=60></head><title>SQL Monitoring Site</title><body><center>" > $outfile
"<table border=1><tr align=center><td colspan=13>Last Updated: $current_time</td></tr>" >> $outfile
"<tr align=center><td>Instance</td><td>blocked_spid</td><td>request_id</td><td>start_time</td><td>status</td><td>command_type</td><td>blocking_spid</td><td>wait_time</td><td>blocker_hostname</td><td>blocker_program</td><td>blocker_login</td><td>query</td><td>Time Stamp</tr>" >> $outfile
				
				$site[$i] = "<tr align=center>"
				write-host "Site: " $site
				$i = $i + 1
				write-host $i
				$site[$i] = "<td>$instance</td><td>$blocked_spid</td><td>$request_id</td><td>$start_time</td><td>$status</td><td>$command_type</td><td>$blocking_spid</td><td>$wait_time</td><td>$blocker_hostname</td><td>$blocker_program</td><td>$blocker_login</td><td>$query</td><td>$current_time</td></tr>"
				write-host $site[$i]
				$i = $i + 1
				write-host "YO YO" $i
				
				write-host "Site stuff: " $site
				$site >> $outfile
			}
		}
	}
	catch {
		#write-host "Unable to connect."
	}
}


Start-Sleep -s 1
} 
