<html>
<head>
<title>FwConfigParser</title>
</head>
<body>
<?php

// Author: Jon Spriggs
// e-mail: jon@spriggs.org.uk
// Date: 2007-07-20
// Licence: This code is released under the GNU General Public Licence, version 3

$filename="process.txt";
$lines=file($filename);
$rule=0;

foreach($lines as $line_num=>$line) {
  $line=trim($line);
  $arr=explode(' ', trim($line));
  switch(strtolower(trim($arr[0]))) {
    case 'name':
      $endpoint[trim($arr[2])]=trim($arr[1]);
    break;
    case 'object-group':
      $group['name']=trim($arr[2]);
    break;
    case 'network-object':
      if(strtolower(trim($arr[1]))=='host') {
        $endpoint[$group['name']][]=trim($arr[2]);
        $endpoint[trim($arr[2])]=$group['name'];
      } elseif($arr[2]=='255.255.255.255') {
        $endpoint[$group['name']][]=trim($arr[1]);
        $endpoint[trim($arr[1])]=$group['name'];
      } else {
        $endpoint[$group['name']][]=getHostRange($arr[1],$arr[2]);
      }
    break;
    case 'port-object':
      if(strtolower(trim($arr[1]))=='eq') {
        $portpoint[$group['name']][]=trim($arr[2]);
        $portpoint[trim($arr[2])][]=$group['name'];
      } elseif(strtolower(trim($arr[1]))=='range') {
        if(is_numeric(trim($arr[2])) AND is_numeric(trim($arr[3]))) {
          for($port=trim($arr[2]); $port<=trim($arr[3]); $port++) {
            $portpoint[$group['name']][]=$port;
            $portpoint[$port][]=$group['name'];
          }
        } else {
          for($port=2; trim($arr[$port])!=''; $port++) {
            $portpoint[$group['name']][]=trim($arr[$port]);
            $portpoint[trim($arr[$port])][]=$group['name'];
          }
        }
      }
    break;
    case 'access-list':
      $next=0;
      if(trim($arr[1])!='compiled') {
        $rule++;
        $ruleline[$rule]=trim($line);
        $interface[$rule]=trim($arr[1]);
        $isPermitted[$rule]=trim($arr[2]);
        $protoType[$rule]=trim($arr[3]);
        if(trim($arr[4])=='host') {
          $fromobj[$rule]='host';
          $fromhost[$rule]=trim($arr[5]);
        } elseif (trim($arr[5])=='255.255.255.0') {
          $fromobj[$rule]='host';
          $fromhost[$rule]=trim($arr[4]);
        } elseif (trim($arr[4])=='object-group') {
          $fromobj[$rule]='object';
          $fromhost[$rule]=trim($arr[5]);
        } elseif (trim($arr[4])=='any') {
          $fromobj[$rule]='host';
          $fromhost[$rule]='Any Host';
          $next--;
        } else {
          $fromobj[$rule]='host';
          $fromhost[$rule]=getHostRange($arr[4], $arr[5]);
        }
        if(trim($arr[6+$next])=='host') {
          $toobj[$rule]='host';
          $tohost[$rule]=trim($arr[7+$next]);
        } elseif (trim($arr[7+$next])=='255.255.255.255') {
          $toobj[$rule]='host';
          $tohost[$rule]=trim($arr[6+$next]);
        } elseif (trim($arr[6+$next])=='object-group') {
          $toobj[$rule]='object';
          $tohost[$rule]=trim($arr[7+$next]);
        } elseif (trim($arr[5+$next])=='any') {
          $toobj[$rule]='host';
          $tohost[$rule]='Any Host';
          $next--;
        } else {
          $toobj[$rule]='host';
          $tohost[$rule]=getHostRange($arr[6+$next], $arr[7+$next]);
        }
        if($arr[3]=='icmp') {
          $portobj[$rule]='port';
          $porttxt[$rule]='Any ICMP';
        } elseif(strtolower(trim($arr[8+$next]))=='eq') {
          $portobj[$rule]='port';
          $porttxt[$rule]=trim($arr[9+$next]);
        } elseif(strtolower(trim($arr[8+$next]))=='range') {
          $portobj[$rule]='port';
          if(is_numeric(trim($arr[9+$next])) AND is_numeric(trim($arr[10+$next]))) {
            for($port=trim($arr[9+$next]); $port<=trim($arr[10+$next]); $port++) {
              $porttxt[$rule][]=$port;
            }
          } else {
            for($port=9+$next; isset($arr[$port]); $port++) {
              $porttxt[$rule][]=trim($arr[$port]);
            }
          }
        } elseif(strtolower(trim($arr[8+$next]))=='object-group') {
          $portobj[$rule]='object';
          $porttxt[$rule]=trim($arr[9+$next]);
        }
      }
    break;
    case 'route':
      $routeno++;
      $route[$routeno]['interface']=trim($arr[1]);
      $route[$routeno]['network']=trim($arr[2]);
      $route[$routeno]['netmask']=trim($arr[3]);
      $route[$routeno]['gateway']=trim($arr[4]);
      $route[$routeno]['metric']=trim($arr[5]);
    break;
    case 'nameif':
      $if=trim($arr[1]);
      $ifname=trim($arr[2]);
      $interface[$if]['name']=$ifname;
      $interface[$ifname]['if']=$if;
      $interface[$if]['security']=trim($arr[3]);
    break;
    case 'interface':
      $if=trim($arr[1]);
      $interface[$if]['speed']=trim($arr[2]);
      if(trim($arr[3])=='shutdown') {$interface[$if]['down']=TRUE;}
    break;
    case 'mtu':
      $if=trim($arr[1]);
      $interface[$if]['mtu']=trim($arr[2]);
    break;
    case 'ip':
      if(strtolower(trim($arr[1]))=='address') {
        $if=trim($arr[2]);
        $interface[$if]['addr']=trim($arr[3]);
        $interface[$if]['mask']=trim($arr[4]);
      }
    break;
    case 'global':
      $pool=trim($arr[2]);
      $natpool[$pool]['interface']=trim($arr[1]);
      $natpool[$pool]['ip']=trim($arr[3]);
      $natpool[$pool]['mask']=trim($arr[5]);
    break;
    case 'nat':
      $natno++;
      $nat[$natno]['line']=$line;
      $nat[$natno]['isstatic']=FALSE;
      $nat[$natno]['insidelan']=trim($arr[1]);
      $nat[$natno]['outsidelan']=trim($arr[2]);
      $nat[$natno]['outsideip']=trim($arr[2]);
      if(strtolower(trim($arr[3]))=='access-list') {
        $nat[$natno]['insideip']='object';
        $nat[$natno]['insideobj']=trim($arr[4]);
      } else {
        $nat[$natno]['insideip']=getHostRange($arr[3], $arr[4]);
      }
    break;
    case 'alias':
    break;
    case 'static':
      $natno++;
      list($if1,$if2)=explode(",",substr(trim($arr[1]),1,strlen($arr[1])-2));
      $nat[$natno]['line']=$line;
      $nat[$natno]['isstatic']=TRUE;
      $nat[$natno]['insidelan']=$if1;
      $nat[$natno]['outsidelan']=$if2;
      $nat[$natno]['outsideip']=trim($arr[2]);
      $nat[$natno]['insideip']=getHostRange($arr[3], $arr[5]);
    break;
  }
}

$maxrule=$rule;
if($maxrule>0) {
  echo "<table width=100% border=1>\n";
  echo "<tr><th>Rule</th><th>Permit?</th><th>From</th><th>To</th><th>Proto</th><th>Access List</th></tr>\n";
  for($rule=1; $rule<=$maxrule; $rule++) {
    if($colour=="#8888e7") {$colour="#3bffa0";} else {$colour="#8888e7";}
    echo "<tr bgcolor='$colour'>\n";
    echo "<td>$rule</td>\n";
    echo "<td>{$isPermitted[$rule]}</td>\n";
    echo "<td>";
    if($fromobj[$rule]=='host') {
      echo $fromhost[$rule];
    } else {
      if(is_array($endpoint[$fromhost[$rule]])) {
        foreach($endpoint[$fromhost[$rule]] AS $host) {
          echo "$host\n";
        }
      } else {
        echo "{$fromhost[$rule]} = {$endpoint[$fromhost[$rule]]}\n";
      }
    }
    echo "</td>\n";
    echo "<td>";
    if($toobj[$rule]=='host') {
      echo $tohost[$rule];
    } else {
      if(is_array($endpoint[$tohost[$rule]])) {
        foreach($endpoint[$tohost[$rule]] AS $host) {
          echo "$host\n";
        }
      } else {
        echo "{$tohost[$rule]} = {$endpoint[$tohost[$rule]]}\n";
      }
    }
    echo "</td>\n";
    echo "<td>";
    if($protoType=='icmp') {echo "ICMP";} else {
      if($portobj[$rule]=='port') {
        echo $porttxt[$rule];
      } else {
        if(is_array($portpoint[$porttxt[$rule]])) {
          foreach($portpoint[$porttxt[$rule]] AS $port) {
            echo "$port\n";
          }
        } else {
          echo "{$porttxt[$rule]} = {$portpoint[$porttxt[$rule]]}\n";
        }
      }
    }
    echo "</td>\n";
    echo "<td>{$interface[$rule]}</td>\n";
    echo "</tr>\n";
    echo "<!-- " . $ruleline[$rule] . " -->\n";
  }
  echo "</table>\n";
}

$maxnat=$natno;
if($maxnat>0) {
  echo "<table width=100% border=1>\n";
  echo "<tr><th>NAT No.</th><th>From LAN</th><th>From IP</th><th>To LAN</th><th>To IP</th></tr>\n";
  for($natno=1; $natno<=$maxnat; $natno++) {
    if($colour=="#8888e7") {$colour="#3bffa0";} else {$colour="#8888e7";}
    echo "<tr bgcolor='$colour'>\n";
    echo "<td>$natno</td>\n";
    if($nat[$natno]['isstatic']==TRUE) {
      echo "<td>" . $nat[$natno]['insidelan'] . "</td>\n";
      echo "<td>" . $nat[$natno]['insideip'] . "</td>\n";
      echo "<td>" . $nat[$natno]['outsidelan'] . "</td>\n";
      echo "<td>" . $nat[$natno]['outsideip'] . "</td>\n";
    } else {
      echo "<td>" . $nat[$natno]['insidelan'] . "</td>\n";
      if($nat[$natno]['insideip']=='object') {
        if(is_array($endpoint[$nat[$natno]['insideobj']])) {
          echo "<td>";
          foreach($endpoint[$nat[$natno]['insideobj']] AS $host) {
            echo "$host\n";
          }
          echo "</td>\n";
        } else {
          echo "<td>{$nat[$natno]['insideobj']} = {$endpoint[$nat[$natno]['insideobj']]}</td>\n";
        }
      } else {
        echo "<td>" . $nat[$natno]['insideip'] . "</td>\n";
      }
      echo "<td>" . $natpool[$nat[$natno]['outsideip']]['interface'] . "</td>\n";
      echo "<td>" . getHostRange($natpool[$nat[$natno]['outsideip']]['ip'], $natpool[$nat[$natno]['outsideip']]['mask']) . "</td>\n";
    }
  }
  echo "</table>\n";
}

function explodeArray($array, $level=0, $startspacer=" ", $endspacer="", $newline="{", $endline="}", $openandclose=FALSE) {

  if($openandclose=TRUE) {$space=$startspacer;} else {$space='';}
  for($lvl=0; $lvl<=$level; $lvl++) {
    $space.=$startspacer.$endspacer;
  }
  if($openandclose=TRUE) {$space=$endspacer;} else {$space='';}

  foreach($array as $key=>$value) {
    if($openandclose=TRUE) {echo $newline;}
    if(is_array($value)) {
      echo $space . $key . " = " . $newline;
      explodeArray($value, $level+1, $startspacer, $endspacer, $newline, $endline, $openandclose);
      echo $space . $endline;
    } else {
      echo $space . $key . " = $value";
    }
    if($openandclose=TRUE) {echo $endline;}
  }
}

function getHostRange($ipaddress, $netmask) {
  $ipadd=explode('.', trim($ipaddress));
  switch($netmask) {
  case '255.0.0.0':
    $scope[1]=255;
    $scope[2]=255;
    $scope[3]=255;
  case '255.128.0.0':
    $scope[1]=127;
    $scope[2]=255;
    $scope[3]=255;
  case '255.192.0.0':
    $scope[1]=63;
    $scope[2]=255;
    $scope[3]=255;
  case '255.224.0.0':
    $scope[1]=31;
    $scope[2]=255;
    $scope[3]=255;
  case '255.240.0.0':
    $scope[1]=15;
    $scope[2]=255;
    $scope[3]=255;
  case '255.248.0.0':
    $scope[1]=7;
    $scope[2]=255;
    $scope[3]=255;
  case '255.252.0.0':
    $scope[1]=3;
    $scope[2]=255;
    $scope[3]=255;
  case '255.254.0.0':
    $scope[1]=1;
    $scope[2]=255;
    $scope[3]=255;
  case '255.255.0.0':
    $scope[1]=0;
    $scope[2]=255;
    $scope[3]=255;
  case '255.255.128.0':
    $scope[1]=0;
    $scope[2]=127;
    $scope[3]=255;
  case '255.255.192.0':
    $scope[1]=0;
    $scope[2]=63;
    $scope[3]=255;
  case '255.255.224.0':
    $scope[1]=0;
    $scope[2]=31;
    $scope[3]=255;
  case '255.255.240.0':
    $scope[1]=0;
    $scope[2]=15;
    $scope[3]=255;
  case '255.255.248.0':
    $scope[1]=0;
    $scope[2]=7;
    $scope[3]=255;
  case '255.255.252.0':
    $scope[1]=0;
    $scope[2]=3;
    $scope[3]=255;
  case '255.255.254.0':
    $scope[1]=0;
    $scope[2]=1;
    $scope[3]=255;
  case '255.255.255.0':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=255;
  break;
  case '255.255.255.128':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=127;
  break;
  case '255.255.255.192':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=63;
  break;
  case '255.255.255.224':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=31;
  break;
  case '255.255.255.240':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=15;
  break;
  case '255.255.255.248':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=7;
  break;
  case '255.255.255.252':
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=3;
  break;
  default:
    $scope[1]=0;
    $scope[2]=0;
    $scope[3]=0;
  }
  if($scope[1]!=0 AND $scope[2]!=0 AND $scope[3]!=0) {
    $ip0=$ipadd[0];
    for($ip1=$ipadd[1]; $ip1<=$ipadd[1]+$scope[1]; $ip1++) {
      for($ip2=$ipadd[2]; $ip2<=$ipadd[2]+$scope[2]; $ip2++) {
        for($ip3=$ipadd[3]; $ip3<=$ipadd[3]+$scope[3]; $ip3++) {
          $return[]=$ip0.'.'.$ip1.'.'.$ip2.'.'.$ip3;
        }
      }
    }
  } else {
    $return=trim($ipaddress).' / '.trim($netmask);
  }
  return($return);
}
?>
</body>
</html>