#!/usr/bin/python3

#-Import needed modules-------------------------------------
import os, sys
import string
import getpass
import socket
from errno import ECONNREFUSED
import string
import argparse

try: import paramiko
except: exit('Paramiko Client module for ptyhon3 is needed. Please install it first.')

try: import PyInquirer
except: exit('Inquirer module for ptyhon3 is needed. Please install it first (via pip install PyInquirer).')


#-Set globals----------------------------------------------------------------
CurPath = os.path.dirname(os.path.realpath(__file__))


#-Build the ArgParser--------------------------------------------------------

def build_arg_parse():
  AppParser = argparse.ArgumentParser()

  AppParser.add_argument("--target-hosts", type=str, required=True,
    help="Required: Set target hosts. multiple hosts separated by comma.")

  AppParser.add_argument("--public-key", type=str, required=True,
    help="Required: Set path to public key file to deploy.")

  AppParser.add_argument("--deploy-user", type=str, required=True,
    help="Required: Set user name for deployment.")

  AppParser.add_argument("--target-user", type=str, 
    help="Optional: Set user name for target user. Else same user name as deploy user will be used.")

  ArgGroup = AppParser.add_mutually_exclusive_group(required=True)
  ArgGroup.add_argument("--deploy-password", type=str, 
    help="Choice (password or key): Set password for deployment.")

  ArgGroup.add_argument("--deploy-key", type=str, 
    help="Choice (key or password): Set path to privat key for deployment.")

  args = AppParser.parse_args()
  return(args)
  



#-SSH deployer Class----------------------------------------------------------
class ssh_deploy:

  #-Fixed Class Vars------------------------------- 

  sshTargetHosts = []
  sshTargetUsr = str
  sshDeployPwd = str
  sshDeployUsr = str
  sshDeployKey = str
  pubKeyPath = str
  paraList = [
    { 
      'name': 'sshTargetHosts',
      'description': 'ssh target host:      ',
    },
    { 
      'name': 'pubKeyPath',
      'description': 'public key path:      ',
    },
    { 
      'name': 'sshDeployUsr',
      'description': 'ssh deploy user:      ',
    },
    { 
      'name': 'sshDeployPwd',
      'description': 'ssh deploy password:  ',
    },
    { 
      'name': 'sshDeployKey',
      'description': 'ssh deploy key:       ',
    },
    { 
      'name': 'sshTargetUsr',
      'description': 'ssh target user:      ',
    }
  ]

  #-Initializer------------------------------------
  def __init__(self):
    print('*New ssh deploy object created')

  #-Helpers----------------------------------------
  def has_special_chars(self, strIn):
    specialChars = string.punctuation
    bools = list(map(lambda char: char in specialChars, strIn))
    if any(bools):
      return True 
    else:
      return False

  #--------------------------------
  def try_usr_std_path(self):
    stdPath = '/home/'+str(self.sshDeployUsr)+'/.ssh/id_rsa.pub' 
    if os.path.isfile(stdPath):
      try: 
        readChk = open(stdPath, 'r')
        readChk.close()
      except:
        return False
      return stdPath
    else:
      return False
  #--------------------------------
  def check_deploy_ready(self):
    chk = []
    if len(self.sshTargetHosts) == 0:
      chk.append('ssh target hosts')
    if type(self.sshTargetUsr) == type:
      chk.append('ssh target user')
    if type(self.sshDeployUsr) == type:
      chk.append('ssh deploy user')
    if type(self.pubKeyPath) == type:
      chk.append('public key')
    if  type(self.sshDeployPwd) == type and type(self.sshDeployKey) == type:
      chk.append('ssh deploy password or ssh deploy key')
    
    return chk
  
  #-------------------------------
  def ssh_port_scan(self, target, port=22):
    try:
      curSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      socketTimeout = 5
      curSock.settimeout(socketTimeout)
      curSock.connect((target, port))
      return True
    except socket.error as err:
        if err.errno == ECONNREFUSED:
            return False


  #-Main Methodes----------------------------------

  def set_ssh_target_host(self, curHost=False):
    if type(curHost) is not str or curHost == '':
      print('- SSH host not set or in wrong format.', "\n  Try String" )
      return

    if not self.ssh_port_scan(curHost):
      print('- SSH host not reachable' )
      return False
    else:
      self.sshTargetHosts.append(curHost)

  #------------------------------------
  def set_ssh_deploy_user(self, usr=False):
    #if type(usr) is str and not self.has_special_chars(usr):
    if type(usr) is str:
      self.sshDeployUsr = usr.replace(' ', '')
      self.sshTargetUsr = usr.replace(' ', '')
    elif not usr:
      curUsr = getpass.getuser()
      print('- Username not defined or in wrong format.', "\n  Proceed with current user: "+curUsr )
      self.sshDeployUsr = curUsr
      self.sshTargetUsr = curUsr
    else:
      return False
  
  #------------------------------------
  def set_ssh_target_user(self, usr=False):
    if type(usr) is str:
      self.sshTargetUsr = usr.replace(' ', '')
    else:
      return False
    # else:
    #   curUsr = getpass.getuser()
    #   print('- Username not defined or in wrong format.', "\n  Proceed with current user: "+curUsr )
    #   self.sshDeployUsr = curUsr

  #------------------------------------
  def set_public_key(self, keyPath=False):
    chk = True
    keyStr = ''
    if type(keyPath) is str:
      curKeyPath = keyPath.replace(' ', '')
      curKeyPath = keyPath.replace('//', '/')
      try:
        curKeyPath = os.path.abspath(keyPath)
        readChk = open(curKeyPath, 'r')
        keyStr = readChk.read()
        readChk.close()
      except:
        chk = False
      
      if not keyStr.startswith('ssh-rsa'): 
        chk = False
      
    else:
      chk = False

    if chk:
      self.pubKeyPath = curKeyPath
    else:
      print('- Invalid public key or file not readable.', "\n  Trying standard public key path...")
      methRes = self.try_usr_std_path()
      if not methRes:
        print('- Unable to use standard public key.', "\n  E.g. try another path.")
        return False
      else:
        self.pubKeyPath = methRes
      
  #------------------------------------
  def set_ssh_deploy_password(self, curPwd=False):
    if type(curPwd) is not str or len(curPwd) < 1:
      print('- Invalid password input.', "\n  Please try again with string input.")
      return
    else:
      self.sshDeployPwd = curPwd
      self.sshDeployKey = str

  #------------------------------------
  def set_ssh_deploy_key(self, keyPath=False):
    chk = True
    keyStr = ''

    if type(keyPath) is str:
      curKeyPath = keyPath.replace(' ', '')
      curKeyPath = keyPath.replace('//', '/')
      try:
        curKeyPath = os.path.abspath(keyPath)
        readChk = open(curKeyPath, 'r')
        keyStr = readChk.read()
        readChk.close()
      except:
        chk = False
      
      if '-BEGIN RSA PRIVATE KEY-' not in keyStr or '-END RSA PRIVATE KEY' not in keyStr: 
        chk = False
    else:
      chk = False

    if chk:
      self.sshDeployKey = curKeyPath
      self.sshDeployPwd = str
    else:
      print('- Invalid ssh key or file not readable.')
      return
  
  #------------------------------------
  def args_to_object(self, AppArgs):

    #-Add hostlist from argparse input---
    tgtHosts = AppArgs.target_hosts.replace(' ', '').replace('/', '').replace('\\', '')
    tgtHosts = tgtHosts.split(',')
    tgtHosts = list(dict.fromkeys(tgtHosts))
    #print(tgtHosts)
    for tgtHost in tgtHosts:
      self.set_ssh_target_host(tgtHost)
    if len(self.sshTargetHosts) == 0:
      exit('- Exit: no valid host in configuration')

    #-Add public key from argparse input---
    pubKeyPath = AppArgs.public_key
    self.set_public_key(pubKeyPath)
    if type(self.pubKeyPath) is type: 
      exit('- Exit: no valid public key path in configuration')

    #-Add deploy user from argparse input---
    deplUsr = AppArgs.deploy_user
    self.set_ssh_deploy_user(deplUsr)
    if type(self.sshDeployUsr) is type: 
      exit('- Exit: no valid user for deployment in configuration')

    #-Add deploy password or key from argparse input---
    if AppArgs.deploy_password:
      #print("go for password")
      deplPwd = AppArgs.deploy_password
      self.set_ssh_deploy_password(deplPwd)
    elif AppArgs.deploy_key:
      #print("go for key")
      deplKeyPath = AppArgs.deploy_key
      self.set_ssh_deploy_key(deplKeyPath)

    if type(self.sshDeployPwd) is type and type(self.sshDeployKey) is type: 
      exit('- Exit: no valid user for deployment in configuration')

    #-Optional:add target user from argparse input---
    if AppArgs.target_user:
      #print("go for target_user")
      tgtUsr = AppArgs.target_user
      self.set_ssh_target_user(tgtUsr)
      if tgtUsr != self.sshTargetUsr:
        print(' - Warning: unable to set target user in configuration')

  #------------------------------------
  def print_object_config(self):
    for varDef in self.paraList:
      curName = varDef['name']
      curDesc = varDef['description']
      curVal = getattr(self, curName)
      if type(curVal) == type:
        curVal = '"not set"'
      print(' - ', curDesc, curVal)


  #------------------------------------
  def deploy_execute(self):
    chkResAry = self.check_deploy_ready()
    if len(chkResAry) > 0:
      print('*Please set following parameters first: ' + ', '.join(chkResAry))
      return
    else:
      for sshTargetHost in self.sshTargetHosts:
        self.deploy_execute_one(sshTargetHost)
  #--------------------
  def deploy_execute_one(self, sshTargetHost):
    print('*Deploy ssh public key on host: %s' %sshTargetHost)
    #-Some temp vars for cleaner code---
    usrHomePath = '/home/'+self.sshTargetUsr
    usrSshPath = usrHomePath+'/.ssh/'
    usrAuthKeysPath = usrSshPath + 'authorized_keys'
    #print(usrAuthKeysPath)

    #-Build the ssh client and establish connection---
    sshCli = paramiko.SSHClient()
    sshCli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if os.path.isfile(str(self.sshDeployKey)):
      keyObj = paramiko.RSAKey.from_private_key_file(self.sshDeployKey)
      sshCli.connect(sshTargetHost, username=self.sshDeployUsr, pkey=keyObj)
    else:
      sshCli.connect(sshTargetHost, username=self.sshDeployUsr, password=self.sshDeployPwd)

    #-Check if target user already exists---
    stdin, stdout, stderr = sshCli.exec_command('getent passwd')
    stdout=stdout.readlines()
    stdOutStr = " ".join(stdout)
    #print(stdOutStr)
    
    #-Create target user incl. ssh folder and files, if not exists---
    if self.sshTargetUsr+':' not in stdOutStr:
      print(' - add user %s on target host' % self.sshTargetUsr)
      sshCli.exec_command('sudo useradd %s' % self.sshTargetUsr)

      #-Add user to admin groups (sudo/wheel)---
      stdin, stdout, stderr = sshCli.exec_command('cat /etc/group')
      stdout=stdout.readlines()
      stdOutStr = " ".join(stdout)
      if 'wheel' in stdOutStr:
        sshCli.exec_command('sudo usermod -aG wheel %s' %self.sshTargetUsr )
      elif 'sudo' in stdOutStr:
        sshCli.exec_command('sudo usermod -aG sudo %s' %self.sshTargetUsr )

      #sshCli.exec_command('sudo usermod -aG wheel %s' % self.sshTargetUsr)
      sshCli.exec_command('sudo mkdir -p %s' % usrSshPath)
      sshCli.exec_command('sudo chown -R '+self.sshTargetUsr+':'+self.sshTargetUsr+' ' + usrHomePath)

      #switch to bash 
      #sshCli.exec_command('sudo chsh -s /bin/bash %s' % self.sshTargetUsr)
      sshCli.exec_command('sudo usermod -s /bin/bash %s' % self.sshTargetUsr)

    sshCli.exec_command('sudo touch %s' % usrAuthKeysPath)


    #-Get public key to deploy as string---
    pubKeyObj = open(self.pubKeyPath)
    pubKeyStr = pubKeyObj.read()
    pubKeyStr = pubKeyStr.replace("\n", "")
    
    #-Get existing auth key file from target host---
    stdin, stdout, stderr = sshCli.exec_command('sudo cat '+usrAuthKeysPath)
    stdout=stdout.readlines()
    authKeyStr = " ".join(stdout)
   
    #print(pubKeyStr, authKeyStr)

    #-Deploy pub key if not in auth key file---
    if pubKeyStr not in authKeyStr:
      if self.sshTargetUsr != self.sshDeployUsr: sudo = 'sudo '
      else: sudo = ''
      #print(sudo + 'echo "'+pubKeyStr+'" >> '+ usrAuthKeysPath)
      sshCli.exec_command(sudo + 'sh -c \'echo "%s" >> %s\'' %(pubKeyStr, usrAuthKeysPath)) #UIUIUIUIUI
      sshCli.exec_command(sudo + 'chown '+self.sshTargetUsr+':'+self.sshTargetUsr + ' ' + usrAuthKeysPath)
      sshCli.exec_command(sudo + 'chmod 644 %s' % usrAuthKeysPath)
      sshCli.exec_command(sudo + 'chmod 700 %s' % usrSshPath)

    sshCli.close()
    print(' - Deployment for host %s => executed' % sshTargetHost)

#-SSH deployer Class----------------------------------------------------------
class interactive_menu:
  
  #sys.path.insert(0, './pip')
  #import PyInquirer

  #-Fixed Class Vars------------------------------- 
  curDeploy = object
  funcMapper = dict
  
  #-Initializer------------------------------------
  def __init__(self):
    print('*Starting interactive configuration menu')

    self.curDeploy = ssh_deploy()
    self.create_function_mapper()
    
    _ = os.system('clear')

    print('Your Configuration: ')
    self.curDeploy.print_object_config()

    self.call_choice_list()
    
    
  #-Main methods-----------------------------------
  def create_function_mapper(self):
    self.funcMapper = {
      "1. add ssh target hosts (required)": {
        "func": self.curDeploy.set_ssh_target_host,
        "txt": "please enter a ssh target host: "
      },
      "2. set public key to deploy (required)": {
        "func": self.curDeploy.set_public_key,
        "txt": "please enter path to public key: "
      },
      "3. set user for deployment (required)": {
        "func": self.curDeploy.set_ssh_deploy_user,
        "txt": "please enter user name od deployment user: "
      },
      "4. set password for deployment (required/choice)": {
        "func": self.curDeploy.set_ssh_deploy_password,
        "txt": "please enter deployment password: "
      },
      "5. set private key path for deployment (required/choice)": {
        "func": self.curDeploy.set_ssh_deploy_key,
        "txt": "please enter deployment key path: "
      },
      "6. set ssh target user (optional)": {
        "func": self.curDeploy.set_ssh_target_user,
        "txt": "please enter ssh target user name: "
      },
      "-> Execute deployment": {
        "func": self.execute_deployment,
      },
      "-> Exit menu": {
        "func": self.exit_menu,
      }
    }

  #------------------------------------------
  def call_choice_list(self):
    print('')

    choiceList = []
    for act, funcObj in self.funcMapper.items():
      choiceList.append(act)

    actSelect = [
      {
        'type': 'list',
        'name': 'conf_act',
        'message': 'Choose between the following actions',
        'choices': choiceList,
        #'filter': lambda val: val.lower()
      }
    ]
    curSelect = PyInquirer.prompt(actSelect)
    curAct = curSelect['conf_act']
    funcObj = self.funcMapper[curAct]
    self.call_user_input(funcObj)

    print('Your Configuration: ')
    self.curDeploy.print_object_config()
    self.call_choice_list()

  #------------------------------------------
  def call_user_input(self, funcObj):
    if 'txt' in funcObj:
      usrIpt = input(funcObj['txt'])
      funcObj['func'](usrIpt)
      _ = os.system('clear')
    else:
      funcObj['func']()

  #------------------------------------------
  def execute_deployment(self):
    _ = os.system('clear')
    self.curDeploy.deploy_execute()
    self.curDeploy = ssh_deploy()

  #------------------------------------------
  def exit_menu(self):
    exit('good by')


#-App Runner------------------------------------------------------------------
if __name__ == '__main__':

  if "--interactive" in sys.argv:
    CurMenu = interactive_menu()
    #CurMenu.execute_deployment()

  else:
    AppArgs = build_arg_parse()
    #print(AppArgs)
    
    CurDeploy = ssh_deploy()
    CurDeploy.args_to_object(AppArgs)
    chk = CurDeploy.check_deploy_ready()
    CurDeploy.print_object_config()
    CurDeploy.deploy_execute()


#-Test Area--------------------------------------
  # testObj = ssh_deploy()
  # testObj.set_ssh_deploy_user('scm')
  # #testObj.set_ssh_deploy_user()
  # testObj.set_ssh_target_user('palim')
  # testObj.set_public_key('/home/scm/.ssh/id_rsa.pub')
  # #testObj.set_public_key()
  # #testObj.set_ssh_deploy_password('Oviss1234!')
  # testObj.set_ssh_deploy_key('/home/scm/.ssh/id_rsa')
  # testObj.set_ssh_target_host('mgmt1')
  # testObj.set_ssh_target_host('mgmt2')
  # #test = testObj.check_deploy_ready()

  # testObj.print_object_config()
  # #testObj.deploy_execute()

  


  
