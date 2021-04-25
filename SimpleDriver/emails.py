
import pkg_resources
from jcloudlabs.util.mailer.jcl_mailer import sendEmail


def prepare_msg(cntxt, msg_template_file, worddict=None):
    """
    Reads the text file from the package directory to string, replaces text patters using worddict
    :param cntxt:
    :param msg_template_file:
    :param worddict:
    :return:
    """
    # read message from the file
    resource_package = __name__
    try:
        message = pkg_resources.resource_string(resource_package, msg_template_file)
    except Exception as exc:
        msg = 'Cannot read from file '+msg_template_file+ '. ' + str(exc)
        cntxt.logError(msg, output=True, console=True)
        raise Exception(msg)

    if type(worddict) is dict and worddict is not None and worddict.__len__() > 0:
        for key in worddict:
            message = message.replace(key, worddict[key])

    return message


def send_email_demo_cmd(cntxt,
                        command=None,
                        cmddesc='No description',
                        timeout=None,
                        stdout='<Nothing>',
                        stderr='<Nothing>',
                        status='Unknown status',
                        time_elapsed=1000000.00,
                        suppress=True):
    """
    Send email with results of Demo Command
    :param cntxt:
    :param command:
    :param cmddesc:
    :param timeout:
    :param stdout:
    :param stderr:
    :param status:
    :param time_elapsed:
    :param suppress
    :return:
    """
    funcName = 'send_email_demo_cmd'
    cntxt.logDebug("{}: Starting function".format(funcName), console=True)

    worddict = {'{{ReservationUser}}': cntxt.owner_user,
                '{{ReservationShortName}}': cntxt.ReservShortName,
                '{{ReservationEndtime}}': cntxt.ReservEndTime,
                '{{ReservationId}}': cntxt.id,
                '{{CommandLine}}': command,
                '{{CommandTimeout}}': str(timeout),
                '{{CommandDescription}}': cmddesc,
                '{{StdOut}}': stdout,
                '{{StdErr}}': stderr,
                '{{Status}}': str(status),
                '{{TimeElapsed}}': str(round(time_elapsed, 2)),
                }
    toAddr = ""
    if not suppress:
        toAddr = cntxt.owner_email

    bccAddr = cntxt.EmailReport_Admin
    ccAddr = ''

    if cntxt.domain == 'CCL':
        pattern_filename = '/email-templates/CCL-HelperVM-Message1.html'
        subject = 'CCL sandbox "{}"; Report for {}'.format(cntxt.ReservShortName, cmddesc)
    elif cntxt.domain == 'vLabs':
        pattern_filename = '/email-templates/vLabs-HelperVM-Message1.html'
        subject = 'vLabs sandbox "{}"; Report for {}'.format(cntxt.ReservShortName, cmddesc)
    else:
        pattern_filename = '/email-templates/JCL-HelperVM-Message1.html'
        subject = 'JCL sandbox "{}"; Report for {}'.format(cntxt.ReservShortName, cmddesc)

    if cntxt.domain == 'vLabs':
        toAddr = cntxt.EmailReport_Admin

    message = prepare_msg(cntxt, pattern_filename, worddict)
    rc = sendEmail(cntxt.session,
                   toAddr,
                   ccAddr,
                   bccAddr=bccAddr,
                   domain=cntxt.domain,
                   subject=subject,
                   msgHtml=message,
                   style=None)
    cntxt.logDebug("{}: Completed function".format(funcName), console=True)
    return rc



