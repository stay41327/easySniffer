from Tkinter import *
import Pmw
import sys, Tkinter
import snlib
import time
import threading
sys.modules['tkinter'] = Tkinter 
eth = ""
def GUI():
    #add UI and Frame 
    root = Tk()
    root.title('Sniffer')
    fleft = Frame(root)
    fright = Frame(root)
    fltop = Frame(fleft,width = 500)
    flml = Frame(fleft)
    flmid = Frame(fleft)
    flmidb = Frame(fleft)
    flbot = Frame(fleft,width = 100)
    flbt = Frame (flbot,width = 100)
    flbb = Frame (flbot,width = 100,height = 30)
    fltopp = Frame (fleft,width = 100,height = 30)
    fltopl = Frame (fltopp,width = 100,height = 30)
    fltopr = Frame (fltopp,width = 100,height = 30)
    
    

    #choose the network
    Pmw.initialise()
    choice = None
    def choseEntry(entry):
        global eth
        eth = entry
        print 'You chose"%s"'%entry
        #choice.configure(text = entry )

    asply = ['eth0', 'wlan0']
    combobox = Pmw.ComboBox(fltop,label_text = 'choose network',labelpos = 'wn',listbox_width =12,dropdown =1,selectioncommand = choseEntry,scrolledlist_items = asply).pack(side = LEFT,fill = BOTH, expand = 1)
    #combobox.selectitem(asply[0])
    
    Label(flml,text =varString(),font = ( "method",12)).pack(padx= 10,pady = 10)
    Label(flbt,text ="detail message:",font = ( "detail message",10)).pack(side = LEFT, padx= 10,pady = 10)
   
    #list1 any packet would set on this
    list1 = Listbox(flmid,height = 6,width = 50)
    s1 = Scrollbar(flmid,command = list1.yview)
    s2 = Scrollbar(flmid,orient = HORIZONTAL,command = list1.xview)
    list1.configure(yscrollcommand = s1.set)
    list1.configure(xscrollcommand = s2.set)
    # 6 Entry to set the condition
    srcStr = StringVar()
    srcStr.set("source address")
    Entry(fltopl,textvariable = srcStr).pack()
    dstIpStr = StringVar()
    dstIpStr.set("destination ip")
    Entry(fltopr,textvariable = dstIpStr).pack()
    dstPortStr = StringVar()
    dstPortStr.set("destination port")
    Entry(fltopl,textvariable = dstPortStr).pack()
    protoStr = StringVar()
    protoStr.set("protocol")
    Entry(fltopr,textvariable = protoStr).pack()
    searchStr = StringVar()
    searchStr.set("search")
    Entry(fltopl,textvariable = searchStr).pack()
    ipIdStr = StringVar()
    ipIdStr.set("ip id for assembly")
    Entry(fltopr,textvariable = ipIdStr).pack()
    
    s2.pack(side = BOTTOM,fill = X)
    list1.pack(side = LEFT)
    s1.pack(side = RIGHT,fill = Y)
    #list2 to set on the additional messages
    list2 = Listbox(flbb,height = 6,width = 50)
    s3 = Scrollbar(flbb,command = list2.yview)
    s4 = Scrollbar(flbb,orient = HORIZONTAL,command = list2.xview)
    list2.configure(yscrollcommand = s3.set)
    list2.configure(xscrollcommand = s4.set)
    list2.pack(side = LEFT)
    s3.pack(side = RIGHT,fill = Y)
    

    #define the start method
    def startSniff():
        global eth
        list1.delete(0, END)
        list2.delete(0, END)
        snlib.Stop_Button_Click = False
        snlib.th_sniff(eth, False, 0)
        class MyThread(threading.Thread):
            def __init__(self):
                threading.Thread.__init__(self)
                threading.Thread.setDaemon(self, True)
            def run(self):
                bufSize = 0
                contSize = 0
                while not snlib.Stop_Button_Click:
                    tmpBufSize = len(snlib.pktBuf)
                    tmpContSize = len(snlib.pktCont)
                    if bufSize == tmpBufSize and contSize == tmpContSize:
                        continue
                    bufi = bufSize
                    conti = contSize
                    while bufi < tmpBufSize:
                        list1.insert(END, str(snlib.pktBuf[bufi]))
                        bufi += 1
                    bufSize = tmpBufSize
                    while conti < tmpContSize:
                        list2.insert(END, str(snlib.pktCont[conti]))
                        conti += 1
                    contSize = tmpContSize
        thread = MyThread()
        thread.start()
    f1 = Frame(fright,borderwidth = 10)
    Button1=Button(f1,text = "Start",bg = "gray75",height = 1,width = 15,command = startSniff).pack()
    f1.place(relx = 10,rely = 10,anchor = NW)
    f1.pack()
    #define stop method
    def stopSniff():
        snlib.Stop_Button_Click = True
    f2 = Frame(fright,borderwidth = 10)
    Button2=Button(f2,text = "Stop",bg = "gray75",height = 1,width = 15,command = stopSniff).pack()
    f2.place(relx = 10,rely = 10,anchor = NW)
    f2.pack()
   #define filter method
    def filterSniff():
        global eth
        del snlib.pktBuf[0:len(snlib.pktBuf)]
        list1.delete(0, END)
        list2.delete(0, END)
        del snlib.fragBuf[0:len(snlib.fragBuf)]
        del snlib.Protocol[0:len(snlib.Protocol)]
        snlib.src_dstIP_sniff(srcStr.get(), dstIpStr.get(), eth)
        snlib.src_dstPort_sniff(srcStr.get(), dstPortStr.get(), eth)
        snlib.pro_sniff(protoStr.get(), eth) 
    f3 = Frame(fright,borderwidth = 10)
    Button(f3,text ="Filter",bg = "gray75",height = 1,width = 15, command = filterSniff).pack()
    f3.place(relx = 10,rely = 10,anchor = NW)
    f3.pack()
    #define search method
    def searchSniff():
        result = snlib.search(searchStr.get())
        list1.delete(0, END)
        for i in result:
            list1.insert(END, str(i))
    f4 = Frame(fright,borderwidth = 10)
    Button(f4,text = "Search",bg = "gray75",height = 1,width = 15, command = searchSniff).pack()
    f4.place(relx = 10,rely = 10,anchor = NW)
    f4.pack()
    #define ChickDaily method   
    def readLog():
        f = file("log", 'r')
        list1.delete(0, END)
        while True:
            line = f.readline()
            if len(line) == 0:
                break
            list1.insert(END, line)
    f5 = Frame(fright,borderwidth = 10)
    Button(f5,text ="CheckDaily",bg = "gray75",height = 1,width = 15, command = readLog).pack()
    f5.place(relx = 10,rely = 10,anchor = NW)
    f5.pack()
    #define messageReconstruct method   
    def assembly():
        result = snlib.pkt_assemble(ipIdStr.get())
        list1.delete(0, END)
        for i in result:
            list1.insert(END, i)
    f6 = Frame(fright,borderwidth = 10)
    Button(f6,text = "MessageReconstruct",bg = "gray75",height = 1,width = 15, command = assembly).pack()
    f6.place(relx = 10,rely = 10,anchor = NW)
    f6.pack()
        
    f7 = Frame(fright,borderwidth = 10)
    Button(f7,text = "saveTxt",bg = "gray75",height = 1,width = 15, command = snlib.savPk).pack()
    f7.place(relx = 10,rely = 10,anchor = NW)
    f7.pack()
        
   
        
    def fileReconstruct():
        list2.delete(0, END)
        list1.delete(0, END)
        snlib.single_file_asm(srcStr.get(),dstIpStr.get(),dstPortStr.get(),eth)
        list1.insert(END, snlib.Content)
    f9 = Frame(fright,borderwidth = 10)
    Button(f9,text = "file reconstruct",bg = "gray75",height = 1,width = 15,command = fileReconstruct).pack()
    f9.place(relx = 10,rely = 10,anchor = NW)
    f9.pack()
    
    f8 = Frame(fright,borderwidth = 10)
    Button(f8,text = "Exit",bg = "gray75",height = 1,width = 15,command = root.quit).pack()
    f8.place(relx = 10,rely = 10,anchor = NW)
    f8.pack()
    # pack the Frames
    flbb.pack(side = BOTTOM) 
    fltopp.pack()
    fltopl.pack(side = LEFT)
    fltopr.pack(side = LEFT) 
    fltop.pack()
    flmid.pack()
    flmidb.pack()
    
    flbt.pack(side = LEFT)
    flbot.pack(padx = 10,pady = 10)
    fleft.pack(side = LEFT,padx = 10,pady = 10)
    fright.pack(side = RIGHT,padx= 10,pady = 20)
    
    root.mainloop()
###below this are functions###
startState = True
stopState = False
def varString():
    return "stop"
def usageMonitor(): 
    usage = "0"
    return "network data usage:"+ usage+ "Kb/s"
def startButton():
    if(startState == True):
         snlib.Stop_Button_Click = False
         startState = False
         stopState = True
         #snlib.th_sniff(interface) #interface:choose network,not finished
         #proInter = Tk()
         #pf = Frame(proInter)
         
   
def stopButton():
    snlib.Stop_Button_Click = True
    startState = True
    stopState = False
    snlib.stop_sniff(True)
    

   
##############################
#begin
gui = GUI()



