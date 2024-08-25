using PacketDotNet;
using SharpPcap;
using System;
using System.Text;
using System.Windows.Forms;


namespace Spcap5
{
    public partial class Form1 : Form
    {
        private ICaptureDevice device;
        private string efr;

        public Form1()
        {
            InitializeComponent();

            device = CaptureDeviceList.Instance[0];

            textBox1.Text = "";

        }

        private void button1_Click(object sender, EventArgs e)

        {
            var ver = Pcap.SharpPcapVersion;

            textBox1.Text = "Sharp Pcap Version  " + ver.ToString();

            int readTimeoutMilliseconds = 1000;

            var device = CaptureDeviceList.Instance[0];

            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            device.StartCapture();

        }


        private bool isProcessingPacket = false;

        private void device_OnPacketArrival(object sender, PacketCapture e)
        {

            if (isProcessingPacket)
            {
                return;
            }


            isProcessingPacket = true;

            try
            {
                var rawPacket = e.GetPacket();
                var p = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);


                this.Invoke((MethodInvoker)delegate
                {
                    textBox1.AppendText(p.ToString() + Environment.NewLine);
                    textBox1.Update();


                    StringBuilder filteredText = new StringBuilder();

                    foreach (byte byteValue in rawPacket.Data)
                    {
                        char character = (char)byteValue;
                        // Fügen Sie nur ASCII-Zeichen hinzu oder ersetzen Sie nicht-ASCII-Zeichen durch "_"
                        if (character >= 32 && character <= 126)
                        {
                            filteredText.Append(character);
                        }
                        else
                        {
                            filteredText.Append('_');
                        }
                    }

                    textBox2.AppendText(filteredText.ToString() + Environment.NewLine);
                    textBox2.Update();

                });
            }

            finally

            {
                isProcessingPacket = false;
            }
        }




        private void button2_Click(object sender, EventArgs e)

        {
            if (device != null && device.Started)

            {
                device.StopCapture();

                MessageBox.Show(device.Statistics.ToString());

                device.Close();
            }


            //Application.Exit();
        }
    }
}
