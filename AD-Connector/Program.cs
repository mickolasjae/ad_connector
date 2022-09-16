using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using Formatting = Newtonsoft.Json.Formatting;


namespace AD_Connector
{
    internal class Program
    {
        private static readonly HttpClient Client = new HttpClient();
        // This member is used to wait for events.
        static AutoResetEvent? _signal;
        private static async Task Main(string[] args)
        {
            while (true)
            {
                _signal = new AutoResetEvent(false);
                var eventLog = new EventLog("Security", ".", "Microsoft Windows security auditing.");
                eventLog.EntryWritten += new EntryWrittenEventHandler(MyOnEntryWritten);
                eventLog.EnableRaisingEvents = true;
                _signal.WaitOne();
            }
        }
        public static void MyOnEntryWritten(object source, EntryWrittenEventArgs e)
        {
            var index = e.Entry.Index; //EventRecord ID
            var instanceId = e.Entry.InstanceId;
            var query = "*[System/EventRecordID=" + index + "]";
            var eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
            try
            {
                var logReader = new EventLogReader(eventsQuery);
                for (var eventDetail = logReader.ReadEvent(); eventDetail != null; eventDetail = logReader.ReadEvent())
                {
                    var xml = eventDetail.ToXml();
                    var doc = new XmlDocument();
                    doc.LoadXml(xml);
                    var json = JsonConvert.SerializeXmlNode(doc, Formatting.Indented, true);
                    JObject jObject = JObject.Parse(json);
                    JToken jEvent = jObject["EventData"]["Data"];
                    Dictionary<string, string> eventProperties = new Dictionary<string, string>();
                    foreach (var events in jEvent)
                    { 
                        eventProperties.Add(events["@Name"].ToString(), events["#text"].ToString());
                    }
                    var eventJson = JsonConvert.SerializeObject(eventProperties);
                    var eventContent = new StringContent(eventJson);
                    switch (instanceId)
                    {
                        case 4720:

                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("User created");
                            break;

                        case 4726:
                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("User deleted");
                            break;

                        case 4725:
                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("User disabled");
                            break;

                        case 4738:
                            /*sendEventPropertiesToOkta(eventContent);*/
                            //WriteToFile("User changed");
                            break;

                        case 4722:
                            /*sendEventPropertiesToOkta(eventContent);*/
                            //WriteToFile("User enabled");
                            break;

                        case 4737:
                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("Group changed");
                            break;

                        case 4728:
                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("User added to group");
                            break;

                        case 4729:
                            sendEventPropertiesToOkta(eventContent);
                            //WriteToFile("User removed from group");
                            break;
                    }
                }
            }

            catch (EventLogNotFoundException)
            {
                Console.WriteLine("Error while reading the event logs");
                return;
            }
        }
        
        public static async Task sendEventPropertiesToOkta(HttpContent eventProperties)
        {
            try
            {
                var response = await Client.PostAsync("https://ooo.workflows.oktapreview.com/api/flo/9c2f5ed8f45e991d0adb014e843df3f9/invoke?clientToken=1150564aa25beed830702d18bced389629b6c1ee81900de3c7b4cd8416c5ee94", eventProperties);
                response.EnsureSuccessStatusCode();
                var responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine(responseBody);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }
        }
    }
}

