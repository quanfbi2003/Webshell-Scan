<%@ Page Language="C#" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    Response.Write(Server.HtmlEncode(Request.QueryString["name"] ?? "guest"));
}
</script>
