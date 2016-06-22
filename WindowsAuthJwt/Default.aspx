<%@ Page Language="C#" %>
<script runat="server">
  protected override void OnLoad(EventArgs e)
  {
      Response.Redirect("JWTLogin.ashx");
      base.OnLoad(e);
  }
</script>
