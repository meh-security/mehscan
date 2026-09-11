<%@ Page Language="C#" ValidateRequest="false" %>

<%= Request["name"] %>
<%= Request.Unvalidated.QueryString["description"] %>
<%: Request["encoded"] %>
<%= HttpUtility.HtmlEncode(Request["alsoEncoded"]) %>
<%-- <%= Request["commented"] %> --%>
<%= Model.DisplayName %>
<%= "literal" %>
