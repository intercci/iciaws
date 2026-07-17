#![allow(dead_code)]
use aws_config::BehaviorVersion;
use aws_sdk_sesv2::{
    Client,
    error::DisplayErrorContext,
    operation::{
        get_contact_list::GetContactListOutput, get_email_template::GetEmailTemplateOutput,
    },
    primitives::Blob,
    types::{
        Body, BulkEmailContent, BulkEmailEntry, Contact, Content, Destination, EmailContent,
        EmailTemplateContent, Message, RawMessage, ReplacementEmailContent, ReplacementTemplate,
        Template,
    },
};
use dotenv::dotenv;
use std::collections::HashSet;
use std::env;
use thiserror::Error;
use tokio::sync::OnceCell;

#[derive(Error, Debug)]
pub enum SesError {
    #[error("SendRawEmail error: {0}")]
    SendRawEmail(String),
    #[error("SendSimpleEmail error: {0}")]
    SendSimpleEmail(String),
    #[error("SendTemplateEmail error: {0}")]
    SendTemplateEmail(String),
    #[error("Contact list error: {0}")]
    ContactList(String),
    #[error("Contact error: {0}")]
    ListContacts(String),
    #[error("List templates error: {0}")]
    ListTemplates(String),
    #[error("Get template error: {0}")]
    GetTemplate(String),
    #[error("Create template error: {0}")]
    CreateTemplate(String),
    #[error("Update template error: {0}")]
    UpdateTemplate(String),
    #[error("Delete template error: {0}")]
    DeleteTemplate(String),
}

#[derive(Debug)]
pub struct BulkUserData {
    pub email: String,
    pub ds: String,
}

pub async fn ses_client() -> Client {
    if env::var("LAMBDA_TASK_ROOT").is_err() {
        dotenv().ok();
    }
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    Client::new(&config)
}

#[derive(Debug)]
pub struct SesClient {
    client: Client,
}

impl SesClient {
    pub async fn new() -> Self {
        SesClient {
            client: ses_client().await,
        }
    }

    pub async fn list_contact_lists(&self) -> Result<Vec<String>, SesError> {
        let output = self.client.list_contact_lists().send().await
            .map_err(|e| SesError::ContactList(format!("{}", DisplayErrorContext(e))))?;

        if output.next_token.is_some() {
            return Err(SesError::ContactList("contact list too long".to_string()));
        }

        let cs = output.contact_lists.ok_or_else(|| {
            SesError::ContactList("empty contact lists".to_string())
        })?;

        let cls: Vec<String> = cs
            .into_iter()
            .filter_map(|c| c.contact_list_name)
            .collect();
        Ok(cls)
    }

    pub async fn get_contact_list(
        &self,
        contact_list_name: &str,
    ) -> Result<GetContactListOutput, SesError> {
        self.client.get_contact_list()
            .contact_list_name(contact_list_name)
            .send().await
            .map_err(|e| SesError::ContactList(format!("{}", DisplayErrorContext(e))))
    }

    pub async fn list_contacts(&self, contact_list_name: &str) -> Result<Vec<Contact>, SesError> {
        let output = self.client.list_contacts()
            .contact_list_name(contact_list_name)
            .send().await
            .map_err(|e| SesError::ListContacts(format!("{}", DisplayErrorContext(e))))?;

        if output.next_token.is_some() {
            return Err(SesError::ListContacts("template list too long".to_string()));
        }

        output.contacts
            .ok_or_else(|| SesError::ListContacts("empty contacts".to_string()))
    }

    pub async fn list_email_templates(&self) -> Result<Vec<String>, SesError> {
        let output = self.client.list_email_templates()
            .page_size(100)
            .send().await
            .map_err(|e| SesError::ListTemplates(format!("{}", DisplayErrorContext(e))))?;

        if output.next_token.is_some() {
            return Err(SesError::ListTemplates("template list too long > 100".to_string()));
        }

        let cs = output.templates_metadata.ok_or_else(|| {
            SesError::ListTemplates("templates not found".to_string())
        })?;

        let ets: Vec<String> = cs.into_iter().filter_map(|t| t.template_name).collect();
        Ok(ets)
    }

    pub async fn get_email_template(
        &self,
        template_name: &str,
    ) -> Result<GetEmailTemplateOutput, SesError> {
        self.client.get_email_template()
            .template_name(template_name)
            .send().await
            .map_err(|e| SesError::GetTemplate(format!("{}", DisplayErrorContext(e))))
    }

    pub async fn create_template(
        &self,
        name: &str,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<(), SesError> {
        let template_content = EmailTemplateContent::builder()
            .subject(subject)
            .html(html)
            .text(text)
            .build();

        self.client.create_email_template()
            .template_name(name)
            .template_content(template_content)
            .send().await
            .map_err(|e| SesError::CreateTemplate(format!("{}", DisplayErrorContext(e))))?;
        Ok(())
    }

    pub async fn update_template(
        &self,
        name: &str,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<(), SesError> {
        let template_content = EmailTemplateContent::builder()
            .subject(subject)
            .html(html)
            .text(text)
            .build();

        self.client.update_email_template()
            .template_name(name)
            .template_content(template_content)
            .send().await
            .map_err(|e| SesError::UpdateTemplate(format!("{}", DisplayErrorContext(e))))?;
        Ok(())
    }

    pub async fn delete_template(&self, template_name: &str) -> Result<(), SesError> {
        self.client.delete_email_template()
            .template_name(template_name)
            .send().await
            .map_err(|e| SesError::DeleteTemplate(format!("{}", DisplayErrorContext(e))))?;
        Ok(())
    }

    pub async fn send_raw(
        &self,
        from: &str,
        tos: Vec<String>,
        content: &str,
    ) -> Result<String, SesError> {
        let dest = Destination::builder().set_to_addresses(Some(tos)).build();
        let raw_cnt = RawMessage::builder().data(Blob::new(content)).build().unwrap();
        let cnt = EmailContent::builder().raw(raw_cnt).build();

        let res = self.client.send_email()
            .from_email_address(from)
            .destination(dest)
            .content(cnt)
            .send().await
            .map_err(|e| SesError::SendRawEmail(format!("{}", DisplayErrorContext(e))))?;

        Ok(res.message_id.unwrap_or_default())
    }

    pub async fn send_simple(
        &self,
        from: &str,
        sbj: &str,
        tos: Vec<String>,
        ccs: Option<Vec<String>>,
        bccs: Option<Vec<String>>,
        content: &str,
    ) -> Result<String, SesError> {
        let dest = Destination::builder()
            .set_to_addresses(Some(tos))
            .set_cc_addresses(ccs)
            .set_bcc_addresses(bccs)
            .build();

        let subj = Content::builder().data(sbj).charset("UTF-8").build()
            .map_err(|e| SesError::SendSimpleEmail(format!("{}", DisplayErrorContext(&e))))?;
        let body_cnt = Content::builder().data(content).charset("UTF-8").build()
            .map_err(|e| SesError::SendSimpleEmail(format!("{}", DisplayErrorContext(&e))))?;
        let body = Body::builder().html(body_cnt).build();
        let msg = Message::builder().subject(subj).body(body).build();
        let email_content = EmailContent::builder().simple(msg).build();

        let res = self.client.send_email()
            .from_email_address(from)
            .destination(dest)
            .content(email_content)
            .send().await
            .map_err(|e| SesError::SendSimpleEmail(format!("{}", DisplayErrorContext(e))))?;

        Ok(res.message_id.unwrap_or_default())
    }

    pub async fn send_template_with_bcc(
        &self,
        template: &str,
        data: String,
        from: &str,
        tos: Vec<String>,
        ccs: Option<Vec<String>>,
        bccs: Option<Vec<String>>,
    ) -> Result<String, SesError> {
        let dest = Destination::builder()
            .set_to_addresses(Some(tos))
            .set_cc_addresses(ccs)
            .set_bcc_addresses(bccs)
            .build();

        let email_content = EmailContent::builder()
            .template(
                Template::builder()
                    .template_name(template)
                    .template_data(data)
                    .build(),
            )
            .build();

        let res = self.client.send_email()
            .from_email_address(from)
            .destination(dest)
            .content(email_content)
            .send().await
            .map_err(|e| SesError::SendTemplateEmail(format!("{}", DisplayErrorContext(e))))?;

        Ok(res.message_id.unwrap_or_default())
    }

    pub async fn send_template(
        &self,
        template: &str,
        data: String,
        from: &str,
        tos: Vec<String>,
    ) -> Result<String, SesError> {
        self.send_template_with_bcc(template, data, from, tos, None, None)
            .await
    }

    /// Send bulk emails with prebuilt BulkEmailContent.
    /// 
    /// # Arguments
    /// 
    /// * bec - the BulkEmailContent built either via stored-template name or inline template text and data
    /// * usrds - user-specific datamap serialised as a JSON string
    /// * from - the From email address
    /// 
    /// # Return - a string 'Success' if all sent, else a list of failed emails errors
    /// 
    pub async fn send_bulk_emails(
        &self,
        bec: BulkEmailContent,
        usrds: Vec<BulkUserData>,
        from: &str,
    ) -> Result<String, SesError> {
        let bees: Vec<BulkEmailEntry> = usrds
            .into_iter()
            .map(|ud| {
                BulkEmailEntry::builder()
                    .destination(Destination::builder().to_addresses(ud.email).build())
                    .replacement_email_content(
                        ReplacementEmailContent::builder()
                            .replacement_template(
                                ReplacementTemplate::builder()
                                    .replacement_template_data(ud.ds)
                                    .build(),
                            )
                            .build(),
                    )
                    .build()
            })
            .collect();

        let res = self.client.send_bulk_email()
            .from_email_address(from)
            .default_content(bec)
            .set_bulk_email_entries(Some(bees))
            .send().await;

        match res {
            Ok(r) => {
                let mut has_error = false;
                let mut error_msgs: HashSet<String> = HashSet::new();
                for (x, result) in r.bulk_email_entry_results().iter().enumerate() {
                    if result.message_id.is_none() {
                        eprintln!("#{} failed: {:?}", x, result.error());
                        has_error = true;
                        error_msgs.insert(result.error().unwrap_or_default().to_owned());
                    }
                }
                if has_error {
                    Err(SesError::SendTemplateEmail(format!("{error_msgs:?}")))
                } else {
                    Ok("Success".to_string())
                }
            }
            Err(e) => Err(SesError::SendTemplateEmail(format!(
                "{}",
                DisplayErrorContext(e)
            ))),
        }
    }

    /// Send bulk emails with stored template.
    ///
    /// # Arguments
    ///
    /// * template - the stored template name
    /// * dfds - default datamap serialized as a string
    /// * usrds - user-specific datamap serialized as a string
    /// * from - From email address
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let uds: Vec<UserData> = vec![...]; // UserData{email: String, ds: String}
    /// let ds = serde_json::to_string(json!({"name": "aa"}));
    /// let c = ses.get_ses_client().await;
    /// let msg_id = c.send_bulk_inline("Template1", ds, uds, "from@domain.com").await?;
    /// ```
    ///
    pub async fn send_bulk_template(
        &self,
        template: &str,
        dfds: String,
        usrds: Vec<BulkUserData>,
        from: &str,
    ) -> Result<String, SesError> {
        let bec = BulkEmailContent::builder()
            .template(
                Template::builder()
                    .template_name(template)
                    .template_data(dfds)
                    .build(),
            )
            .build();

        self.send_bulk_emails(bec, usrds, from).await
    }

    /// Send bulk emails with inline template
    /// 
    /// # Arguments
    /// 
    /// * subject - the subject line
    /// * html - the template content as html
    /// * text - the template content as text
    /// * dfds - default datamap serialized as a string
    /// * usrds - user-specific datamap serialized as a string
    /// * from - From email address
    ///
    pub async fn send_bulk_inline_template(
        &self,
        subject: &str,
        html: &str,
        text: &str,
        dfds: String,
        usrds: Vec<BulkUserData>,
        from: &str,
    ) -> Result<String, SesError> {
        let bec = BulkEmailContent::builder()
            .template(
                Template::builder()
                    .template_content(
                        EmailTemplateContent::builder()
                            .subject(subject)
                            .html(html)
                            .text(text)
                            .build(),
                    )
                    .template_data(dfds)
                    .build(),
            )
            .build();

        self.send_bulk_emails(bec, usrds, from).await
    }
}

pub static SNS: OnceCell<SesClient> = OnceCell::const_new();

pub async fn get_ses_client() -> &'static SesClient {
    SNS.get_or_init(|| async { SesClient::new().await }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_contact_lists() {
        let c = get_ses_client().await;
        let re1 = c.list_contact_lists().await;
        if let Ok(cs) = re1 {
            println!("Contact Lists: {:?}", cs);
        } else {
            assert!(false, "Error list_contact_lists: {:?}", re1);
        }
    }

    #[tokio::test]
    async fn test_list_templates() {
        let c = get_ses_client().await;

        let re1 = c.list_email_templates().await;
        if let Ok(ts) = re1 {
            println!("Templates: {:?}", ts); // cargo test -- --nocapture
        } else {
            assert!(false, "Error list_email_templates: {:?}", re1);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_send_bulk_inline_template() {
        let subject = "Test my inline template bulk email";
        let html = r##"<h1>Hello, {{name}}</h1><p style="color:red">Shared string is '{{msg}}'.</p>"##;
        let text = "Hello, {{name}}, Shared string is '{{msg}}'.";
        let dfds = r##"{"msg":"World"}"##.to_string();
        let usrds: Vec<BulkUserData> = vec![
            BulkUserData{ email: "qywen@hotmail.com".to_string(), ds: r##"{"name":"Qy"}"##.to_string() },
            BulkUserData{ email: "suinova@gmail.com".to_string(), ds: r##"{"name":"Suinova"}"##.to_string() },
        ];
        let c = get_ses_client().await;
        let res = c.send_bulk_inline_template(subject, html, text, dfds, usrds, "no-reply@intercci.com").await;
        println!("{:?}", res);
    }
}
