use ldap_parser::ldap::{AuthenticationChoice, ProtocolOp};
use ldap_parser::{parse_ldap_messages, FromBer};
use log::{error, info};
use rasn::der;
use rasn::error::EncodeError;
use rasn_ldap::{BindResponse, LdapMessage, ResultCode};
use std::borrow::Cow;
use std::error::Error;
use std::ops::BitAndAssign;
use std::vec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use self::parser::handle_bind_response;

mod data;
mod index;
mod parser;
mod schema;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("config/log4rs.yml", Default::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:1389").await?;
    info!("LDAP server listening on 127.0.0.1:389");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        info!("Accepted connection from {:?}", addr);

        tokio::spawn(async move {
            let mut buffer = vec![0; 1024];

            match socket.read(&mut buffer).await {
                Ok(n) if n == 0 => return,
                Ok(n) => {
                    info!("Received {} bytes", n);
                    let x = parse_ldap_messages(&buffer);
                    match x {
                        Ok((d, m)) => {
                            info!("Message {:?}", m);
                            for message in m {
                                let message_id = message.message_id;
                                match message.protocol_op {
                                    ProtocolOp::BindRequest(re) => {
                                        let version = re.version;
                                        let authenticartion = re.authentication;
                                        let name = re.name;

                                        match authenticartion {
                                            AuthenticationChoice::Simple(cred) => {
                                                let st =
                                                    unsafe { std::str::from_utf8_unchecked(&cred) };
                                                info!("Cred {}", st);
                                                let encoded_response =
                                                    handle_bind_response(message_id.0).unwrap();
                                                socket.write_all(&encoded_response).await.unwrap();
                                                //#TODO: Send response to clients
                                            }
                                            AuthenticationChoice::Sasl(_) => {
                                                todo!()
                                            }
                                        }
                                    }
                                    ProtocolOp::UnbindRequest => todo!(),
                                    ProtocolOp::SearchRequest(_) => todo!(),
                                    ProtocolOp::SearchResultReference(_) => {
                                        todo!()
                                    }
                                    ProtocolOp::ModifyRequest(_) => todo!(),
                                    ProtocolOp::AddRequest(_) => todo!(),
                                    ProtocolOp::DelRequest(_) => todo!(),
                                    ProtocolOp::ModDnRequest(_) => todo!(),
                                    ProtocolOp::CompareRequest(_) => todo!(),
                                    ProtocolOp::AbandonRequest(_) => todo!(),
                                    ProtocolOp::ExtendedRequest(_) => todo!(),
                                    _ => todo!(),
                                }
                            }
                        }
                        Err(e) => todo!(),
                    }
                }
                Err(e) => {
                    error!("Failed to read from socket: {:?}", e);
                }
            }
        });
    }
}
