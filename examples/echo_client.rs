use argparse::ArgumentParser;
use argparse::Store;
use argparse::StoreOption;
use argparse::StoreTrue;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::join;
use futures::StreamExt;
use futures::SinkExt;
use mumble_protocol_2x::control::msgs;
use mumble_protocol_2x::control::ClientControlCodec;
use mumble_protocol_2x::control::ControlPacket;
use mumble_protocol_2x::crypt::ClientCryptState;
use mumble_protocol_2x::voice::VoicePacket;
use mumble_protocol_2x::voice::VoicePacketPayload;
use tokio_rustls::rustls::RootCertStore;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_util::codec::Decoder;
use tokio_util::udp::UdpFramed;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::client::danger::ServerCertVerified;
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }

    fn verify_server_cert(
        &self,
        _: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Option<&[tokio_rustls::rustls::DistinguishedName]> {
        None
    }
}

async fn connect(
    server_addr: SocketAddr,
    server_host: String,
    user_name: String,
    password: Option<String>,
    accept_invalid_cert: bool,
    crypt_state_sender: oneshot::Sender<ClientCryptState>,
) {
    // Wrap crypt_state_sender in Option, so we can call it only once
    let mut crypt_state_sender = Some(crypt_state_sender);

    // Connect to server via TCP
    let stream = TcpStream::connect(&server_addr)
        .await
        .expect("Failed to connect to server:");
    println!("TCP connected..");

    // Wrap the connection in TLS
    let config = if accept_invalid_cert {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned()))
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));
    let domain = server_host.try_into().expect("Invalid DNS name: {}");
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .expect("Failed to connect TLS: {}");
    println!("TLS connected..");

    // Wrap the TLS stream with Mumble's client-side control-channel codec
    let (mut sink, mut stream) = ClientControlCodec::new().framed(tls_stream).split();

    // Handshake (omitting `Version` message for brevity)
    let mut msg = msgs::Authenticate::new();
    msg.set_username(user_name);
    if let Some(password) = password {
        msg.set_password(password);
    }
    msg.set_opus(true);
    sink.send(msg.into()).await.unwrap();

    println!("Logging in..");
    let mut crypt_state = None;

    // Note: A normal application also has to send periodic Ping packets

    // Handle incoming packets
    while let Some(packet) = stream.next().await {
        match packet.unwrap() {
            ControlPacket::TextMessage(mut msg) => {
                println!(
                    "Got message from user with session ID {}: {}",
                    msg.actor(),
                    msg.message()
                );
                // Send reply back to server
                let mut response = msgs::TextMessage::new();
                response.mut_session().push(msg.actor());
                response.set_message(msg.take_message());
                sink.send(response.into()).await.unwrap();
            }
            ControlPacket::CryptSetup(msg) => {
                // Wait until we're fully connected before initiating UDP voice
                crypt_state = Some(ClientCryptState::new_from(
                    msg.key()
                        .try_into()
                        .expect("Server sent private key with incorrect size"),
                    msg.client_nonce()
                        .try_into()
                        .expect("Server sent client_nonce with incorrect size"),
                    msg.server_nonce()
                        .try_into()
                        .expect("Server sent server_nonce with incorrect size"),
                ));
            }
            ControlPacket::ServerSync(_) => {
                println!("Logged in!");
                if let Some(sender) = crypt_state_sender.take() {
                    let _ = sender.send(
                        crypt_state
                            .take()
                            .expect("Server didn't send us any CryptSetup packet!"),
                    );
                }
            }
            ControlPacket::Reject(msg) => {
                println!("Login rejected: {:?}", msg);
            }
            _ => {},
        }
    }
}

async fn handle_udp(
    server_addr: SocketAddr,
    crypt_state: oneshot::Receiver<ClientCryptState>,
) {
    // Bind UDP socket
    let udp_socket = UdpSocket::bind((Ipv6Addr::from(0u128), 0u16))
        .await
        .expect("Failed to bind UDP socket");

    // Wait for initial CryptState
    let crypt_state = match crypt_state.await {
        Ok(crypt_state) => crypt_state,
        // disconnected before we received the CryptSetup packet, oh well
        Err(_) => return,
    };
    println!("UDP ready!");

    // Wrap the raw UDP packets in Mumble's crypto and voice codec (CryptState does both)
    let (mut sink, mut source) = UdpFramed::new(udp_socket, crypt_state).split();

    // Note: A normal application would also send periodic Ping packets, and its own audio
    //       via UDP. We instead trick the server into accepting us by sending it one
    //       dummy voice packet.
    sink.send((
        VoicePacket::Audio {
            _dst: std::marker::PhantomData,
            target: 0,
            session_id: (),
            seq_num: 0,
            payload: VoicePacketPayload::Opus(Bytes::from([0u8; 128].as_ref()), true),
            position_info: None,
        },
        server_addr,
    )).await.unwrap();

    // Handle incoming UDP packets
    while let Some(packet) = source.next().await {
        let (packet, src_addr) = match packet {
            Ok(packet) => packet,
            Err(err) => {
                eprintln!("Got an invalid UDP packet: {}", err);
                // To be expected, considering this is the internet, just ignore it
                continue
            }
        };
        match packet {
            VoicePacket::Ping { .. } => {
                // Note: A normal application would handle these and only use UDP for voice
                //       once it has received one.
                continue
            }
            VoicePacket::Audio {
                seq_num,
                payload,
                position_info,
                ..
            } => {
                // Got audio, naively echo it back
                let reply = VoicePacket::Audio {
                    _dst: std::marker::PhantomData,
                    target: 0,      // normal speech
                    session_id: (), // unused for server-bound packets
                    seq_num,
                    payload,
                    position_info,
                };
                sink.send((reply, src_addr)).await.unwrap();
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Handle command line arguments
    let mut server_host = "".to_string();
    let mut server_port = 64738u16;
    let mut user_name = "EchoBot".to_string();
    let mut password = None;
    let mut accept_invalid_cert = false;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Run the echo client example");
        ap.refer(&mut server_host)
            .add_option(&["--host"], Store, "Hostname of mumble server")
            .required();
        ap.refer(&mut server_port)
            .add_option(&["--port"], Store, "Port of mumble server");
        ap.refer(&mut user_name)
            .add_option(&["--username"], Store, "User name used to connect");
        ap.refer(&mut password)
            .add_option(&["--password"], StoreOption, "Server password used to connect");
        ap.refer(&mut accept_invalid_cert).add_option(
            &["--accept-invalid-cert"],
            StoreTrue,
            "Accept invalid TLS certificates",
        );
        ap.parse_args_or_exit();
    }
    let server_addr = (server_host.as_ref(), server_port)
        .to_socket_addrs()
        .expect("Failed to parse server address")
        .next()
        .expect("Failed to resolve server address");

    // Oneshot channel for setting UDP CryptState from control task
    // For simplicity we don't deal with re-syncing, real applications would have to.
    let (crypt_state_sender, crypt_state_receiver) = oneshot::channel::<ClientCryptState>();

    // Run it
    join!(
        connect(
            server_addr,
            server_host,
            user_name,
            password,
            accept_invalid_cert,
            crypt_state_sender,
        ),
        handle_udp(server_addr, crypt_state_receiver)
    );
}
