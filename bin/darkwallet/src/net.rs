use darkfi_serial::{deserialize, Decodable, Encodable, SerialDecodable};
use std::{
    io::Cursor,
    sync::{atomic::Ordering, mpsc},
    thread,
};

use crate::{
    error::{Error, Result},
    scene::{PropertyType, PropertyValue, SceneGraphPtr, SceneNodeId, SceneNodeType, Slot, SlotId},
};

#[derive(Debug, SerialDecodable)]
#[repr(u8)]
enum Command {
    Hello = 0,
    AddNode = 1,
    RemoveNode = 9,
    RenameNode = 23,
    LookupNodeId = 12,
    AddProperty = 11,
    LinkNode = 2,
    UnlinkNode = 8,
    GetInfo = 19,
    GetChildren = 4,
    GetParents = 5,
    GetProperties = 3,
    GetProperty = 6,
    SetProperty = 7,
    GetSignals = 14,
    RegisterSlot = 15,
    UnregisterSlot = 16,
    LookupSlotId = 17,
    GetSlots = 18,
    GetMethods = 20,
    GetMethod = 21,
    CallMethod = 22,
}

pub struct ZeroMQAdapter {
    // req-reply commands
    req_socket: zmq::Socket,
    // We cannot share zmq sockets across threads, and we cannot quickly spawn
    // pub sockets due to address reuse errors.
    slot_sender: mpsc::SyncSender<Vec<u8>>,
    slot_recvr: Option<mpsc::Receiver<Vec<u8>>>,
    scene_graph: SceneGraphPtr,
}

impl ZeroMQAdapter {
    pub fn new(scene_graph: SceneGraphPtr) -> Self {
        let zmq_ctx = zmq::Context::new();
        let req_socket = zmq_ctx.socket(zmq::REP).unwrap();
        req_socket.set_ipv6(true).unwrap();
        req_socket.bind("tcp://*:9484").unwrap();

        let (slot_sender, slot_recvr) = mpsc::sync_channel(100);

        Self { req_socket, slot_sender, slot_recvr: Some(slot_recvr), scene_graph }
    }

    pub fn poll(&mut self) {
        let rx = std::mem::take(&mut self.slot_recvr).unwrap();
        let _ = thread::spawn(move || {
            let zmq_ctx = zmq::Context::new();
            let pub_socket = zmq_ctx.socket(zmq::PUB).unwrap();
            pub_socket.set_ipv6(true).unwrap();
            pub_socket.bind("tcp://*:9485").unwrap();

            loop {
                let user_data = rx.recv().unwrap();
                pub_socket.send(&user_data, 0).unwrap();
            }
        });

        loop {
            // https://github.com/johnliu55tw/rust-zmq-poller/blob/master/src/main.rs
            let mut items = [self.req_socket.as_poll_item(zmq::POLLIN)];
            // Poll forever
            let _rc = zmq::poll(&mut items, -1).unwrap();

            // Rust borrow checker things
            let is_item0_readable = items[0].is_readable();
            drop(items);

            if is_item0_readable {
                let req = self.req_socket.recv_multipart(zmq::DONTWAIT).unwrap();

                assert_eq!(req[0].len(), 1);
                assert_eq!(req.len(), 2);
                let cmd = deserialize(&req[0]).unwrap();
                let payload = req[1].clone();

                match self.process_request(cmd, payload) {
                    Ok(reply) => {
                        // [errc:1] [reply]
                        self.req_socket.send_multipart(&[vec![0], reply], zmq::DONTWAIT).unwrap();
                    }
                    Err(err) => {
                        let errc = err as u8;
                        warn!(target: "req", "errc {}: {}", errc, err);
                        self.req_socket
                            .send_multipart(&[vec![errc], vec![]], zmq::DONTWAIT)
                            .unwrap();
                    }
                }
            }
        }
    }

    fn process_request(&self, cmd: Command, payload: Vec<u8>) -> Result<Vec<u8>> {
        let mut scene_graph = self.scene_graph.lock().unwrap();
        let mut cur = Cursor::new(&payload);
        let mut reply = vec![];
        match cmd {
            Command::Hello => {
                debug!(target: "req", "hello()");
                assert_eq!(payload.len(), 0);
                "hello".encode(&mut reply).unwrap();
            }
            Command::GetInfo => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                node.name.encode(&mut reply).unwrap();
                node.typ.encode(&mut reply).unwrap();
            }
            Command::GetChildren => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let children: Vec<_> = node
                    .children
                    .iter()
                    .map(|node_inf| (node_inf.name.clone(), node_inf.id, node_inf.typ))
                    .collect();
                children.encode(&mut reply).unwrap();
            }
            Command::GetParents => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let parents: Vec<_> = node
                    .parents
                    .iter()
                    .map(|node_inf| (node_inf.name.clone(), node_inf.id, node_inf.typ))
                    .collect();
                parents.encode(&mut reply).unwrap();
            }
            Command::GetProperties => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let mut props = vec![];
                for prop in &node.props {
                    props.push((prop.name.clone(), prop.get_type() as u8));
                }
                props.encode(&mut reply).unwrap();
            }
            Command::GetProperty => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let prop_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, node_id, prop_name);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let prop = node.get_property(&prop_name).ok_or(Error::PropertyNotFound)?;
                match &prop.val {
                    PropertyValue::Null => {
                        0u8.encode(&mut reply).unwrap();
                    }
                    PropertyValue::Buffer(_) => {
                        1u8.encode(&mut reply).unwrap();
                    }
                    PropertyValue::Bool(val) => {
                        3u8.encode(&mut reply).unwrap();
                        let val = val.load(Ordering::SeqCst);
                        val.encode(&mut reply).unwrap();
                    }
                    PropertyValue::Uint32(val) => {
                        2u8.encode(&mut reply).unwrap();
                        let val = val.load(Ordering::SeqCst);
                        val.encode(&mut reply).unwrap();
                    }
                    PropertyValue::Float32(val) => {
                        4u8.encode(&mut reply).unwrap();
                        let val = val.load(Ordering::SeqCst);
                        val.encode(&mut reply).unwrap();
                    }
                    PropertyValue::Str(val) => {
                        5u8.encode(&mut reply).unwrap();
                        let val = val.lock().unwrap();
                        val.encode(&mut reply).unwrap();
                    }
                    PropertyValue::SceneNodeId(val) => {
                        6u8.encode(&mut reply).unwrap();
                        let val = val.load(Ordering::SeqCst);
                        val.encode(&mut reply).unwrap();
                    }
                };
            }
            Command::AddNode => {
                let node_name = String::decode(&mut cur).unwrap();
                let node_type = SceneNodeType::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {:?})", cmd, node_name, node_type);

                let node_id = scene_graph.add_node(&node_name, node_type).id;
                node_id.encode(&mut reply).unwrap();
            }
            Command::RemoveNode => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);
                scene_graph.remove_node(node_id)?;
            }
            Command::RenameNode => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let node_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);
                scene_graph.rename_node(node_id, node_name)?;
            }
            Command::LookupNodeId => {
                let node_path: String = deserialize(&payload).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_path);
                let node_id = scene_graph.lookup_node_id(&node_path).ok_or(Error::NodeNotFound)?;
                node_id.encode(&mut reply).unwrap();
            }
            Command::AddProperty => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let prop_name = String::decode(&mut cur).unwrap();
                let prop_type = PropertyType::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {}, {:?})", cmd, node_id, prop_name, prop_type);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;
                node.add_property(prop_name, prop_type)?;
            }
            Command::LinkNode => {
                let child_id = SceneNodeId::decode(&mut cur).unwrap();
                let parent_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, child_id, parent_id);
                scene_graph.link(child_id, parent_id)?;
            }
            Command::UnlinkNode => {
                let child_id = SceneNodeId::decode(&mut cur).unwrap();
                let parent_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, child_id, parent_id);
                scene_graph.unlink(child_id, parent_id)?;
            }
            Command::SetProperty => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let prop_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, node_id, prop_name);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;
                let prop = node.get_property(&prop_name).ok_or(Error::PropertyNotFound)?;

                match prop.get_type() {
                    PropertyType::Null => {}
                    PropertyType::Buffer => {
                        let val = Vec::<u8>::decode(&mut cur).unwrap();
                        prop.set_buf(val)?;
                    }
                    PropertyType::Bool => {
                        let val = bool::decode(&mut cur).unwrap();
                        prop.set_bool(val)?;
                    }
                    PropertyType::Uint32 => {
                        let val = u32::decode(&mut cur).unwrap();
                        prop.set_u32(val)?;
                    }
                    PropertyType::Float32 => {
                        let val = f32::decode(&mut cur).unwrap();
                        prop.set_f32(val)?;
                    }
                    PropertyType::Str => {
                        let val = String::decode(&mut cur).unwrap();
                        prop.set_str(val)?;
                    }
                    PropertyType::SceneNodeId => {
                        let val = SceneNodeId::decode(&mut cur).unwrap();
                        prop.set_node_id(val)?;
                    }
                }
            }
            Command::GetSignals => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;

                let mut sigs = vec![];
                for sig in &node.sigs {
                    sigs.push(sig.name.clone());
                }
                sigs.encode(&mut reply).unwrap();
            }
            Command::RegisterSlot => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let sig_name = String::decode(&mut cur).unwrap();
                let slot_name = String::decode(&mut cur).unwrap();
                let user_data = Vec::<u8>::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {}, {}, {:?})", cmd, node_id, sig_name, slot_name, user_data);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;

                let sender = self.slot_sender.clone();
                let slot = Slot {
                    name: slot_name,
                    func: Box::new(move || {
                        sender.send(user_data.clone()).unwrap();
                    }),
                };

                let slot_id = node.register(&sig_name, slot)?;
                slot_id.encode(&mut reply).unwrap();
            }
            Command::UnregisterSlot => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let sig_name = String::decode(&mut cur).unwrap();
                let slot_id = SlotId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {}, {})", cmd, node_id, sig_name, slot_id);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;
                node.unregister(&sig_name, slot_id)?;
            }
            Command::LookupSlotId => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let sig_name = String::decode(&mut cur).unwrap();
                let slot_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {}, {})", cmd, node_id, sig_name, slot_name);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let signal = node.get_signal(&sig_name).ok_or(Error::SignalNotFound)?;
                let slot_id = signal.lookup_slot_id(&slot_name).ok_or(Error::SlotNotFound)?;
                slot_id.encode(&mut reply).unwrap();
            }
            Command::GetSlots => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let sig_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, node_id, sig_name);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let signal = node.get_signal(&sig_name).ok_or(Error::SignalNotFound)?;

                let mut slots = vec![];
                for (slot_id, slot) in signal.get_slots() {
                    slots.push((slot.name.clone(), slot_id));
                }
                slots.encode(&mut reply).unwrap();
            }
            Command::GetMethods => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({})", cmd, node_id);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let method_names: Vec<_> = node.methods.iter().map(|m| m.name.clone()).collect();

                method_names.encode(&mut reply).unwrap();
            }
            Command::GetMethod => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let method_name = String::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {})", cmd, node_id, method_name);

                let node = scene_graph.get_node(node_id).ok_or(Error::NodeNotFound)?;
                let method = node.get_method(&method_name).ok_or(Error::MethodNotFound)?;

                method.args.encode(&mut reply).unwrap();
                method.result.encode(&mut reply).unwrap();
            }
            Command::CallMethod => {
                let node_id = SceneNodeId::decode(&mut cur).unwrap();
                let method_name = String::decode(&mut cur).unwrap();
                let arg_data = Vec::<u8>::decode(&mut cur).unwrap();
                debug!(target: "req", "{:?}({}, {}, ...)", cmd, node_id, method_name);

                let node = scene_graph.get_node_mut(node_id).ok_or(Error::NodeNotFound)?;

                let method_name2 = method_name.clone();
                let (tx, rx) = mpsc::sync_channel::<Result<Vec<u8>>>(0);
                let response_fn = Box::new(move |result| {
                    debug!(target: "req", "processing callmethod for {}:'{}'", node_id, method_name2);
                    tx.send(result).unwrap();
                });
                node.call_method(&method_name, arg_data, response_fn)?;
                drop(scene_graph);

                let result = rx.recv().unwrap();
                debug!(target: "req", "received callmethod for {}:'{}'", node_id, method_name);
                match result {
                    Ok(res_data) => {
                        0u8.encode(&mut reply).unwrap();
                        res_data.encode(&mut reply).unwrap();
                    }
                    Err(err) => {
                        let errc = err as u8;
                        errc.encode(&mut reply).unwrap();
                        0u8.encode(&mut reply).unwrap();
                    }
                }
            }
        }

        Ok(reply)
    }
}