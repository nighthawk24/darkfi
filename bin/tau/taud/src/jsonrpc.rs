use async_std::sync::{Arc, Mutex};
use std::{fs::create_dir_all, path::PathBuf};

use async_trait::async_trait;
use fxhash::FxHashMap;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use darkfi::{
    net,
    rpc::{
        jsonrpc::{ErrorCode, JsonError, JsonRequest, JsonResult},
        server::RequestHandler,
    },
    util::{expand_path, Timestamp},
    Error,
};

use crate::{
    error::{to_json_result, TaudError, TaudResult},
    month_tasks::MonthTasks,
    task_info::{Comment, TaskInfo},
    util::Workspace,
};

pub struct JsonRpcInterface {
    dataset_path: PathBuf,
    notify_queue_sender: async_channel::Sender<TaskInfo>,
    nickname: String,
    workspace: Arc<Mutex<String>>,
    configured_ws: FxHashMap<String, Workspace>,
    p2p: net::P2pPtr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BaseTaskInfo {
    title: String,
    desc: String,
    assign: Vec<String>,
    project: Vec<String>,
    due: Option<Timestamp>,
    rank: Option<f32>,
}

#[async_trait]
impl RequestHandler for JsonRpcInterface {
    async fn handle_request(&self, req: JsonRequest) -> JsonResult {
        if !req.params.is_array() {
            return JsonError::new(ErrorCode::InvalidParams, None, req.id).into()
        }

        let params = req.params.as_array().unwrap();

        let rep = match req.method.as_str() {
            Some("add") => self.add(params).await,
            Some("get_ids") => self.get_ids(params).await,
            Some("update") => self.update(params).await,
            Some("set_state") => self.set_state(params).await,
            Some("set_comment") => self.set_comment(params).await,
            Some("get_task_by_id") => self.get_task_by_id(params).await,
            Some("switch_ws") => self.switch_ws(params).await,
            Some("get_ws") => self.get_ws(params).await,
            Some("export") => self.export_to(params).await,
            Some("import") => self.import_from(params).await,
            Some("get_stop_tasks") => self.get_stop_tasks(params).await,
            Some("ping") => self.pong(params).await,
            Some("get_info") => self.get_info(params).await,
            Some(_) | None => return JsonError::new(ErrorCode::MethodNotFound, None, req.id).into(),
        };

        to_json_result(rep, req.id)
    }
}

impl JsonRpcInterface {
    pub fn new(
        dataset_path: PathBuf,
        notify_queue_sender: async_channel::Sender<TaskInfo>,
        nickname: String,
        workspace: Arc<Mutex<String>>,
        configured_ws: FxHashMap<String, Workspace>,
        p2p: net::P2pPtr,
    ) -> Self {
        Self { dataset_path, nickname, workspace, configured_ws, notify_queue_sender, p2p }
    }

    // RPCAPI:
    // Replies to a ping method.
    // --> {"jsonrpc": "2.0", "method": "ping", "params": [], "id": 42}
    // <-- {"jsonrpc": "2.0", "result": "pong", "id": 42}
    async fn pong(&self, _params: &[Value]) -> TaudResult<Value> {
        Ok(json!("pong"))
    }

    // RPCAPI:
    // Retrieves P2P network information.
    // --> {"jsonrpc": "2.0", "method": "get_info", "params": [], "id": 42}
    // <-- {"jsonrpc": "2.0", result": {"nodeID": [], "nodeinfo": [], "id": 42}
    async fn get_info(&self, _params: &[Value]) -> TaudResult<Value> {
        let resp = self.p2p.get_info().await;
        Ok(resp)
    }

    // RPCAPI:
    // Add new task and returns `true` upon success.
    // --> {"jsonrpc": "2.0", "method": "add",
    //      "params":
    //          [{
    //          "title": "..",
    //          "desc": "..",
    //          assign: [..],
    //          project: [..],
    //          "due": ..,
    //          "rank": ..
    //          }],
    //      "id": 1
    //      }
    // <-- {"jsonrpc": "2.0", "result": true, "id": 1}
    async fn add(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::add() params {:?}", params);

        let task: BaseTaskInfo = serde_json::from_value(params[0].clone())?;
        let ws = self.workspace.lock().await.clone();
        let mut new_task: TaskInfo = TaskInfo::new(
            ws,
            &task.title,
            &task.desc,
            &self.nickname,
            task.due,
            task.rank,
            &self.dataset_path,
        )?;
        new_task.set_project(&task.project);
        new_task.set_assign(&task.assign);

        self.notify_queue_sender.send(new_task).await.map_err(Error::from)?;
        Ok(json!(true))
    }

    // RPCAPI:
    // List tasks
    // --> {"jsonrpc": "2.0", "method": "get_ids", "params": [], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": [task_id, ...], "id": 1}
    async fn get_ids(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::get_ids() params {:?}", params);
        let ws = self.workspace.lock().await.clone();
        let tasks = MonthTasks::load_current_tasks(&self.dataset_path, ws, false)?;
        let task_ids: Vec<u32> = tasks.iter().map(|task| task.get_id()).collect();
        Ok(json!(task_ids))
    }

    // RPCAPI:
    // Update task and returns `true` upon success.
    // --> {"jsonrpc": "2.0", "method": "update", "params": [task_id, {"title": "new title"} ], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": true, "id": 1}
    async fn update(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::update() params {:?}", params);

        if params.len() != 2 {
            return Err(TaudError::InvalidData("len of params should be 2".into()))
        }
        let ws = self.workspace.lock().await.clone();

        let task = self.check_params_for_update(&params[0], &params[1], ws)?;
        self.notify_queue_sender.send(task).await.map_err(Error::from)?;
        Ok(json!(true))
    }

    // RPCAPI:
    // Set state for a task and returns `true` upon success.
    // --> {"jsonrpc": "2.0", "method": "set_state", "params": [task_id, state], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": true, "id": 1}
    async fn set_state(&self, params: &[Value]) -> TaudResult<Value> {
        // Allowed states for a task
        let states = ["stop", "start", "open", "pause"];

        debug!(target: "tau", "JsonRpc::set_state() params {:?}", params);

        if params.len() != 2 {
            return Err(TaudError::InvalidData("len of params should be 2".into()))
        }

        let state: String = serde_json::from_value(params[1].clone())?;
        let ws = self.workspace.lock().await.clone();

        let mut task: TaskInfo = self.load_task_by_id(&params[0], ws)?;

        if states.contains(&state.as_str()) {
            task.set_state(&state);
            task.set_event("state", &self.nickname, &state);
        }

        self.notify_queue_sender.send(task).await.map_err(Error::from)?;

        Ok(json!(true))
    }

    // RPCAPI:
    // Set comment for a task and returns `true` upon success.
    // --> {"jsonrpc": "2.0", "method": "set_comment", "params": [task_id, comment_content], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": true, "id": 1}
    async fn set_comment(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::set_comment() params {:?}", params);

        if params.len() != 2 {
            return Err(TaudError::InvalidData("len of params should be 3".into()))
        }

        let comment_content: String = serde_json::from_value(params[1].clone())?;
        let ws = self.workspace.lock().await.clone();

        let mut task: TaskInfo = self.load_task_by_id(&params[0], ws)?;
        task.set_comment(Comment::new(&comment_content, &self.nickname));
        task.set_event("comment", &self.nickname, &comment_content);

        self.notify_queue_sender.send(task).await.map_err(Error::from)?;

        Ok(json!(true))
    }

    // RPCAPI:
    // Get a task by id.
    // --> {"jsonrpc": "2.0", "method": "get_task_by_id", "params": [task_id], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "task", "id": 1}
    async fn get_task_by_id(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::get_task_by_id() params {:?}", params);

        if params.len() != 1 {
            return Err(TaudError::InvalidData("len of params should be 1".into()))
        }
        let ws = self.workspace.lock().await.clone();

        let task: TaskInfo = self.load_task_by_id(&params[0], ws)?;

        Ok(json!(task))
    }

    // RPCAPI:
    // Get all tasks.
    // --> {"jsonrpc": "2.0", "method": "get_all_tasks", "params": [task_id], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "task", "id": 1}
    async fn get_stop_tasks(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::get_all_tasks() params {:?}", params);

        if params.len() != 1 {
            return Err(TaudError::InvalidData("len of params should be 1".into()))
        }
        if !params[0].is_i64() {
            return Err(TaudError::InvalidData("Invalid month".into()))
        }
        let month = Timestamp(params[0].as_i64().unwrap());
        let ws = self.workspace.lock().await.clone();

        let tasks = MonthTasks::load_stop_tasks(&self.dataset_path, ws, &month)?;

        Ok(json!(tasks))
    }

    // RPCAPI:
    // Switch tasks workspace.
    // --> {"jsonrpc": "2.0", "method": "switch_ws", "params": [workspace], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "true", "id": 1}
    async fn switch_ws(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::switch_ws() params {:?}", params);

        if params.len() != 1 {
            return Err(TaudError::InvalidData("len of params should be 1".into()))
        }

        if !params[0].is_string() {
            return Err(TaudError::InvalidData("Invalid workspace".into()))
        }

        let ws = params[0].as_str().unwrap().to_string();
        let mut s = self.workspace.lock().await;

        if self.configured_ws.contains_key(&ws) {
            *s = ws
        } else {
            warn!("Workspace \"{}\" is not configured", ws);
        }

        Ok(json!(true))
    }

    // RPCAPI:
    // Get workspace.
    // --> {"jsonrpc": "2.0", "method": "get_ws", "params": [], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "workspace", "id": 1}
    async fn get_ws(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::switch_ws() params {:?}", params);
        let ws = self.workspace.lock().await.clone();

        Ok(json!(ws))
    }

    // RPCAPI:
    // Export tasks.
    // --> {"jsonrpc": "2.0", "method": "export_to", "params": [path], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "true", "id": 1}
    async fn export_to(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::export_to() params {:?}", params);

        if params.len() != 1 {
            return Err(TaudError::InvalidData("len of params should be 1".into()))
        }

        if !params[0].is_string() {
            return Err(TaudError::InvalidData("Invalid path".into()))
        }

        let ws = self.workspace.lock().await.clone();
        let path = expand_path(params[0].as_str().unwrap())?.join("exported_tasks");
        // mkdir datastore_path if not exists
        create_dir_all(path.join("month")).map_err(Error::from)?;
        create_dir_all(path.join("task")).map_err(Error::from)?;

        let tasks = MonthTasks::load_current_tasks(&self.dataset_path, ws, true)?;

        for task in tasks {
            task.save(&path)?;
        }

        Ok(json!(true))
    }

    // RPCAPI:
    // Import tasks.
    // --> {"jsonrpc": "2.0", "method": "import_from", "params": [path], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": "true", "id": 1}
    async fn import_from(&self, params: &[Value]) -> TaudResult<Value> {
        debug!(target: "tau", "JsonRpc::import_from() params {:?}", params);

        if params.len() != 1 {
            return Err(TaudError::InvalidData("len of params should be 1".into()))
        }

        if !params[0].is_string() {
            return Err(TaudError::InvalidData("Invalid path".into()))
        }

        let ws = self.workspace.lock().await.clone();
        let path = expand_path(params[0].as_str().unwrap())?.join("exported_tasks");
        let tasks = MonthTasks::load_current_tasks(&path, ws, true)?;

        for task in tasks {
            self.notify_queue_sender.send(task).await.map_err(Error::from)?;
        }
        Ok(json!(true))
    }

    fn load_task_by_id(&self, task_id: &Value, ws: String) -> TaudResult<TaskInfo> {
        let task_id: u64 = serde_json::from_value(task_id.clone())?;
        let tasks = MonthTasks::load_current_tasks(&self.dataset_path, ws, false)?;
        let task = tasks.into_iter().find(|t| (t.get_id() as u64) == task_id);

        task.ok_or(TaudError::InvalidId)
    }

    fn check_params_for_update(
        &self,
        task_id: &Value,
        fields: &Value,
        ws: String,
    ) -> TaudResult<TaskInfo> {
        let mut task: TaskInfo = self.load_task_by_id(task_id, ws)?;

        if !fields.is_object() {
            return Err(TaudError::InvalidData("Invalid task's data".into()))
        }

        let fields = fields.as_object().unwrap();

        if fields.contains_key("title") {
            let title = fields.get("title").unwrap().clone();
            let title: String = serde_json::from_value(title)?;
            if !title.is_empty() {
                task.set_title(&title);
                task.set_event("title", &self.nickname, &title);
            }
        }

        if fields.contains_key("desc") {
            let description = fields.get("desc");
            if let Some(description) = description {
                let description: Option<String> = serde_json::from_value(description.clone())?;
                if description.is_some() {
                    let desc = description.unwrap();
                    task.set_desc(&desc);
                    task.set_event("desc", &self.nickname, &desc);
                }
            }
        }

        if fields.contains_key("rank") {
            let rank_opt = fields.get("rank");
            if let Some(rank) = rank_opt {
                let rank: Option<f32> = serde_json::from_value(rank.clone())?;
                if rank.is_some() {
                    task.set_rank(rank);
                    task.set_event("rank", &self.nickname, &rank.unwrap().to_string());
                }
            }
        }

        if fields.contains_key("due") {
            let due = fields.get("due").unwrap().clone();
            let due: Option<Option<Timestamp>> = serde_json::from_value(due)?;
            if let Some(d) = due {
                task.set_due(d);
                if d.is_some() {
                    task.set_event("due", &self.nickname, &d.unwrap().0.to_string());
                }
            }
        }

        if fields.contains_key("assign") {
            let assign = fields.get("assign").unwrap().clone();
            let assign: Vec<String> = serde_json::from_value(assign)?;
            if !assign.is_empty() {
                task.set_assign(&assign);
                task.set_event("assign", &self.nickname, &assign.join(", "));
            }
        }

        if fields.contains_key("project") {
            let project = fields.get("project").unwrap().clone();
            let project: Vec<String> = serde_json::from_value(project)?;
            if !project.is_empty() {
                task.set_project(&project);
                task.set_event("project", &self.nickname, &project.join(", "));
            }
        }

        Ok(task)
    }
}
