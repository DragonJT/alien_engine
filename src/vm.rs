
use core::panic;

use crate::runtime_module::*;

#[derive(Debug, Clone)]
pub enum Value {
    I32(i32),
    // later: I64, F32, F64, Ref, etc.
}

impl Value {
    fn as_i32(&self) -> i32 {
        match *self {
            Value::I32(v) => v,
        }
    }
}

pub struct Vm {
    pub runtime: RuntimeModule,
}

#[derive(Debug)]
pub enum VmError {
    StackUnderflow,
    InvalidOpcode { ip: usize, op: u8 },
    BadCallArgCount { expected: usize, got: usize },
    UnexpectedRetVoid,
}

type VmResult<T> = Result<T, VmError>;

struct Frame {
    ip: usize,
    eval: Vec<Value>,
    args: Vec<Value>,
}

impl Vm {
    pub fn exec_method(&mut self, method:RuntimeMethod, args: Vec<Value>) -> VmResult<Option<Value>> {            

        if args.len() != method.sig.param_count as usize{
            return Err(VmError::BadCallArgCount {
                expected: method.sig.param_count as usize,
                got: args.len(),
            });
        }

        match (method.body){
            Some((header, il)) => {
                let mut frame = Frame {
                    ip: 0,
                    eval: Vec::with_capacity(header.maxstack as usize),
                    args,
                };

                while frame.ip < il.len() {
                    let op = il[frame.ip];
                    frame.ip += 1;

                    match op {
                        0x02 => {
                            // ldarg.0
                            let v = frame.args.get(0).cloned().ok_or(VmError::StackUnderflow)?;
                            frame.eval.push(v);
                        }

                        0x16..=0x1E => frame.eval.push(Value::I32((op - 0x16) as i32)),

                        0x1F => {
                            // ldc.i4.s <int8>
                            let imm = il[frame.ip] as i8;
                            frame.ip += 1;
                            frame.eval.push(Value::I32(imm as i32));
                        }

                        0x58 => {
                            // add
                            let b = frame.eval.pop().ok_or(VmError::StackUnderflow)?.as_i32();
                            let a = frame.eval.pop().ok_or(VmError::StackUnderflow)?.as_i32();
                            frame.eval.push(Value::I32(a.wrapping_add(b)));
                        }

                        0x28 => {
                            // call <u32 token> (little-endian)
                            if frame.ip + 4 > il.len() {
                                return Err(VmError::InvalidOpcode { ip: frame.ip - 1, op });
                            }
                            let token = u32::from_le_bytes([
                                il[frame.ip],
                                il[frame.ip + 1],
                                il[frame.ip + 2],
                                il[frame.ip + 3],
                            ]);
                            frame.ip += 4;

                            let callee = self.runtime.get_method_by_token(token);

                            // pop args in reverse, then reverse to correct order
                            let mut call_args = Vec::with_capacity(callee.sig.param_count as usize);
                            for _ in 0..callee.sig.param_count {
                                call_args.push(frame.eval.pop().ok_or(VmError::StackUnderflow)?);
                            }
                            call_args.reverse();

                            let ret = self.exec_method(callee, call_args)?;
                            if let Some(v) = ret {
                                frame.eval.push(v);
                            } else {
                                // void return: nothing pushed
                            }
                        }

                        0x2A => {
                            // ret
                            match method.sig.ret{
                                ElemType::I4 => {
                                    let v = frame.eval.pop().ok_or(VmError::StackUnderflow)?;
                                    return Ok(Some(v));
                                },
                                _ => return Ok(None),
                            }
                        }
                        _ => return Err(VmError::InvalidOpcode { ip: frame.ip - 1, op }),
                    }
                }

                match method.sig.ret{
                    ElemType::Void => {
                        return Ok(None);
                    },
                    _ => { 
                        return Err(VmError::UnexpectedRetVoid);
                    }
                }
            }
            None => {
                match method.name.as_str() {
                    "Print" => {
                        println!("{}", args[0].as_i32());
                        return Ok(None);
                    }
                    _ => {
                        panic!("Unexpected function call");
                    }
                }
            }
        }
    }
}