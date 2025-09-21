--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local ngx     = ngx
local core    = require("apisix.core")
local plugin  = require("apisix.plugin")
local sub_str = string.sub
local jwt     = require("resty.jwt")


local schema = {
    type = "object",
    properties = {
        keys = { type = "array", minItems = 1 },
        header = { type = "string", default = "authorization" },
    },
    required = { "keys" },
}

-- local metadata_schema = {
--     type = "object",
--     properties = {
--         ikey = { type = "number", minimum = 0 },
--         skey = { type = "string" },
--     },
--     required = { "ikey", "skey" },
-- }

local plugin_name = "jwt-header-plugin"

local _M = {
    version = 0.1,
    priority = 89,
    name = plugin_name,
    schema = schema,
    -- metadata_schema = metadata_schema,
}


function _M.check_schema(conf, schema_type)
    return core.schema.check(schema, conf)
end

function _M.init()
    -- call this function when plugin is loaded
    local attr = plugin.plugin_attr(plugin_name)
    if attr then
        core.log.info(plugin_name, " get plugin attr val: ", attr.val)
    end
end

function _M.destroy()
    -- call this function when plugin is unloaded
end

local function fetch_jwt_token(conf, ctx)
    local token = core.request.header(ctx, conf.header)
    if token then
        local prefix = sub_str(token, 1, 7)
        if prefix == 'Bearer ' or prefix == 'bearer ' then
            return sub_str(token, 8)
        end

        return token
    end
end

local function base64url_decode(str)
    local b64 = str:gsub("-", "+"):gsub("_", "/")
    local padding = 4 - (#b64 % 4)
    b64 = b64 .. string.rep("=", padding)
    return ngx.decode_base64(b64)
end

local function decode_jwt(token)
    local segments = {}
    for segment in token:gmatch("([^.]+)") do
        table.insert(segments, segment)
    end
    if #segments ~= 3 then
        return nil
    end

    -- local header = base64url_decode(segments[1])
    local payload = base64url_decode(segments[2])

    return payload
end


function _M.rewrite(conf, ctx)
    core.log.warn("plugin rewrite phase, conf: ", core.json.encode(conf))
    local token = fetch_jwt_token(conf, ctx)
    if token == nil then
        core.log.warn("JWT token not providen in headder")
        return
    end
    core.log.warn("token==>", token)

    local payload = decode_jwt(token)
    if payload == nil then
        core.log.warn("invalid jwt provided")
        return
    end
    core.log.warn("payload==>", payload)
    local lua_payload_table = core.json.decode(payload)
    local keys = conf.keys

    for i = 1, #keys do
        local element = keys[i]
        core.log.warn("Element", i, ":", element)
        if lua_payload_table[element] ~= nil then
            core.request.set_header(element, lua_payload_table[element])
        end
    end

    core.log.warn("conf_type: ", ctx.conf_type)
    core.log.warn("conf_id: ", ctx.conf_id)
    core.log.warn("conf_version: ", ctx.conf_version)
end

local function hello()
    local args = ngx.req.get_uri_args()
    if args["json"] then
        return 200, { msg = "world" }
    else
        return 200, "world\n"
    end
end


function _M.control_api()
    return {
        {
            methods = { "GET" },
            uris = { "/v1/plugin/test-plugin/hello" },
            handler = hello,
        }
    }
end

return _M