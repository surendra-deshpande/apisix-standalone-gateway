local core   = require("apisix.core")
local http   = require("resty.http")
local type   = type
local ipairs = ipairs
local ngx = ngx
local tostring = tostring
local ngx      = ngx
local log = core.log

local schema = {
    type = "object",
    properties = {
        host = {
            type = "string"
        },
        datadome_endpoint = {
            type = "string",
            default = "api.datadome.co"
        },
        module_name = {
            type = "string",
            default = "apisix-openresty"
        },
        module_version = {
            type = "string",
            default = "1.1"
        },
        datadome_server_side_key = {
            type = "string",
        },
        datadome_url_pattern_inclusion = {
            type = "string",
            default = "",
        },
        datadome_url_pattern_exclusion = {
            type = "string",
            default = "\\.(avi|flv|mka|mkv|mov|mp4|mpeg|mpg|mp3|flac|ogg|ogm|opus|wav|webm|webp|bmp|gif|ico|jpeg|jpg|png|svg|svgz|swf|eot|otf|ttf|woff|woff2|css|less|js|map|json)$",
        },
        datadome_timeout = {
            type = "integer",
            default = 200,
        },
    },
    required = {"datadome_server_side_key"}
}


local _M = {
    version = 0.1,
    priority = 10,
    name = "datadome-protect",
    schema = schema,
}

local headers_truncation_size = {
    ['SecCHDeviceMemory'] = 8,
    ['SecCHUAMobile'] = 8,
    ['SecFetchUser'] = 8,
    ['SecCHUAArch'] = 16,
    ['SecCHUAPlatform'] = 32,
    ['SecFetchDest'] = 32,
    ['SecFetchMode'] = 32,
    ['ContentType'] = 64,
    ['SecFetchSite'] = 64,
    ['AcceptCharset'] = 128,
    ['AcceptEncoding'] = 128,
    ['CacheControl'] = 128,
    ['ClientID'] = 128,
    ['Connection'] = 128,
    ['From'] = 128,
    ['Pragma'] = 128,
    ['SecCHUA'] = 128,
    ['SecCHUAModel'] = 128,
    ['TrueClientIP'] = 128,
    ['X-Real-IP'] = 128,
    ['X-Requested-With'] = 128,
    ['AcceptLanguage'] = 256,
    ['SecCHUAFullVersionList'] = 256,
    ['Via'] = 256,
    ['Accept'] = 512,
    ['HeadersList'] = 512,
    ['Origin'] = 512,
    ['ServerName'] = 512,
    ['ServerHostname'] = 512,
    ['Host']  = 512,
    ['XForwardedForIP'] = -512,
    ['UserAgent'] = 768,
    ['Referer'] = 1024,
    ['Request'] = 2048,
  }


function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local constants = {
    api_connection_state = "new",
    http_method = "POST",
    path = "/validate-request",
    keepalive = true,
    ssl = true,
}

local function urlencode(str)
    if str then
      str = ngx.re.gsub(str, '\n', '\r\n', "io")
      str = ngx.re.gsub(str,
                        '([^[:alnum:]-_.~])',
                        function(c) return string.format('%%%02X', string.byte(c[0])) end,
                        "io")
    end
  
    return str
end

local function stringify(params)
    if type(params) == "table" then
      local fields = {}
      for key,value in pairs(params) do
        local keyString = urlencode(tostring(key)) .. '='
        if type(value) == "table" then
          for _, v in ipairs(value) do
            table.insert(fields, keyString .. urlencode(tostring(v)))
          end
        else
          table.insert(fields, keyString .. urlencode(tostring(value)))
        end
      end
      return table.concat(fields, '&')
    end
    return ''
end

local function callDatadome(body,datadomeHeaders,conf)
    local protocol = constants.ssl and 'https://' or 'http://'
    local options = {
        method = constants.http_method,
        ssl_verify = constants.ssl,
        keep_alive = constants.keepalive,
        body = stringify(body),
        headers = datadomeHeaders
    }
  
    local httpc = require("resty.http").new()
    httpc:set_timeout(conf.datadome_timeout)
    local res, err = httpc:request_uri(protocol .. conf.datadome_endpoint .. constants.path, options)
  
    --core.log.error("[DataDome] response", res)
    --core.log.error("[DataDome] response error", err)
    return res, err
end

local function getClientIdAndCookiesLength(request_headers)
    local cookie = request_headers["cookie"] or ""
    local len = string.len(cookie)
    local clientId = nil
    if len > 0 then
      for element in ngx.re.gmatch(cookie, "([^;= ]+)=([^;$]+)", "io") do
        if element[1] == "datadome" then
          clientId = element[2]
          break
        end
      end
    end
    return clientId, len
end

local function getCurrentMicroTime()
    -- we need time up to microseccconds, but at lua we can do up to seconds :( round it
    return tostring(os.time()) .. "000000"
end

local function getHeadersList(request_headers)
    local headers = {}
    for key, _ in pairs(request_headers) do
        table.insert(headers, key)
    end
    return table.concat(headers, ",")
end

function getAuthorizationLen(request_headers)
    return string.len(request_headers["authorization"] or "")
end

local function skipRequestViaRegex(conf)
    -- using ngx.var.uri to get the normalised path just like nginx module: no query string (?) or fragment (#), remove double slashes (//) and URL decode (%)
    -- ngx.var.uri can also have a different value after rewrites
    local url = ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri
  
    if conf.datadome_url_pattern_inclusion then
      if not ngx.re.match(url, conf.datadome_url_pattern_inclusion, "io") then
        return true
      end
    end
  
    if ngx.re.match(url, conf.datadome_url_pattern_exclusion, "io") then
      return true
    end
  
    return false
end

local function parseResponse(response)
    return response.status, response.headers, response.body
end

local function isXDataDomeResponseError(api_response_headers, status)
    if api_response_headers then
      if tonumber(api_response_headers["X-DataDomeResponse"]) == nil then
        ngx.log(ngx.ERR, "[DataDome] Empty X-DataDomeResponse; does not match with API response status:  ", status);
        return true
      elseif tonumber(api_response_headers["X-DataDomeResponse"]) ~= status then
        ngx.log(ngx.ERR, "[DataDome] Invalid X-DataDomeResponse header: " .. api_response_headers["X-DataDomeResponse"] .. "; does not match with API response status: " .. status)
        return true
      else
        ngx.log(ngx.DEBUG, "[DataDome] Valid X-DataDomeResponse header, code: ", status)
      end
    end
    return false
end
  
local function isHttpError(err)
    if err ~= nil then
      if err == "timeout" then
        ngx.log(ngx.DEBUG, "[DataDome] API connection timed out, request skipped")
      else
        ngx.log(ngx.ERR, "[DataDome] The following error occurred while connecting to the API ",err)
      end
      return true
    else
      ngx.log(ngx.DEBUG, "[DataDome] Successful connection to the API")
    end
    return false
end

local function isError(err, api_response_headers, status)
    if isHttpError(err) or isXDataDomeResponseError(api_response_headers, status) then
      return true
    else
      return false
    end
end

local function addRequestHeaders(api_response_headers)
    local request_headers = api_response_headers['X-DataDome-Request-Headers']
  
    if request_headers == nil then
        return
    end
  
    for header_name in ngx.re.gmatch(request_headers, "([^ ]+)", "io") do
        local header_value = api_response_headers[header_name[0]]
        if header_value ~= nil then
            ngx.req.set_header(header_name[0], header_value)
        end
    end
  end
  
local function addResponseHeaders(api_response_headers)
    local response_headers = api_response_headers['X-DataDome-Headers']
  
    if response_headers == nil then
        return
    end
  
    for header_name in ngx.re.gmatch(response_headers, "([^ ]+)", "io") do
        local header_value = api_response_headers[header_name[0]]
        if header_value ~= nil then
            if header_name[0] == 'Set-Cookie' then
                if type(ngx.header["Set-Cookie"]) == "table" then
                    ngx.header["Set-Cookie"] = { header_value, table.unpack(ngx.header["Set-Cookie"]) }
                else
                    ngx.header["Set-Cookie"] = { header_value, ngx.header["Set-Cookie"] }
                end
            else
                ngx.header[header_name[0]] = header_value
            end
        end
    end
  end

local function updateHeaders(api_response_headers)
    addResponseHeaders(api_response_headers)
    addRequestHeaders(api_response_headers)
end

local function getHeaderStringValue(header_value)
    local header_string_value = header_value
  
    if type(header_value) == "table" then
      header_string_value = header_value[1]
    end
  
    return header_string_value
end

local function truncateHeaders(body)
    for header, truncation_size in pairs (headers_truncation_size) do
        if body[header] then
            local header_string_value = getHeaderStringValue(body[header])
            if truncation_size >= 0 then
                body[header] = string.sub(header_string_value,1,truncation_size)
            else  -- backward truncation
                body[header] = string.sub(header_string_value,truncation_size)
            end
        end
    end
end

local function getBodyAndDatadomeHeaders(conf)
    local request_headers = ngx.req.get_headers()
    local clientId, cookieLen = getClientIdAndCookiesLength(request_headers)
    cookieLen = tostring(cookieLen)
    local time_request = getCurrentMicroTime()
    local headers_list = getHeadersList(request_headers)
    local authorization_length = tostring(getAuthorizationLen(request_headers))
    local protocol = string.len(ngx.var.https) == 0 and 'http' or 'https'
  
    local body = {
      ['Key']                = conf.datadome_server_side_key,
      ['IP']                 = ngx.var.remote_addr,
      ['Accept']             = request_headers['accept'],
      ['AcceptCharset']      = request_headers['accept-charset'],
      ['AcceptEncoding']     = request_headers['accept-encoding'],
      ['AcceptLanguage']     = request_headers['accept-language'],
      ['APIConnectionState'] = constants.api_connection_state,
      ['AuthorizationLen']   = authorization_length,
      ['CacheControl']       = request_headers['cache-control'],
      ['ClientID']           = clientId,
      ['Connection']         = request_headers['connection'],
      ['ContentType']        = request_headers['content-type'],
      ['CookiesLen']         = cookieLen,
      ['From']               = request_headers['from'],
      ['HeadersList']        = headers_list,
      ['Host']               = request_headers['host'],
      ['Method']             = ngx.req.get_method(),
      ['ModuleVersion']      = conf.module_version,
      ['Origin']             = request_headers['origin'],
      ['Port']               = ngx.var.server_port,
      ['PostParamLen']       = request_headers['content-length'],
      ['Pragma']             = request_headers['pragma'],
      ['Protocol']           = protocol,
      ['Referer']            = request_headers['referer'],
      ['Request']            = ngx.var.request_uri,
      ['RequestModuleName']  = conf.module_name,
      ['SecCHDeviceMemory']  = request_headers['Sec-CH-Device-Memory'],
      ['SecCHUA']            = request_headers['Sec-CH-UA'],
      ['SecCHUAArch']        = request_headers['Sec-CH-UA-Arch'],
      ['SecCHUAFullVersionList'] = request_headers['Sec-CH-UA-Full-Version-List'],
      ['SecCHUAMobile']      = request_headers['Sec-CH-UA-Mobile'],
      ['SecCHUAModel']       = request_headers['Sec-CH-UA-Model'],
      ['SecCHUAPlatform']    = request_headers['Sec-CH-UA-Platform'],
      ['SecFetchDest']       = request_headers['Sec-Fetch-Dest'],
      ['SecFetchMode']       = request_headers['Sec-Fetch-Mode'],
      ['SecFetchSite']       = request_headers['Sec-Fetch-Site'],
      ['SecFetchUser']       = request_headers['Sec-Fetch-User'],
      ['ServerHostname']     = ngx.var.hostname,
      ['ServerName']         = ngx.var.server_name,
      ['TimeRequest']        = time_request,
      ['TrueClientIP']       = request_headers['true-client-ip'],
      ['UserAgent']          = request_headers['user-agent'],
      ['Via']                = request_headers['via'],
      ['XForwardedForIP']     = request_headers['x-forwarded-for'],
      ['X-Requested-With']   = request_headers['x-requested-with'],
      ['X-Real-IP']          = request_headers['x-real-ip'],
    }
  
    local datadomeHeaders = {
      ["Connection"] = "keep-alive",
      ["Content-Type"] = "application/x-www-form-urlencoded",
    }
  
    if request_headers['x-datadome-clientid'] ~= nil then
      body['ClientID'] = request_headers['x-datadome-clientid']
      datadomeHeaders["X-DataDome-X-Set-Cookie"] = "true"
    else
        body['ClientID'] = clientId
    end
  
    truncateHeaders(body)
  
    return body,datadomeHeaders
end

local function checkStatusCode(status, api_response_body)
    ngx.log(ngx.DEBUG, "[DataDome] HTTP status code for API response: ", status)
  
    if status == 403 or status == 401 or status == 301 or status == 302 then
      ngx.status = status
      ngx.say(api_response_body)
      ngx.exit(status)
    end
end

local function validateRequest(conf)
    if skipRequestViaRegex(conf) then return false end
    local body, datadomeHeaders = getBodyAndDatadomeHeaders(conf)
  
    local res, err = callDatadome(body, datadomeHeaders, conf)
    if not res then return false end
  
    local status, api_response_headers, api_response_body = parseResponse(res)
    if isError(err, api_response_headers, status) then return false end
  
    updateHeaders(api_response_headers)
    checkStatusCode(status, api_response_body);
  
    return true
end

function _M.rewrite(conf, ctx)
    validateRequest(conf)
end

return _M