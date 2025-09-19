
//   Copyright 2016 otris software AG
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//   This project is hosted at https://github.com/otris

#pragma once

#include <string>

#ifdef EWS_HAS_NOEXCEPT_SPECIFIER
#define EWS_NOEXCEPT noexcept
#else
#define EWS_NOEXCEPT
#endif

// Forward declarations
namespace ews
{
class and_;
class attachment;
class attachment_id;
class attendee;
class basic_credentials;
class body;
class calendar_item;
class connecting_sid;
class contact;
class contains;
class date_time;
class delegate_user;
class distinguished_folder_id;
class duration;
class exception;
class exchange_error;
class folder_id;
class http_error;
class indexed_property_path;
class internet_message_header;
class is_equal_to;
class is_greater_than;
class is_greater_than_or_equal_to;
class is_less_than;
class is_less_than_or_equal_to;
class is_not_equal_to;
class item;
class item_id;
class mailbox;
class message;
class mime_content;
class not_;
class ntlm_credentials;
class or_;
class parse_error;
class property;
class property_path;
class schema_validation_error;
class search_expression;
class soap_fault;
class task;
class update;
class user_id;
struct autodiscover_result;
struct autodiscover_hints;
template <typename T> class basic_service;
bool operator==(const date_time&, const date_time&);
bool operator==(const property_path&, const property_path&);
void set_up() EWS_NOEXCEPT;
void tear_down() EWS_NOEXCEPT;
std::string version();
template <typename T>
autodiscover_result get_exchange_web_services_url(const std::string&,
                                                  const basic_credentials&);
template <typename T>
autodiscover_result get_exchange_web_services_url(const std::string&,
                                                  const basic_credentials&,
                                                  const autodiscover_hints&);
}

// vim:et ts=4 sw=4
