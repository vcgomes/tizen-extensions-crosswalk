// Copyright (c) 2013 Intel Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NOTIFICATION_NOTIFICATION_PARAMETERS_H_
#define NOTIFICATION_NOTIFICATION_PARAMETERS_H_

#include <string>
#include <vector>

namespace picojson {
class value;
}

struct NotificationParameters {
  std::string status_type;

  std::string title;
  std::string content;

  std::string icon_path;

  std::string progress_type;
  int progress_value;

  std::string sub_icon_path;

  std::string background_image_path;
  std::vector<std::string> thumbnails;
};

NotificationParameters ReadNotificationParameters(const picojson::value& v);

#endif  // NOTIFICATION_NOTIFICATION_PARAMETERS_H_
