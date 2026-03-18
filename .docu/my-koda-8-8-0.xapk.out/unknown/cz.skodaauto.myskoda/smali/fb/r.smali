.class public final Lfb/r;
.super Loa/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I

.field public final d:Loa/a;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    iput p1, p0, Lfb/r;->c:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/16 p1, 0xe

    .line 7
    .line 8
    const/16 v0, 0xf

    .line 9
    .line 10
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Ldv/a;

    .line 14
    .line 15
    const/4 v0, 0x5

    .line 16
    invoke-direct {p1, v0}, Ldv/a;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    const/4 p1, 0x6

    .line 23
    const/4 v0, 0x7

    .line 24
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 25
    .line 26
    .line 27
    new-instance p1, Lny/b;

    .line 28
    .line 29
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 33
    .line 34
    return-void

    .line 35
    :pswitch_1
    const/16 p1, 0x1e

    .line 36
    .line 37
    const/16 v0, 0x1f

    .line 38
    .line 39
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 40
    .line 41
    .line 42
    new-instance p1, Lny/b;

    .line 43
    .line 44
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 48
    .line 49
    return-void

    .line 50
    :pswitch_2
    const/16 p1, 0x18

    .line 51
    .line 52
    const/16 v0, 0x19

    .line 53
    .line 54
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 55
    .line 56
    .line 57
    new-instance p1, Lny/b;

    .line 58
    .line 59
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_3
    const/16 p1, 0xe

    .line 66
    .line 67
    const/16 v0, 0xf

    .line 68
    .line 69
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 70
    .line 71
    .line 72
    new-instance p1, Lny/b;

    .line 73
    .line 74
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 78
    .line 79
    return-void

    .line 80
    :pswitch_4
    const/16 p1, 0xd

    .line 81
    .line 82
    const/16 v0, 0xe

    .line 83
    .line 84
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 85
    .line 86
    .line 87
    new-instance p1, Lny/b;

    .line 88
    .line 89
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 93
    .line 94
    return-void

    .line 95
    :pswitch_5
    const/16 p1, 0x13

    .line 96
    .line 97
    const/16 v0, 0x14

    .line 98
    .line 99
    invoke-direct {p0, p1, v0}, Loa/b;-><init>(II)V

    .line 100
    .line 101
    .line 102
    new-instance p1, Let/d;

    .line 103
    .line 104
    const/4 v0, 0x5

    .line 105
    invoke-direct {p1, v0}, Let/d;-><init>(I)V

    .line 106
    .line 107
    .line 108
    iput-object p1, p0, Lfb/r;->d:Loa/a;

    .line 109
    .line 110
    return-void

    .line 111
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final b(Lua/a;)V
    .locals 1

    .line 1
    iget v0, p0, Lfb/r;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "connection"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "ALTER TABLE `vehicle` ADD COLUMN `priority` INTEGER NOT NULL DEFAULT 0"

    .line 12
    .line 13
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "ALTER TABLE `ordered_vehicle` ADD COLUMN `priority` INTEGER NOT NULL DEFAULT 0"

    .line 17
    .line 18
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_ordered_vehicle` (`commissionId` TEXT NOT NULL, `name` TEXT NOT NULL, `vin` TEXT, `dealerId` TEXT, `priority` INTEGER NOT NULL DEFAULT 0, `activationStatus` TEXT NOT NULL, `orderStatus` TEXT NOT NULL, `startDeliveryDate` TEXT, `endDeliveryDate` TEXT, `spec_model` TEXT, `spec_trimLevel` TEXT, `spec_engine` TEXT, `spec_exteriorColor` TEXT, `spec_interiorColor` TEXT, `spec_batteryCapacity` INTEGER, `spec_maxPerformanceInKW` INTEGER, `spec_wltpRangeInM` INTEGER, `spec_consumptionInLitPer100km` REAL, `spec_consumptionInkWhPer100km` REAL, `spec_consumptionInKgPer100km` REAL, PRIMARY KEY(`commissionId`))"

    .line 22
    .line 23
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, "INSERT INTO `_new_ordered_vehicle` (`commissionId`,`name`,`vin`,`dealerId`,`activationStatus`,`orderStatus`,`startDeliveryDate`,`endDeliveryDate`,`spec_model`,`spec_trimLevel`,`spec_engine`,`spec_exteriorColor`,`spec_interiorColor`,`spec_batteryCapacity`,`spec_maxPerformanceInKW`,`spec_wltpRangeInM`,`spec_consumptionInLitPer100km`,`spec_consumptionInkWhPer100km`,`spec_consumptionInKgPer100km`) SELECT `commissionId`,`name`,`vin`,`dealerId`,`activationStatus`,`orderStatus`,`startDeliveryDate`,`endDeliveryDate`,`spec_model`,`spec_trimLevel`,`spec_engine`,`spec_exteriorColor`,`spec_interiorColor`,`spec_batteryCapacity`,`spec_maxPerformanceInKW`,`spec_wltpRangeInM`,`spec_consumptionInLitPer100km`,`spec_consumptionInkWhPer100km`,`spec_consumptionInKgPer100km` FROM `ordered_vehicle`"

    .line 27
    .line 28
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v0, "DROP TABLE `ordered_vehicle`"

    .line 32
    .line 33
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v0, "ALTER TABLE `_new_ordered_vehicle` RENAME TO `ordered_vehicle`"

    .line 37
    .line 38
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 42
    .line 43
    check-cast p0, Lny/b;

    .line 44
    .line 45
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_0
    const-string v0, "connection"

    .line 50
    .line 51
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_route_settings` (`id` INTEGER NOT NULL, `includeFerries` INTEGER NOT NULL, `includeMotorways` INTEGER NOT NULL, `includeTollRoads` INTEGER NOT NULL, `includeBorderCrossings` INTEGER NOT NULL, `departureBatteryLevel` INTEGER, `arrivalBatteryLevel` INTEGER, PRIMARY KEY(`id`))"

    .line 55
    .line 56
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v0, "INSERT INTO `_new_route_settings` (`id`,`includeFerries`,`includeMotorways`,`includeTollRoads`,`includeBorderCrossings`,`departureBatteryLevel`,`arrivalBatteryLevel`) SELECT `id`,`includeFerries`,`includeMotorways`,`includeTollRoads`,`includeBorderCrossings`,`deprature_percentage`,`arrival_percentage` FROM `route_settings`"

    .line 60
    .line 61
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string v0, "DROP TABLE `route_settings`"

    .line 65
    .line 66
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    const-string v0, "ALTER TABLE `_new_route_settings` RENAME TO `route_settings`"

    .line 70
    .line 71
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 75
    .line 76
    check-cast p0, Lny/b;

    .line 77
    .line 78
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :pswitch_1
    const-string v0, "connection"

    .line 83
    .line 84
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string v0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_running_request_value` TEXT DEFAULT NULL"

    .line 88
    .line 89
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_running_request_target_temperature_value` REAL DEFAULT NULL"

    .line 93
    .line 94
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    const-string v0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_running_request_target_temperature_unit` TEXT DEFAULT NULL"

    .line 98
    .line 99
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_air_conditioning_status` (`vin` TEXT NOT NULL, `state` TEXT NOT NULL, `window_heating_enabled` INTEGER, `target_temperature_at` TEXT, `air_conditioning_without_external_power` INTEGER, `air_conditioning_at_unlock` INTEGER, `steering_wheel_position` TEXT NOT NULL, `heater_source` TEXT NOT NULL, `charger_connection_state` TEXT, `air_conditioning_errors` TEXT NOT NULL, `car_captured_timestamp` TEXT, `target_temperature_value` REAL, `target_temperature_unit` TEXT, `window_heating_front` TEXT NOT NULL, `window_heating_rear` TEXT NOT NULL, `seat_heating_front_left` INTEGER, `seat_heating_front_right` INTEGER, `seat_heating_rear_left` INTEGER, `seat_heating_rear_right` INTEGER, `air_conditioning_running_request_value` TEXT, `air_conditioning_running_request_target_temperature_value` REAL, `air_conditioning_running_request_target_temperature_unit` TEXT, PRIMARY KEY(`vin`))"

    .line 103
    .line 104
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    const-string v0, "INSERT INTO `_new_air_conditioning_status` (`vin`,`state`,`window_heating_enabled`,`target_temperature_at`,`air_conditioning_without_external_power`,`air_conditioning_at_unlock`,`steering_wheel_position`,`heater_source`,`charger_connection_state`,`air_conditioning_errors`,`car_captured_timestamp`,`target_temperature_value`,`target_temperature_unit`,`window_heating_front`,`window_heating_rear`,`seat_heating_front_left`,`seat_heating_front_right`,`seat_heating_rear_left`,`seat_heating_rear_right`) SELECT `vin`,`state`,`window_heating_enabled`,`target_temperature_at`,`air_conditioning_without_external_power`,`air_conditioning_at_unlock`,`steering_wheel_position`,`heater_source`,`charger_connection_state`,`air_conditioning_errors`,`car_captured_timestamp`,`target_temperature_value`,`target_temperature_unit`,`window_heating_front`,`window_heating_rear`,`seat_heating_front_left`,`seat_heating_front_right`,`seat_heating_rear_left`,`seat_heating_rear_right` FROM `air_conditioning_status`"

    .line 108
    .line 109
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string v0, "DROP TABLE `air_conditioning_status`"

    .line 113
    .line 114
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string v0, "ALTER TABLE `_new_air_conditioning_status` RENAME TO `air_conditioning_status`"

    .line 118
    .line 119
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 123
    .line 124
    check-cast p0, Lny/b;

    .line 125
    .line 126
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    :pswitch_2
    const-string v0, "connection"

    .line 131
    .line 132
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_composite_render` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vehicle_id` TEXT NOT NULL, `vehicle_type` TEXT NOT NULL, `view_type` TEXT NOT NULL, `modifications_adjust_space_left` INTEGER, `modifications_adjust_space_right` INTEGER, `modifications_adjust_space_top` INTEGER, `modifications_adjust_space_bottom` INTEGER, `modifications_flip_horizontal` INTEGER, `modifications_anchor_to` TEXT)"

    .line 136
    .line 137
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    const-string v0, "INSERT INTO `_new_composite_render` (`id`,`vehicle_id`,`vehicle_type`,`view_type`,`modifications_adjust_space_left`,`modifications_adjust_space_right`,`modifications_adjust_space_top`,`modifications_adjust_space_bottom`,`modifications_flip_horizontal`,`modifications_anchor_to`) SELECT `id`,`vehicle_id`,`vehicle_type`,`view_type`,`modifications_adjust_space_left`,`modifications_adjust_space_right`,`modifications_adjust_space_top`,`modifications_adjust_space_bottom`,`modifications_flip_horizontal`,`modifications_anchor_to` FROM `composite_render`"

    .line 141
    .line 142
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string v0, "DROP TABLE `composite_render`"

    .line 146
    .line 147
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    const-string v0, "ALTER TABLE `_new_composite_render` RENAME TO `composite_render`"

    .line 151
    .line 152
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 156
    .line 157
    check-cast p0, Lny/b;

    .line 158
    .line 159
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :pswitch_3
    const-string v0, "connection"

    .line 164
    .line 165
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const-string v0, "DROP TABLE `render`"

    .line 169
    .line 170
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    const-string v0, "DROP TABLE `ordered_render`"

    .line 174
    .line 175
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_composite_render_layer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `composite_render_id` INTEGER NOT NULL, `url` TEXT NOT NULL, `order` INTEGER NOT NULL, FOREIGN KEY(`composite_render_id`) REFERENCES `composite_render`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 179
    .line 180
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    const-string v0, "INSERT INTO `_new_composite_render_layer` (`id`,`composite_render_id`,`url`,`order`) SELECT `id`,`composite_render_id`,`url`,`order` FROM `composite_render_layer`"

    .line 184
    .line 185
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    const-string v0, "DROP TABLE `composite_render_layer`"

    .line 189
    .line 190
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    const-string v0, "ALTER TABLE `_new_composite_render_layer` RENAME TO `composite_render_layer`"

    .line 194
    .line 195
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    const-string v0, "composite_render_layer"

    .line 199
    .line 200
    invoke-static {p1, v0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 204
    .line 205
    check-cast p0, Lny/b;

    .line 206
    .line 207
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 208
    .line 209
    .line 210
    return-void

    .line 211
    :pswitch_4
    const-string v0, "connection"

    .line 212
    .line 213
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `input_merger_class_name` TEXT NOT NULL, `input` BLOB NOT NULL, `output` BLOB NOT NULL, `initial_delay` INTEGER NOT NULL, `interval_duration` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NULL, `backoff_delay_duration` INTEGER NOT NULL, `last_enqueue_time` INTEGER NOT NULL DEFAULT -1, `minimum_retention_duration` INTEGER NOT NULL, `schedule_requested_at` INTEGER NOT NULL, `run_in_foreground` INTEGER NOT NULL, `out_of_quota_policy` INTEGER NOT NULL, `period_count` INTEGER NOT NULL DEFAULT 0, `generation` INTEGER NOT NULL DEFAULT 0, `next_schedule_time_override` INTEGER NOT NULL DEFAULT 9223372036854775807, `next_schedule_time_override_generation` INTEGER NOT NULL DEFAULT 0, `stop_reason` INTEGER NOT NULL DEFAULT -256, `required_network_type` INTEGER NOT NULL, `requires_charging` INTEGER NOT NULL, `requires_device_idle` INTEGER NOT NULL, `requires_battery_not_low` INTEGER NOT NULL, `requires_storage_not_low` INTEGER NOT NULL, `trigger_content_update_delay` INTEGER NOT NULL, `trigger_max_content_delay` INTEGER NOT NULL, `content_uri_triggers` BLOB NOT NULL, PRIMARY KEY(`id`))"

    .line 217
    .line 218
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const-string v0, "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last_enqueue_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`period_count`,`generation`,`next_schedule_time_override`,`next_schedule_time_override_generation`,`stop_reason`,`required_network_type`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers`) SELECT `id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last_enqueue_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`period_count`,`generation`,`next_schedule_time_override`,`next_schedule_time_override_generation`,`stop_reason`,`required_network_type`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers` FROM `WorkSpec`"

    .line 222
    .line 223
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string v0, "DROP TABLE `WorkSpec`"

    .line 227
    .line 228
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    const-string v0, "ALTER TABLE `_new_WorkSpec` RENAME TO `WorkSpec`"

    .line 232
    .line 233
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    const-string v0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_schedule_requested_at` ON `WorkSpec` (`schedule_requested_at`)"

    .line 237
    .line 238
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    const-string v0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_last_enqueue_time` ON `WorkSpec` (`last_enqueue_time`)"

    .line 242
    .line 243
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 247
    .line 248
    check-cast p0, Let/d;

    .line 249
    .line 250
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 251
    .line 252
    .line 253
    return-void

    .line 254
    :pswitch_5
    const-string v0, "connection"

    .line 255
    .line 256
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    const-string v0, "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `input_merger_class_name` TEXT, `input` BLOB NOT NULL, `output` BLOB NOT NULL, `initial_delay` INTEGER NOT NULL, `interval_duration` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NULL, `backoff_delay_duration` INTEGER NOT NULL, `last_enqueue_time` INTEGER NOT NULL, `minimum_retention_duration` INTEGER NOT NULL, `schedule_requested_at` INTEGER NOT NULL, `run_in_foreground` INTEGER NOT NULL, `out_of_quota_policy` INTEGER NOT NULL, `period_count` INTEGER NOT NULL DEFAULT 0, `required_network_type` INTEGER NOT NULL, `requires_charging` INTEGER NOT NULL, `requires_device_idle` INTEGER NOT NULL, `requires_battery_not_low` INTEGER NOT NULL, `requires_storage_not_low` INTEGER NOT NULL, `trigger_content_update_delay` INTEGER NOT NULL, `trigger_max_content_delay` INTEGER NOT NULL, `content_uri_triggers` BLOB NOT NULL, PRIMARY KEY(`id`))"

    .line 260
    .line 261
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    const-string v0, "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last_enqueue_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`required_network_type`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers`) SELECT `id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`period_start_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`required_network_type`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers` FROM `WorkSpec`"

    .line 265
    .line 266
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    const-string v0, "DROP TABLE `WorkSpec`"

    .line 270
    .line 271
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    const-string v0, "ALTER TABLE `_new_WorkSpec` RENAME TO `WorkSpec`"

    .line 275
    .line 276
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    const-string v0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_schedule_requested_at` ON `WorkSpec` (`schedule_requested_at`)"

    .line 280
    .line 281
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    const-string v0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_last_enqueue_time` ON `WorkSpec` (`last_enqueue_time`)"

    .line 285
    .line 286
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    iget-object p0, p0, Lfb/r;->d:Loa/a;

    .line 290
    .line 291
    check-cast p0, Ldv/a;

    .line 292
    .line 293
    invoke-interface {p0, p1}, Loa/a;->i(Lua/a;)V

    .line 294
    .line 295
    .line 296
    return-void

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
