.class public final Lny/a;
.super Loa/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    .line 1
    iput p3, p0, Lny/a;->c:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Loa/b;-><init>(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Landroidx/sqlite/db/SupportSQLiteDatabase;)V
    .locals 1

    .line 1
    iget v0, p0, Lny/a;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Loa/b;->a(Landroidx/sqlite/db/SupportSQLiteDatabase;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string p0, "db"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p0, "UPDATE network_log SET log_type = \'AsyncEvent\' WHERE log_type = \'SilentMessage\'"

    .line 16
    .line 17
    invoke-interface {p1, p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lua/a;)V
    .locals 1

    .line 1
    iget v0, p0, Lny/a;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Loa/b;->b(Lua/a;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string p0, "connection"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p0, "ALTER TABLE `charging_profile_timer` ADD COLUMN `start_air_condition` INTEGER NOT NULL DEFAULT false"

    .line 16
    .line 17
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_1
    const-string p0, "connection"

    .line 22
    .line 23
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p0, "CREATE TABLE IF NOT EXISTS `app_log` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `timestamp` TEXT NOT NULL, `level` TEXT NOT NULL, `tag` TEXT NOT NULL, `message` TEXT NOT NULL)"

    .line 27
    .line 28
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_2
    const-string p0, "connection"

    .line 33
    .line 34
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string p0, "ALTER TABLE `charging_profile` ADD COLUMN `location_lat` REAL DEFAULT NULL"

    .line 38
    .line 39
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string p0, "ALTER TABLE `charging_profile` ADD COLUMN `location_lng` REAL DEFAULT NULL"

    .line 43
    .line 44
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_3
    const-string p0, "connection"

    .line 49
    .line 50
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const-string p0, "ALTER TABLE `recent_places` ADD COLUMN `is_laura_search` INTEGER DEFAULT NULL"

    .line 54
    .line 55
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :pswitch_4
    const-string p0, "connection"

    .line 60
    .line 61
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string p0, "CREATE TABLE IF NOT EXISTS `trips_overview` (`vin` TEXT NOT NULL, `vehicle_type` TEXT NOT NULL, `end_mileage` INTEGER, `average_fuel_consumption` REAL, `average_electric_consumption` REAL, `average_gas_consumption` REAL, PRIMARY KEY(`vin`))"

    .line 65
    .line 66
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_5
    const-string p0, "connection"

    .line 71
    .line 72
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `spec_colour` TEXT DEFAULT NULL"

    .line 76
    .line 77
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `spec_length` INTEGER DEFAULT NULL"

    .line 81
    .line 82
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `spec_width` INTEGER DEFAULT NULL"

    .line 86
    .line 87
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `spec_height` INTEGER DEFAULT NULL"

    .line 91
    .line 92
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :pswitch_6
    const-string p0, "connection"

    .line 97
    .line 98
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string p0, "ALTER TABLE `charging` ADD COLUMN `charging_settings_max_charge_current` INTEGER DEFAULT NULL"

    .line 102
    .line 103
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    return-void

    .line 107
    :pswitch_7
    const-string p0, "connection"

    .line 108
    .line 109
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p0, "ALTER TABLE `charging` ADD COLUMN `charging_settings_battery_care_mode_target_value` INTEGER DEFAULT NULL"

    .line 113
    .line 114
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :pswitch_8
    const-string p0, "connection"

    .line 119
    .line 120
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    const-string p0, "ALTER TABLE `route_settings` ADD COLUMN `preferPowerpassChargingProviders` INTEGER DEFAULT NULL"

    .line 124
    .line 125
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    return-void

    .line 129
    :pswitch_9
    const-string p0, "connection"

    .line 130
    .line 131
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string p0, "ALTER TABLE `user` ADD COLUMN `countryOfResidenceCode` TEXT DEFAULT NULL"

    .line 135
    .line 136
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :pswitch_a
    const-string p0, "connection"

    .line 141
    .line 142
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string p0, "ALTER TABLE `user` ADD COLUMN `billingAddressCountry` TEXT DEFAULT NULL"

    .line 146
    .line 147
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    const-string p0, "ALTER TABLE `user` ADD COLUMN `billingAddressCity` TEXT DEFAULT NULL"

    .line 151
    .line 152
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string p0, "ALTER TABLE `user` ADD COLUMN `billingAddressStreet` TEXT DEFAULT NULL"

    .line 156
    .line 157
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    const-string p0, "ALTER TABLE `user` ADD COLUMN `billingAddressHouseNumber` TEXT DEFAULT NULL"

    .line 161
    .line 162
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    const-string p0, "ALTER TABLE `user` ADD COLUMN `billingAddressZipCode` TEXT DEFAULT NULL"

    .line 166
    .line 167
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_backups_notice` (`vin` TEXT NOT NULL, PRIMARY KEY(`vin`))"

    .line 171
    .line 172
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    return-void

    .line 176
    :pswitch_b
    const-string p0, "connection"

    .line 177
    .line 178
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    const-string p0, "ALTER TABLE `auxiliary_heating_status` ADD COLUMN `outside_temperature_timestamp` TEXT DEFAULT NULL"

    .line 182
    .line 183
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    const-string p0, "ALTER TABLE `auxiliary_heating_status` ADD COLUMN `outside_temperature_outside_temperaturevalue` REAL DEFAULT NULL"

    .line 187
    .line 188
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string p0, "ALTER TABLE `auxiliary_heating_status` ADD COLUMN `outside_temperature_outside_temperatureunit` TEXT DEFAULT NULL"

    .line 192
    .line 193
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    return-void

    .line 197
    :pswitch_c
    const-string p0, "connection"

    .line 198
    .line 199
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    const-string p0, "CREATE TABLE IF NOT EXISTS `fleet` (`vin` TEXT NOT NULL, `fleet` INTEGER NOT NULL, PRIMARY KEY(`vin`))"

    .line 203
    .line 204
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    return-void

    .line 208
    :pswitch_d
    const-string p0, "connection"

    .line 209
    .line 210
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    const-string p0, "ALTER TABLE `active_ventilation_status` ADD COLUMN `outside_temperature_timestamp` TEXT DEFAULT NULL"

    .line 214
    .line 215
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    const-string p0, "ALTER TABLE `active_ventilation_status` ADD COLUMN `outside_temperature_outside_temperaturevalue` REAL DEFAULT NULL"

    .line 219
    .line 220
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    const-string p0, "ALTER TABLE `active_ventilation_status` ADD COLUMN `outside_temperature_outside_temperatureunit` TEXT DEFAULT NULL"

    .line 224
    .line 225
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    return-void

    .line 229
    :pswitch_e
    const-string p0, "connection"

    .line 230
    .line 231
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    const-string p0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_outside_temperaturetimestamp` TEXT DEFAULT NULL"

    .line 235
    .line 236
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    const-string p0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_outside_temperatureoutside_temperaturevalue` REAL DEFAULT NULL"

    .line 240
    .line 241
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    const-string p0, "ALTER TABLE `air_conditioning_status` ADD COLUMN `air_conditioning_outside_temperatureoutside_temperatureunit` TEXT DEFAULT NULL"

    .line 245
    .line 246
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    return-void

    .line 250
    :pswitch_f
    const-string p0, "connection"

    .line 251
    .line 252
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_auxiliary_heating_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `auxiliary_heating_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 256
    .line 257
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    const-string p0, "INSERT INTO `_new_auxiliary_heating_timers` (`id`,`vin`,`enabled`,`time`,`type`,`days`) SELECT `id`,`vin`,`enabled`,`time`,`type`,`days` FROM `auxiliary_heating_timers`"

    .line 261
    .line 262
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    const-string p0, "DROP TABLE `auxiliary_heating_timers`"

    .line 266
    .line 267
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    const-string p0, "ALTER TABLE `_new_auxiliary_heating_timers` RENAME TO `auxiliary_heating_timers`"

    .line 271
    .line 272
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_auxiliary_heating_timers_vin` ON `auxiliary_heating_timers` (`vin`)"

    .line 276
    .line 277
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_composite_render_layer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `composite_render_id` INTEGER NOT NULL, `url` TEXT NOT NULL, `order` INTEGER NOT NULL, FOREIGN KEY(`composite_render_id`) REFERENCES `composite_render`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 281
    .line 282
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    const-string p0, "INSERT INTO `_new_composite_render_layer` (`id`,`composite_render_id`,`url`,`order`) SELECT `id`,`composite_render_id`,`url`,`order` FROM `composite_render_layer`"

    .line 286
    .line 287
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    const-string p0, "DROP TABLE `composite_render_layer`"

    .line 291
    .line 292
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    const-string p0, "ALTER TABLE `_new_composite_render_layer` RENAME TO `composite_render_layer`"

    .line 296
    .line 297
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_composite_render_layer_composite_render_id` ON `composite_render_layer` (`composite_render_id`)"

    .line 301
    .line 302
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_order_checkpoint` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `orderStatus` TEXT NOT NULL, `date` TEXT, `startEstimatedDate` TEXT, `endEstimatedDate` TEXT, `commissionId` TEXT NOT NULL, FOREIGN KEY(`commissionId`) REFERENCES `ordered_vehicle`(`commissionId`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 306
    .line 307
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    const-string p0, "INSERT INTO `_new_order_checkpoint` (`id`,`orderStatus`,`date`,`startEstimatedDate`,`endEstimatedDate`,`commissionId`) SELECT `id`,`orderStatus`,`date`,`startEstimatedDate`,`endEstimatedDate`,`commissionId` FROM `order_checkpoint`"

    .line 311
    .line 312
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    const-string p0, "DROP TABLE `order_checkpoint`"

    .line 316
    .line 317
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    const-string p0, "ALTER TABLE `_new_order_checkpoint` RENAME TO `order_checkpoint`"

    .line 321
    .line 322
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_order_checkpoint_commissionId` ON `order_checkpoint` (`commissionId`)"

    .line 326
    .line 327
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    const-string p0, "auxiliary_heating_timers"

    .line 331
    .line 332
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    const-string p0, "composite_render_layer"

    .line 336
    .line 337
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    const-string p0, "order_checkpoint"

    .line 341
    .line 342
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 343
    .line 344
    .line 345
    return-void

    .line 346
    :pswitch_10
    const-string p0, "connection"

    .line 347
    .line 348
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_charging_profile` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `profile_id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `name` TEXT NOT NULL, `settings_min_battery_charged_state` INTEGER, `settings_target_charged_state` INTEGER, `settings_reduced_current_active` INTEGER, `settings_cable_lock_active` INTEGER, FOREIGN KEY(`vin`) REFERENCES `charging_profiles`(`vin`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 352
    .line 353
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    const-string p0, "INSERT INTO `_new_charging_profile` (`id`,`profile_id`,`vin`,`name`,`settings_min_battery_charged_state`,`settings_target_charged_state`,`settings_reduced_current_active`,`settings_cable_lock_active`) SELECT `id`,`profile_id`,`vin`,`name`,`settings_min_battery_charged_state`,`settings_target_charged_state`,`settings_reduced_current_active`,`settings_cable_lock_active` FROM `charging_profile`"

    .line 357
    .line 358
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    const-string p0, "DROP TABLE `charging_profile`"

    .line 362
    .line 363
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    const-string p0, "ALTER TABLE `_new_charging_profile` RENAME TO `charging_profile`"

    .line 367
    .line 368
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 369
    .line 370
    .line 371
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_vin` ON `charging_profile` (`vin`)"

    .line 372
    .line 373
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    const-string p0, "CREATE UNIQUE INDEX IF NOT EXISTS `index_charging_profile_profile_id_vin` ON `charging_profile` (`profile_id`, `vin`)"

    .line 377
    .line 378
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_charging_profile_timer` (`id` INTEGER NOT NULL, `profile_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`, `profile_id`), FOREIGN KEY(`profile_id`) REFERENCES `charging_profile`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 382
    .line 383
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    const-string p0, "INSERT INTO `_new_charging_profile_timer` (`id`,`profile_id`,`enabled`,`time`,`type`,`days`) SELECT `id`,`profile_id`,`enabled`,`time`,`type`,`days` FROM `charging_profile_timer`"

    .line 387
    .line 388
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    const-string p0, "DROP TABLE `charging_profile_timer`"

    .line 392
    .line 393
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    const-string p0, "ALTER TABLE `_new_charging_profile_timer` RENAME TO `charging_profile_timer`"

    .line 397
    .line 398
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 399
    .line 400
    .line 401
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_timer_profile_id` ON `charging_profile_timer` (`profile_id`)"

    .line 402
    .line 403
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 404
    .line 405
    .line 406
    const-string p0, "charging_profile"

    .line 407
    .line 408
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    const-string p0, "charging_profile_timer"

    .line 412
    .line 413
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    return-void

    .line 417
    :pswitch_11
    const-string p0, "connection"

    .line 418
    .line 419
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `profile_id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `name` TEXT NOT NULL, `settings_min_battery_charged_state` INTEGER, `settings_target_charged_state` INTEGER, `settings_reduced_current_active` INTEGER, `settings_cable_lock_active` INTEGER, FOREIGN KEY(`vin`) REFERENCES `charging_profiles`(`vin`) ON UPDATE NO ACTION ON DELETE NO ACTION )"

    .line 423
    .line 424
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 425
    .line 426
    .line 427
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_vin` ON `charging_profile` (`vin`)"

    .line 428
    .line 429
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    const-string p0, "CREATE UNIQUE INDEX IF NOT EXISTS `index_charging_profile_profile_id_vin` ON `charging_profile` (`profile_id`, `vin`)"

    .line 433
    .line 434
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 435
    .line 436
    .line 437
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile_charging_time` (`id` INTEGER NOT NULL, `profile_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `start_time` TEXT NOT NULL, `end_time` TEXT NOT NULL, PRIMARY KEY(`id`, `profile_id`), FOREIGN KEY(`profile_id`) REFERENCES `charging_profile`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 438
    .line 439
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_charging_time_profile_id` ON `charging_profile_charging_time` (`profile_id`)"

    .line 443
    .line 444
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profiles` (`vin` TEXT NOT NULL, `current_profile_id` INTEGER, `next_timer_time` TEXT, `car_captured_timestamp` TEXT, PRIMARY KEY(`vin`))"

    .line 448
    .line 449
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile_timer` (`id` INTEGER NOT NULL, `profile_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`, `profile_id`), FOREIGN KEY(`profile_id`) REFERENCES `charging_profile`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 453
    .line 454
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 455
    .line 456
    .line 457
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_timer_profile_id` ON `charging_profile_timer` (`profile_id`)"

    .line 458
    .line 459
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    return-void

    .line 463
    :pswitch_12
    const-string p0, "connection"

    .line 464
    .line 465
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_plan` (`vin` TEXT NOT NULL, `target_temperature_celsius` REAL, `min_battery_charged_state_percent` INTEGER, `first_occurring_timer_id` INTEGER, `car_captured_timestamp` TEXT, PRIMARY KEY(`vin`))"

    .line 469
    .line 470
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 471
    .line 472
    .line 473
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_timer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vin` TEXT NOT NULL, `index` INTEGER NOT NULL, `is_enabled` INTEGER NOT NULL, `is_charging_enabled` INTEGER NOT NULL, `is_air_conditioning_enabled` INTEGER NOT NULL, `target_charged_state` INTEGER, `timer_id` INTEGER NOT NULL, `timer_enabled` INTEGER NOT NULL, `timer_time` TEXT NOT NULL, `timer_type` TEXT NOT NULL, `timer_days` TEXT NOT NULL, FOREIGN KEY(`vin`) REFERENCES `departure_plan`(`vin`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 474
    .line 475
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 476
    .line 477
    .line 478
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_departure_timer_vin` ON `departure_timer` (`vin`)"

    .line 479
    .line 480
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_charging_time` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timer_id` INTEGER NOT NULL, `charging_time_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `start_time` TEXT NOT NULL, `end_time` TEXT NOT NULL, FOREIGN KEY(`timer_id`) REFERENCES `departure_timer`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 484
    .line 485
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_departure_charging_time_timer_id` ON `departure_charging_time` (`timer_id`)"

    .line 489
    .line 490
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_capability` (`id` TEXT NOT NULL, `serviceExpiration` TEXT, `statuses` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`id`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 494
    .line 495
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 496
    .line 497
    .line 498
    const-string p0, "INSERT INTO `_new_capability` (`id`,`serviceExpiration`,`statuses`,`vin`) SELECT `id`,`serviceExpiration`,`statuses`,`vin` FROM `capability`"

    .line 499
    .line 500
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 501
    .line 502
    .line 503
    const-string p0, "DROP TABLE `capability`"

    .line 504
    .line 505
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 506
    .line 507
    .line 508
    const-string p0, "ALTER TABLE `_new_capability` RENAME TO `capability`"

    .line 509
    .line 510
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_capability_vin` ON `capability` (`vin`)"

    .line 514
    .line 515
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 516
    .line 517
    .line 518
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_capability_error` (`type` TEXT NOT NULL, `description` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`type`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 519
    .line 520
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    const-string p0, "INSERT INTO `_new_capability_error` (`type`,`description`,`vin`) SELECT `type`,`description`,`vin` FROM `capability_error`"

    .line 524
    .line 525
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 526
    .line 527
    .line 528
    const-string p0, "DROP TABLE `capability_error`"

    .line 529
    .line 530
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    const-string p0, "ALTER TABLE `_new_capability_error` RENAME TO `capability_error`"

    .line 534
    .line 535
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 536
    .line 537
    .line 538
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_capability_error_vin` ON `capability_error` (`vin`)"

    .line 539
    .line 540
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 541
    .line 542
    .line 543
    const-string p0, "capability"

    .line 544
    .line 545
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 546
    .line 547
    .line 548
    const-string p0, "capability_error"

    .line 549
    .line 550
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    return-void

    .line 554
    :pswitch_13
    const-string p0, "connection"

    .line 555
    .line 556
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 557
    .line 558
    .line 559
    const-string p0, "CREATE TABLE IF NOT EXISTS `air_conditioning_status` (`vin` TEXT NOT NULL, `state` TEXT NOT NULL, `window_heating_enabled` INTEGER, `target_temperature_at` TEXT, `air_conditioning_without_external_power` INTEGER, `air_conditioning_at_unlock` INTEGER, `steering_wheel_position` TEXT NOT NULL, `heater_source` TEXT NOT NULL, `charger_connection_state` TEXT, `air_conditioning_errors` TEXT NOT NULL, `running_requests` TEXT NOT NULL, `car_captured_timestamp` TEXT, `target_temperature_value` REAL, `target_temperature_unit` TEXT, `window_heating_front` TEXT NOT NULL, `window_heating_rear` TEXT NOT NULL, `seat_heating_front_left` INTEGER, `seat_heating_front_right` INTEGER, `seat_heating_rear_left` INTEGER, `seat_heating_rear_right` INTEGER, PRIMARY KEY(`vin`))"

    .line 560
    .line 561
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    const-string p0, "CREATE TABLE IF NOT EXISTS `air_conditioning_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `air_conditioning_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 565
    .line 566
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 567
    .line 568
    .line 569
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_air_conditioning_timers_vin` ON `air_conditioning_timers` (`vin`)"

    .line 570
    .line 571
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 572
    .line 573
    .line 574
    const-string p0, "CREATE TABLE IF NOT EXISTS `active_ventilation_status` (`vin` TEXT NOT NULL, `estimated_to_reach_target` TEXT, `state` TEXT NOT NULL, `duration` INTEGER NOT NULL, `car_captured_timestamp` TEXT, PRIMARY KEY(`vin`))"

    .line 575
    .line 576
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    const-string p0, "CREATE TABLE IF NOT EXISTS `active_ventilation_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `active_ventilation_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 580
    .line 581
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 582
    .line 583
    .line 584
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_active_ventilation_timers_vin` ON `active_ventilation_timers` (`vin`)"

    .line 585
    .line 586
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    const-string p0, "CREATE TABLE IF NOT EXISTS `auxiliary_heating_status` (`vin` TEXT NOT NULL, `estimated_date_time_to_reach_target_temperature` TEXT, `state` TEXT NOT NULL, `duration` INTEGER NOT NULL, `start_mode` TEXT NOT NULL, `heating_errors` TEXT, `car_captured_timestamp` TEXT, `target_temperature_value` REAL, `target_temperature_unit` TEXT, PRIMARY KEY(`vin`))"

    .line 590
    .line 591
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    const-string p0, "CREATE TABLE IF NOT EXISTS `auxiliary_heating_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `auxiliary_heating_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 595
    .line 596
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    return-void

    .line 600
    :pswitch_14
    const-string p0, "connection"

    .line 601
    .line 602
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 603
    .line 604
    .line 605
    return-void

    .line 606
    :pswitch_15
    const-string p0, "connection"

    .line 607
    .line 608
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    const-string p0, "ALTER TABLE `charging` ADD COLUMN `car_captured_timestamp` TEXT DEFAULT NULL"

    .line 612
    .line 613
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    const-string p0, "ALTER TABLE `range_ice` ADD COLUMN `car_captured_timestamp` TEXT DEFAULT NULL"

    .line 617
    .line 618
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 619
    .line 620
    .line 621
    const-string p0, "ALTER TABLE `vehicle_status` ADD COLUMN `car_captured_timestamp` TEXT DEFAULT NULL"

    .line 622
    .line 623
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 624
    .line 625
    .line 626
    return-void

    .line 627
    :pswitch_16
    const-string p0, "connection"

    .line 628
    .line 629
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 630
    .line 631
    .line 632
    const-string p0, "CREATE TABLE IF NOT EXISTS `range_ice` (`vin` TEXT NOT NULL, `car_type` TEXT NOT NULL, `ad_blue_range` INTEGER, `total_range` INTEGER, `primary_engine_engine_type` TEXT NOT NULL, `primary_engine_current_soc_in_pct` INTEGER, `primary_engine_current_fuel_level_pct` INTEGER, `primary_engine_remaining_range` INTEGER, `secondary_engine_engine_type` TEXT, `secondary_engine_current_soc_in_pct` INTEGER, `secondary_engine_current_fuel_level_pct` INTEGER, `secondary_engine_remaining_range` INTEGER, PRIMARY KEY(`vin`))"

    .line 633
    .line 634
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 635
    .line 636
    .line 637
    return-void

    .line 638
    :pswitch_17
    const-string p0, "connection"

    .line 639
    .line 640
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging` (`vin` TEXT NOT NULL, `battery_care_mode` TEXT, `in_saved_location` INTEGER NOT NULL, `charging_errors` TEXT, `battery_statuscurrent_charged_state` INTEGER, `battery_statuscruising_range_electric` INTEGER, `charging_settings_charge_current` TEXT, `charging_settings_plug_unlock` TEXT, `charging_settings_target_charged_state` INTEGER, `charging_status_charging_state` TEXT, `charging_status_charging_type` TEXT, `charging_status_charge_power` INTEGER, `charging_status_remaining_time_to_complete` INTEGER, `charge_mode_settings_available_charge_modes` TEXT, `charge_mode_settings_preferred_charge_mode` TEXT, PRIMARY KEY(`vin`))"

    .line 644
    .line 645
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 646
    .line 647
    .line 648
    return-void

    .line 649
    :pswitch_18
    const-string p0, "connection"

    .line 650
    .line 651
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 652
    .line 653
    .line 654
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_status` (`vin` TEXT NOT NULL, `overall_status_doors` TEXT NOT NULL, `overall_status_windows` TEXT NOT NULL, `overall_status_locked` TEXT NOT NULL, `overall_status_lights` TEXT NOT NULL, `overall_status_doors_locked` TEXT NOT NULL, `overall_status_doors_open` TEXT NOT NULL, `detail_status_sun_roof_status` TEXT NOT NULL, `detail_status_trunk_status` TEXT NOT NULL, `detail_status_bonnet_status` TEXT NOT NULL, `render_light_mode_one_x` TEXT, `render_light_mode_one_and_half_x` TEXT, `render_light_mode_two_x` TEXT, `render_light_mode_three_x` TEXT, `render_dark_mode_one_x` TEXT, `render_dark_mode_one_and_half_x` TEXT, `render_dark_mode_two_x` TEXT, `render_dark_mode_three_x` TEXT, PRIMARY KEY(`vin`))"

    .line 655
    .line 656
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 657
    .line 658
    .line 659
    return-void

    .line 660
    :pswitch_19
    const-string p0, "connection"

    .line 661
    .line 662
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 663
    .line 664
    .line 665
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_capability` (`id` TEXT NOT NULL, `serviceExpiration` TEXT, `statuses` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`id`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 666
    .line 667
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 668
    .line 669
    .line 670
    const-string p0, "INSERT INTO `_new_capability` (`id`,`serviceExpiration`,`statuses`,`vin`) SELECT `id`,`serviceExpiration`,`statuses`,`vin` FROM `capability`"

    .line 671
    .line 672
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 673
    .line 674
    .line 675
    const-string p0, "DROP TABLE `capability`"

    .line 676
    .line 677
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 678
    .line 679
    .line 680
    const-string p0, "ALTER TABLE `_new_capability` RENAME TO `capability`"

    .line 681
    .line 682
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 683
    .line 684
    .line 685
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_capability_error` (`type` TEXT NOT NULL, `description` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`type`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 686
    .line 687
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 688
    .line 689
    .line 690
    const-string p0, "INSERT INTO `_new_capability_error` (`type`,`description`,`vin`) SELECT `type`,`description`,`vin` FROM `capability_error`"

    .line 691
    .line 692
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 693
    .line 694
    .line 695
    const-string p0, "DROP TABLE `capability_error`"

    .line 696
    .line 697
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 698
    .line 699
    .line 700
    const-string p0, "ALTER TABLE `_new_capability_error` RENAME TO `capability_error`"

    .line 701
    .line 702
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 703
    .line 704
    .line 705
    const-string p0, "capability"

    .line 706
    .line 707
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 708
    .line 709
    .line 710
    const-string p0, "capability_error"

    .line 711
    .line 712
    invoke-static {p1, p0}, Ljp/ue;->b(Lua/a;Ljava/lang/String;)V

    .line 713
    .line 714
    .line 715
    return-void

    .line 716
    :pswitch_1a
    const-string p0, "connection"

    .line 717
    .line 718
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    const-string p0, "CREATE TABLE IF NOT EXISTS `composite_render` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vehicle_id` TEXT NOT NULL, `vehicle_type` TEXT NOT NULL, `view_type` TEXT NOT NULL, `modifications_adjust_space_left` INTEGER, `modifications_adjust_space_right` INTEGER, `modifications_adjust_space_top` INTEGER, `modifications_adjust_space_bottom` INTEGER, `modifications_height_dip` INTEGER, `modifications_flip_horizontal` INTEGER, `modifications_anchor_to` TEXT)"

    .line 722
    .line 723
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    const-string p0, "CREATE TABLE IF NOT EXISTS `composite_render_layer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `composite_render_id` INTEGER NOT NULL, `url` TEXT NOT NULL, `view_point` TEXT NOT NULL, `order` INTEGER NOT NULL, FOREIGN KEY(`composite_render_id`) REFERENCES `composite_render`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 727
    .line 728
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 729
    .line 730
    .line 731
    return-void

    .line 732
    :pswitch_1b
    const-string p0, "connection"

    .line 733
    .line 734
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 735
    .line 736
    .line 737
    const-string p0, "ALTER TABLE `widget` ADD COLUMN `isInMotion` INTEGER NOT NULL DEFAULT false"

    .line 738
    .line 739
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_fuel_level` (`vin` TEXT NOT NULL, `fuel_type` TEXT NOT NULL, `fuel_level_pct` INTEGER NOT NULL, `last_notification_date` TEXT, PRIMARY KEY(`vin`, `fuel_type`))"

    .line 743
    .line 744
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 745
    .line 746
    .line 747
    return-void

    .line 748
    :pswitch_1c
    const-string p0, "connection"

    .line 749
    .line 750
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 751
    .line 752
    .line 753
    const-string p0, "ALTER TABLE `widget` ADD COLUMN `parkingAddress` TEXT DEFAULT NULL"

    .line 754
    .line 755
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 756
    .line 757
    .line 758
    const-string p0, "ALTER TABLE `widget` ADD COLUMN `parkingMapUrl` TEXT DEFAULT NULL"

    .line 759
    .line 760
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 761
    .line 762
    .line 763
    const-string p0, "CREATE TABLE IF NOT EXISTS `route_settings` (`id` INTEGER NOT NULL, `includeFerries` INTEGER NOT NULL, `includeMotorways` INTEGER NOT NULL, `includeTollRoads` INTEGER NOT NULL, `includeBorderCrossings` INTEGER NOT NULL, `deprature_enabled` INTEGER NOT NULL, `deprature_percentage` INTEGER NOT NULL, `charging_enabled` INTEGER NOT NULL, `charging_percentage` INTEGER NOT NULL, `arrival_enabled` INTEGER NOT NULL, `arrival_percentage` INTEGER NOT NULL, PRIMARY KEY(`id`))"

    .line 764
    .line 765
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 766
    .line 767
    .line 768
    return-void

    .line 769
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
