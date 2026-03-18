.class public final Lny/e;
.super Loa/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    .line 1
    iput p3, p0, Lny/e;->c:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Loa/b;-><init>(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lny/e;->c:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "connection"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "ALTER TABLE `user_preferences` ADD COLUMN `automaticWakeUp` INTEGER DEFAULT NULL"

    .line 12
    .line 13
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    const-string p0, "connection"

    .line 18
    .line 19
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string p0, "CREATE TABLE IF NOT EXISTS `map_tile_type` (`id` INTEGER NOT NULL, `type` TEXT NOT NULL, PRIMARY KEY(`id`))"

    .line 23
    .line 24
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string p0, "CREATE TABLE IF NOT EXISTS `widget` (`id` INTEGER NOT NULL, `name` TEXT NOT NULL, `render` TEXT, `licencePlate` TEXT, `isDoorLocked` INTEGER, `isCharging` INTEGER NOT NULL, `drivingRange` INTEGER, `remainingCharging` INTEGER, `battery` INTEGER, `updated` TEXT NOT NULL, PRIMARY KEY(`id`))"

    .line 28
    .line 29
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_1
    const-string p0, "connection"

    .line 34
    .line 35
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string p0, "ALTER TABLE `user` ADD COLUMN `capabilityIds` TEXT DEFAULT NULL"

    .line 39
    .line 40
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_2
    const-string p0, "connection"

    .line 45
    .line 46
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `isWorkshopMode` INTEGER NOT NULL DEFAULT false"

    .line 50
    .line 51
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string p0, "CREATE TABLE IF NOT EXISTS `ordered_vehicle` (`commissionId` TEXT NOT NULL, `name` TEXT NOT NULL, `vin` TEXT, `dealerId` TEXT, `activationStatus` TEXT NOT NULL, `orderStatus` TEXT NOT NULL, `startDeliveryDate` TEXT, `endDeliveryDate` TEXT, `spec_model` TEXT, `spec_trimLevel` TEXT, `spec_engine` TEXT, `spec_wheels` TEXT, `spec_exteriorColor` TEXT, `spec_interiorColor` TEXT, `spec_batteryCapacity` INTEGER, `spec_maxPerformanceInKW` INTEGER, `spec_wltpRangeInM` INTEGER, `spec_consumptionInLitPer100km` REAL, `spec_consumptionInkWhPer100km` REAL, `spec_consumptionInKgPer100km` REAL, PRIMARY KEY(`commissionId`))"

    .line 55
    .line 56
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string p0, "CREATE TABLE IF NOT EXISTS `ordered_render` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `url` TEXT NOT NULL, `type` TEXT NOT NULL, `view_point` TEXT NOT NULL, `commissionId` TEXT NOT NULL, FOREIGN KEY(`commissionId`) REFERENCES `ordered_vehicle`(`commissionId`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 60
    .line 61
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string p0, "CREATE TABLE IF NOT EXISTS `order_checkpoint` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `orderStatus` TEXT NOT NULL, `date` TEXT, `startEstimatedDate` TEXT, `endEstimatedDate` TEXT, `commissionId` TEXT NOT NULL, FOREIGN KEY(`commissionId`) REFERENCES `ordered_vehicle`(`commissionId`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 65
    .line 66
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_3
    const-string p0, "connection"

    .line 71
    .line 72
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `softwareVersion` TEXT DEFAULT NULL"

    .line 76
    .line 77
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-void

    .line 81
    :pswitch_4
    const-string p0, "connection"

    .line 82
    .line 83
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string p0, "ALTER TABLE `vehicle_status` ADD COLUMN `overall_status_lock_status` TEXT NOT NULL DEFAULT \'unknown\'"

    .line 87
    .line 88
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :pswitch_5
    const-string p0, "connection"

    .line 93
    .line 94
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    const-string p0, "ALTER TABLE `charging` ADD COLUMN `charging_status_charging_rate_in_kilometers_per_hour` REAL DEFAULT NULL"

    .line 98
    .line 99
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :pswitch_6
    const-string p0, "connection"

    .line 104
    .line 105
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string p0, "ALTER TABLE `vehicle` ADD COLUMN `connectivity_sunset_impact` TEXT DEFAULT NULL"

    .line 109
    .line 110
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :pswitch_7
    const-string p0, "connection"

    .line 115
    .line 116
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    const-string p0, "CREATE TABLE IF NOT EXISTS `_new_charging` (`vin` TEXT NOT NULL, `battery_care_mode` TEXT, `in_saved_location` INTEGER NOT NULL, `charging_errors` TEXT, `car_captured_timestamp` TEXT, `battery_statuscurrent_charged_state` INTEGER, `battery_statuscruising_range_electric` INTEGER, `charging_settings_charge_current` TEXT, `charging_settings_max_charge_current` INTEGER, `charging_settings_plug_unlock` TEXT, `charging_settings_target_charged_state` INTEGER, `charging_settings_battery_care_mode_target_value` INTEGER, `charging_status_charging_state` TEXT, `charging_status_charging_type` TEXT, `charging_status_charge_power` REAL, `charging_status_remaining_time_to_complete` INTEGER, `charge_mode_settings_available_charge_modes` TEXT, `charge_mode_settings_preferred_charge_mode` TEXT, PRIMARY KEY(`vin`))"

    .line 120
    .line 121
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    const-string p0, "INSERT INTO `_new_charging` (`vin`,`battery_care_mode`,`in_saved_location`,`charging_errors`,`car_captured_timestamp`,`battery_statuscurrent_charged_state`,`battery_statuscruising_range_electric`,`charging_settings_charge_current`,`charging_settings_max_charge_current`,`charging_settings_plug_unlock`,`charging_settings_target_charged_state`,`charging_settings_battery_care_mode_target_value`,`charging_status_charging_state`,`charging_status_charging_type`,`charging_status_charge_power`,`charging_status_remaining_time_to_complete`,`charge_mode_settings_available_charge_modes`,`charge_mode_settings_preferred_charge_mode`) SELECT `vin`,`battery_care_mode`,`in_saved_location`,`charging_errors`,`car_captured_timestamp`,`battery_statuscurrent_charged_state`,`battery_statuscruising_range_electric`,`charging_settings_charge_current`,`charging_settings_max_charge_current`,`charging_settings_plug_unlock`,`charging_settings_target_charged_state`,`charging_settings_battery_care_mode_target_value`,`charging_status_charging_state`,`charging_status_charging_type`,`charging_status_charge_power`,`charging_status_remaining_time_to_complete`,`charge_mode_settings_available_charge_modes`,`charge_mode_settings_preferred_charge_mode` FROM `charging`"

    .line 125
    .line 126
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string p0, "DROP TABLE `charging`"

    .line 130
    .line 131
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string p0, "ALTER TABLE `_new_charging` RENAME TO `charging`"

    .line 135
    .line 136
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
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
