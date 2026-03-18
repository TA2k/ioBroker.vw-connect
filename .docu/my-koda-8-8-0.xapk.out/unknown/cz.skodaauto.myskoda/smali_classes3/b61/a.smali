.class public final Lb61/a;
.super Lka/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lla/u;


# direct methods
.method public constructor <init>(Landroidx/work/impl/WorkDatabase_Impl;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lb61/a;->d:I

    iput-object p1, p0, Lb61/a;->e:Lla/u;

    .line 2
    const-string p1, "08b926448d86528e697981ddd30459f7"

    const-string v0, "149fd8ad55885d3fe3549a37a0163243"

    const/16 v1, 0x18

    .line 3
    invoke-direct {p0, p1, v1, v0}, Lka/u;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Lcz/skodaauto/myskoda/app/main/system/ApplicationDatabase_Impl;)V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Lb61/a;->d:I

    iput-object p1, p0, Lb61/a;->e:Lla/u;

    .line 4
    const-string p1, "a71c80c4b2bc821ea82200c2630dabf1"

    const-string v0, "683ce6e58719d3af7da6d4e32368c734"

    const/16 v1, 0x2d

    invoke-direct {p0, p1, v1, v0}, Lka/u;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lb61/a;->d:I

    iput-object p1, p0, Lb61/a;->e:Lla/u;

    .line 1
    const-string p1, "d9dfb9c7242ddd2a6d926b92b4445acd"

    const-string v0, "0bddfb67e8f1e80badee492d38f43482"

    const/4 v1, 0x1

    invoke-direct {p0, p1, v1, v0}, Lka/u;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    return-void
.end method

.method private final w(Lua/a;)Lco/a;
    .locals 32

    move-object/from16 v0, p1

    const-string v1, "connection"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 2
    new-instance v2, Lqa/h;

    const/4 v7, 0x0

    const/4 v4, 0x1

    const/4 v3, 0x1

    const-string v5, "vin"

    const-string v6, "TEXT"

    const/4 v8, 0x1

    invoke-direct/range {v2 .. v8}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v3, "vin"

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3
    new-instance v4, Lqa/h;

    const/4 v9, 0x0

    const/4 v6, 0x1

    const/4 v5, 0x0

    const-string v7, "state"

    const-string v8, "TEXT"

    const/4 v10, 0x1

    invoke-direct/range {v4 .. v10}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "state"

    invoke-interface {v1, v2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    new-instance v5, Lqa/h;

    const/4 v10, 0x0

    const/4 v7, 0x1

    const/4 v6, 0x0

    const-string v8, "window_heating_enabled"

    const-string v9, "INTEGER"

    const/4 v11, 0x0

    invoke-direct/range {v5 .. v11}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "window_heating_enabled"

    invoke-interface {v1, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    new-instance v6, Lqa/h;

    const/4 v11, 0x0

    const/4 v8, 0x1

    const/4 v7, 0x0

    const-string v9, "target_temperature_at"

    const-string v10, "TEXT"

    const/4 v12, 0x0

    invoke-direct/range {v6 .. v12}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "target_temperature_at"

    invoke-interface {v1, v4, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    new-instance v7, Lqa/h;

    const/4 v12, 0x0

    const/4 v9, 0x1

    const/4 v8, 0x0

    const-string v10, "air_conditioning_without_external_power"

    const-string v11, "INTEGER"

    const/4 v13, 0x0

    invoke-direct/range {v7 .. v13}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "air_conditioning_without_external_power"

    invoke-interface {v1, v4, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    new-instance v8, Lqa/h;

    const/4 v13, 0x0

    const/4 v10, 0x1

    const/4 v9, 0x0

    const-string v11, "air_conditioning_at_unlock"

    const-string v12, "INTEGER"

    const/4 v14, 0x0

    invoke-direct/range {v8 .. v14}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "air_conditioning_at_unlock"

    invoke-interface {v1, v4, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    new-instance v9, Lqa/h;

    const/4 v14, 0x0

    const/4 v11, 0x1

    const/4 v10, 0x0

    const-string v12, "steering_wheel_position"

    const-string v13, "TEXT"

    const/4 v15, 0x1

    invoke-direct/range {v9 .. v15}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "steering_wheel_position"

    invoke-interface {v1, v4, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x0

    const-string v13, "heater_source"

    const-string v14, "TEXT"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "heater_source"

    invoke-interface {v1, v4, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "charger_connection_state"

    const-string v15, "TEXT"

    const/16 v17, 0x0

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "charger_connection_state"

    invoke-interface {v1, v4, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "air_conditioning_errors"

    const-string v16, "TEXT"

    const/16 v18, 0x1

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "air_conditioning_errors"

    invoke-interface {v1, v4, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    new-instance v5, Lqa/h;

    const/4 v10, 0x0

    const/4 v7, 0x1

    const/4 v6, 0x0

    const-string v8, "car_captured_timestamp"

    const-string v9, "TEXT"

    const/4 v11, 0x0

    invoke-direct/range {v5 .. v11}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v4, "car_captured_timestamp"

    invoke-interface {v1, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    new-instance v6, Lqa/h;

    const/4 v11, 0x0

    const/4 v8, 0x1

    const/4 v7, 0x0

    const-string v9, "target_temperature_value"

    const-string v10, "REAL"

    const/4 v12, 0x0

    invoke-direct/range {v6 .. v12}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v5, "target_temperature_value"

    invoke-interface {v1, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    new-instance v7, Lqa/h;

    const/4 v12, 0x0

    const/4 v9, 0x1

    const/4 v8, 0x0

    const-string v10, "target_temperature_unit"

    const-string v11, "TEXT"

    invoke-direct/range {v7 .. v13}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v6, "target_temperature_unit"

    invoke-interface {v1, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    new-instance v8, Lqa/h;

    const/4 v13, 0x0

    const/4 v10, 0x1

    const/4 v9, 0x0

    const-string v11, "window_heating_front"

    const-string v12, "TEXT"

    invoke-direct/range {v8 .. v14}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "window_heating_front"

    invoke-interface {v1, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    new-instance v9, Lqa/h;

    const/4 v14, 0x0

    const/4 v11, 0x1

    const/4 v10, 0x0

    const-string v12, "window_heating_rear"

    const-string v13, "TEXT"

    const/4 v15, 0x1

    invoke-direct/range {v9 .. v15}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "window_heating_rear"

    invoke-interface {v1, v7, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x0

    const-string v13, "seat_heating_front_left"

    const-string v14, "INTEGER"

    const/16 v16, 0x0

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "seat_heating_front_left"

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "seat_heating_front_right"

    const-string v15, "INTEGER"

    const/16 v17, 0x0

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "seat_heating_front_right"

    invoke-interface {v1, v7, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "seat_heating_rear_left"

    const-string v16, "INTEGER"

    const/16 v18, 0x0

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "seat_heating_rear_left"

    invoke-interface {v1, v7, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/4 v14, 0x0

    const-string v16, "seat_heating_rear_right"

    const-string v17, "INTEGER"

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "seat_heating_rear_right"

    invoke-interface {v1, v7, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/4 v15, 0x0

    const-string v17, "air_conditioning_running_request_value"

    const-string v18, "TEXT"

    const/16 v20, 0x0

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "air_conditioning_running_request_value"

    invoke-interface {v1, v7, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v16, 0x0

    const-string v18, "air_conditioning_running_request_target_temperature_value"

    const-string v19, "REAL"

    const/16 v21, 0x0

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "air_conditioning_running_request_target_temperature_value"

    invoke-interface {v1, v7, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    new-instance v8, Lqa/h;

    const/4 v13, 0x0

    const/4 v10, 0x1

    const/4 v9, 0x0

    const-string v11, "air_conditioning_running_request_target_temperature_unit"

    const-string v12, "TEXT"

    const/4 v14, 0x0

    invoke-direct/range {v8 .. v14}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "air_conditioning_running_request_target_temperature_unit"

    invoke-interface {v1, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    new-instance v9, Lqa/h;

    const/4 v14, 0x0

    const/4 v11, 0x1

    const/4 v10, 0x0

    const-string v12, "air_conditioning_outside_temperaturetimestamp"

    const-string v13, "TEXT"

    const/4 v15, 0x0

    invoke-direct/range {v9 .. v15}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "air_conditioning_outside_temperaturetimestamp"

    invoke-interface {v1, v7, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x0

    const-string v13, "air_conditioning_outside_temperatureoutside_temperaturevalue"

    const-string v14, "REAL"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "air_conditioning_outside_temperatureoutside_temperaturevalue"

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "air_conditioning_outside_temperatureoutside_temperatureunit"

    const-string v15, "TEXT"

    const/16 v17, 0x0

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 27
    const-string v7, "air_conditioning_outside_temperatureoutside_temperatureunit"

    invoke-static {v1, v7, v11}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v7

    .line 28
    new-instance v8, Ljava/util/LinkedHashSet;

    invoke-direct {v8}, Ljava/util/LinkedHashSet;-><init>()V

    .line 29
    new-instance v9, Lqa/k;

    const-string v10, "air_conditioning_status"

    invoke-direct {v9, v10, v1, v7, v8}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 30
    invoke-static {v0, v10}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 31
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v7

    const-string v8, "\n Found:\n"

    const/4 v10, 0x0

    if-nez v7, :cond_0

    .line 32
    new-instance v0, Lco/a;

    .line 33
    const-string v2, "air_conditioning_status(cz.skodaauto.myskoda.library.airconditioning.data.AirConditioningStatusEntity).\n Expected:\n"

    .line 34
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 35
    invoke-direct {v0, v10, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 36
    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 37
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x1

    const-string v14, "id"

    const-string v15, "INTEGER"

    const/16 v17, 0x1

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v7, "id"

    invoke-interface {v1, v7, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "vin"

    const-string v16, "TEXT"

    const/16 v18, 0x1

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v3, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/4 v14, 0x0

    const-string v16, "enabled"

    const-string v17, "INTEGER"

    const/16 v19, 0x1

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v9, "enabled"

    invoke-interface {v1, v9, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/4 v15, 0x0

    const-string v17, "time"

    const-string v18, "TEXT"

    const/16 v20, 0x1

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v11, "time"

    invoke-interface {v1, v11, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v16, 0x0

    const-string v18, "type"

    const-string v19, "TEXT"

    const/16 v21, 0x1

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v12, "type"

    invoke-interface {v1, v12, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v17, 0x0

    const-string v19, "days"

    const-string v20, "TEXT"

    const/16 v22, 0x1

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v13, v16

    .line 43
    const-string v14, "days"

    invoke-static {v1, v14, v13}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v13

    .line 44
    new-instance v15, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v19

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v20

    const-string v16, "air_conditioning_status"

    const-string v17, "CASCADE"

    const-string v18, "NO ACTION"

    invoke-direct/range {v15 .. v20}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    invoke-interface {v13, v15}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 45
    new-instance v15, Ljava/util/LinkedHashSet;

    invoke-direct {v15}, Ljava/util/LinkedHashSet;-><init>()V

    .line 46
    new-instance v10, Lqa/j;

    move-object/from16 v16, v6

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    move-object/from16 v17, v5

    const-string v5, "ASC"

    move-object/from16 v18, v5

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    move-object/from16 v19, v14

    const-string v14, "index_air_conditioning_timers_vin"

    move-object/from16 v20, v12

    const/4 v12, 0x0

    invoke-direct {v10, v14, v6, v5, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v15, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 47
    new-instance v5, Lqa/k;

    const-string v6, "air_conditioning_timers"

    invoke-direct {v5, v6, v1, v13, v15}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 48
    invoke-static {v0, v6}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 49
    invoke-virtual {v5, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1

    .line 50
    new-instance v0, Lco/a;

    .line 51
    const-string v2, "air_conditioning_timers(cz.skodaauto.myskoda.library.airconditioning.data.AirConditioningTimerEntity).\n Expected:\n"

    .line 52
    invoke-static {v2, v5, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 53
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 54
    :cond_1
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 55
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v22, 0x1

    const-string v24, "vin"

    const-string v25, "TEXT"

    const/16 v27, 0x1

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    invoke-interface {v1, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    new-instance v21, Lqa/h;

    const/16 v22, 0x0

    const-string v24, "estimated_to_reach_target"

    const-string v25, "TEXT"

    const/16 v27, 0x0

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    const-string v6, "estimated_to_reach_target"

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    new-instance v21, Lqa/h;

    const-string v24, "state"

    const-string v25, "TEXT"

    const/16 v27, 0x1

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    invoke-interface {v1, v2, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    new-instance v21, Lqa/h;

    const-string v24, "duration"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    const-string v6, "duration"

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    new-instance v21, Lqa/h;

    const-string v24, "car_captured_timestamp"

    const-string v25, "TEXT"

    const/16 v27, 0x0

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    invoke-interface {v1, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    new-instance v21, Lqa/h;

    const-string v24, "outside_temperature_timestamp"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    const-string v10, "outside_temperature_timestamp"

    invoke-interface {v1, v10, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    new-instance v21, Lqa/h;

    const-string v24, "outside_temperature_outside_temperaturevalue"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    const-string v12, "outside_temperature_outside_temperaturevalue"

    invoke-interface {v1, v12, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    new-instance v21, Lqa/h;

    const-string v24, "outside_temperature_outside_temperatureunit"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    .line 63
    const-string v13, "outside_temperature_outside_temperatureunit"

    invoke-static {v1, v13, v5}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v5

    .line 64
    new-instance v14, Ljava/util/LinkedHashSet;

    invoke-direct {v14}, Ljava/util/LinkedHashSet;-><init>()V

    .line 65
    new-instance v15, Lqa/k;

    move-object/from16 v21, v13

    const-string v13, "active_ventilation_status"

    invoke-direct {v15, v13, v1, v5, v14}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 66
    invoke-static {v0, v13}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 67
    invoke-virtual {v15, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_2

    .line 68
    new-instance v0, Lco/a;

    .line 69
    const-string v2, "active_ventilation_status(cz.skodaauto.myskoda.feature.activeventilation.data.ActiveVentilationStatusEntity).\n Expected:\n"

    .line 70
    invoke-static {v2, v15, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 71
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 72
    :cond_2
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 73
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v23, 0x1

    const-string v25, "id"

    const-string v26, "INTEGER"

    const/16 v28, 0x1

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v22

    invoke-interface {v1, v7, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    new-instance v22, Lqa/h;

    const/16 v23, 0x0

    const-string v25, "vin"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v22

    invoke-interface {v1, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    new-instance v22, Lqa/h;

    const-string v25, "enabled"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v22

    invoke-interface {v1, v9, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    new-instance v22, Lqa/h;

    const-string v25, "time"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v22

    invoke-interface {v1, v11, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    new-instance v22, Lqa/h;

    const-string v25, "type"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v13, v20

    move-object/from16 v5, v22

    invoke-interface {v1, v13, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    new-instance v22, Lqa/h;

    const-string v25, "days"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v14, v19

    move-object/from16 v5, v22

    .line 79
    invoke-static {v1, v14, v5}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v5

    .line 80
    new-instance v22, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v26

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v27

    const-string v23, "active_ventilation_status"

    const-string v24, "CASCADE"

    const-string v25, "NO ACTION"

    invoke-direct/range {v22 .. v27}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v15, v22

    invoke-interface {v5, v15}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 81
    new-instance v15, Ljava/util/LinkedHashSet;

    invoke-direct {v15}, Ljava/util/LinkedHashSet;-><init>()V

    .line 82
    new-instance v14, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v13

    move-object/from16 v22, v11

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v11

    move-object/from16 v23, v9

    const-string v9, "index_active_ventilation_timers_vin"

    move-object/from16 v24, v12

    const/4 v12, 0x0

    invoke-direct {v14, v9, v13, v11, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v15, v14}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 83
    new-instance v9, Lqa/k;

    const-string v11, "active_ventilation_timers"

    invoke-direct {v9, v11, v1, v5, v15}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 84
    invoke-static {v0, v11}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 85
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_3

    .line 86
    new-instance v0, Lco/a;

    .line 87
    const-string v2, "active_ventilation_timers(cz.skodaauto.myskoda.feature.activeventilation.data.ActiveVentilationTimerEntity).\n Expected:\n"

    .line 88
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 89
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 90
    :cond_3
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 91
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    const/16 v31, 0x0

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    invoke-interface {v1, v7, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "timestamp"

    const-string v29, "TEXT"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v9, "timestamp"

    invoke-interface {v1, v9, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    new-instance v25, Lqa/h;

    const-string v28, "level"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v11, "level"

    invoke-interface {v1, v11, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    new-instance v25, Lqa/h;

    const-string v28, "tag"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v11, "tag"

    invoke-interface {v1, v11, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    new-instance v25, Lqa/h;

    const-string v28, "message"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    .line 96
    const-string v11, "message"

    invoke-static {v1, v11, v5}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v5

    .line 97
    new-instance v11, Ljava/util/LinkedHashSet;

    invoke-direct {v11}, Ljava/util/LinkedHashSet;-><init>()V

    .line 98
    new-instance v12, Lqa/k;

    const-string v13, "app_log"

    invoke-direct {v12, v13, v1, v5, v11}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 99
    invoke-static {v0, v13}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 100
    invoke-virtual {v12, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_4

    .line 101
    new-instance v0, Lco/a;

    .line 102
    const-string v2, "app_log(cz.skodaauto.myskoda.library.loggerpersistence.data.AppLogEntity).\n Expected:\n"

    .line 103
    invoke-static {v2, v12, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 104
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 105
    :cond_4
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 106
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v31, 0x1

    const/16 v26, 0x1

    const-string v28, "vin"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    invoke-interface {v1, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const/16 v26, 0x0

    const-string v28, "estimated_date_time_to_reach_target_temperature"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v11, "estimated_date_time_to_reach_target_temperature"

    invoke-interface {v1, v11, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    new-instance v25, Lqa/h;

    const/16 v31, 0x1

    const-string v28, "state"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    invoke-interface {v1, v2, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    new-instance v25, Lqa/h;

    const-string v28, "duration"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    new-instance v25, Lqa/h;

    const-string v28, "start_mode"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v6, "start_mode"

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const-string v28, "heating_errors"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    const-string v6, "heating_errors"

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    new-instance v25, Lqa/h;

    const-string v28, "car_captured_timestamp"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v25

    invoke-interface {v1, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    new-instance v25, Lqa/h;

    const-string v28, "target_temperature_value"

    const-string v29, "REAL"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v6, v17

    move-object/from16 v5, v25

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    new-instance v25, Lqa/h;

    const-string v28, "target_temperature_unit"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v6, v16

    move-object/from16 v5, v25

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/16 v17, 0x0

    const/4 v12, 0x0

    const-string v14, "outside_temperature_timestamp"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v10, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    new-instance v25, Lqa/h;

    const-string v28, "outside_temperature_outside_temperaturevalue"

    const-string v29, "REAL"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v6, v24

    move-object/from16 v5, v25

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x0

    const/4 v11, 0x0

    const-string v13, "outside_temperature_outside_temperatureunit"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v21

    .line 118
    invoke-static {v1, v5, v10}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v5

    .line 119
    new-instance v6, Ljava/util/LinkedHashSet;

    invoke-direct {v6}, Ljava/util/LinkedHashSet;-><init>()V

    .line 120
    new-instance v10, Lqa/k;

    const-string v11, "auxiliary_heating_status"

    invoke-direct {v10, v11, v1, v5, v6}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 121
    invoke-static {v0, v11}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 122
    invoke-virtual {v10, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_5

    .line 123
    new-instance v0, Lco/a;

    .line 124
    const-string v2, "auxiliary_heating_status(cz.skodaauto.myskoda.feature.auxiliaryheating.data.AuxiliaryHeatingStatusEntity).\n Expected:\n"

    .line 125
    invoke-static {v2, v10, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 126
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 127
    :cond_5
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 128
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x1

    const-string v13, "id"

    const-string v14, "INTEGER"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "vin"

    const-string v15, "TEXT"

    const/16 v17, 0x1

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v3, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    new-instance v24, Lqa/h;

    const/16 v29, 0x0

    const/16 v26, 0x1

    const/16 v25, 0x0

    const-string v27, "enabled"

    const-string v28, "INTEGER"

    const/16 v30, 0x1

    invoke-direct/range {v24 .. v30}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v6, v23

    move-object/from16 v5, v24

    invoke-interface {v1, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x0

    const-string v13, "time"

    const-string v14, "TEXT"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v22

    invoke-interface {v1, v5, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "type"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v13, v20

    invoke-interface {v1, v13, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    new-instance v20, Lqa/h;

    const/16 v25, 0x0

    const/16 v22, 0x1

    const/16 v21, 0x0

    const-string v23, "days"

    const-string v24, "TEXT"

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v14, v19

    move-object/from16 v10, v20

    .line 134
    invoke-static {v1, v14, v10}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v10

    .line 135
    new-instance v19, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v23

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v24

    const-string v20, "auxiliary_heating_status"

    const-string v21, "CASCADE"

    const-string v22, "NO ACTION"

    invoke-direct/range {v19 .. v24}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v11, v19

    invoke-interface {v10, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 136
    new-instance v11, Ljava/util/LinkedHashSet;

    invoke-direct {v11}, Ljava/util/LinkedHashSet;-><init>()V

    .line 137
    new-instance v12, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v15

    move-object/from16 v16, v9

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    move-object/from16 v17, v2

    const-string v2, "index_auxiliary_heating_timers_vin"

    move-object/from16 v19, v14

    const/4 v14, 0x0

    invoke-direct {v12, v2, v15, v9, v14}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v11, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 138
    new-instance v2, Lqa/k;

    const-string v9, "auxiliary_heating_timers"

    invoke-direct {v2, v9, v1, v10, v11}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 139
    invoke-static {v0, v9}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 140
    invoke-virtual {v2, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_6

    .line 141
    new-instance v0, Lco/a;

    .line 142
    const-string v3, "auxiliary_heating_timers(cz.skodaauto.myskoda.feature.auxiliaryheating.data.AuxiliaryHeatingTimerEntity).\n Expected:\n"

    .line 143
    invoke-static {v3, v2, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 144
    invoke-direct {v0, v14, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 145
    :cond_6
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 146
    new-instance v20, Lqa/h;

    const/16 v25, 0x0

    const/16 v22, 0x1

    const/16 v21, 0x1

    const-string v23, "id"

    const-string v24, "TEXT"

    const/16 v26, 0x1

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    new-instance v20, Lqa/h;

    const/16 v21, 0x0

    const-string v23, "serviceExpiration"

    const-string v24, "TEXT"

    const/16 v26, 0x0

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    const-string v9, "serviceExpiration"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 148
    new-instance v20, Lqa/h;

    const-string v23, "statuses"

    const-string v24, "TEXT"

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    const-string v9, "statuses"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    new-instance v20, Lqa/h;

    const/16 v21, 0x2

    const-string v23, "vin"

    const-string v24, "TEXT"

    const/16 v26, 0x1

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    .line 150
    invoke-static {v1, v3, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 151
    new-instance v20, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v24

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v25

    const-string v21, "vehicle"

    const-string v22, "CASCADE"

    const-string v23, "NO ACTION"

    invoke-direct/range {v20 .. v25}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v9, v20

    invoke-interface {v2, v9}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 152
    new-instance v9, Ljava/util/LinkedHashSet;

    invoke-direct {v9}, Ljava/util/LinkedHashSet;-><init>()V

    .line 153
    new-instance v10, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v11

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    const-string v14, "index_capability_vin"

    const/4 v15, 0x0

    invoke-direct {v10, v14, v11, v12, v15}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v9, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 154
    new-instance v10, Lqa/k;

    const-string v11, "capability"

    invoke-direct {v10, v11, v1, v2, v9}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 155
    invoke-static {v0, v11}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 156
    invoke-virtual {v10, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_7

    .line 157
    new-instance v0, Lco/a;

    .line 158
    const-string v2, "capability(cz.skodaauto.myskoda.library.deliveredvehicle.data.CapabilityEntity).\n Expected:\n"

    .line 159
    invoke-static {v2, v10, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 160
    invoke-direct {v0, v15, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 161
    :cond_7
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 162
    new-instance v20, Lqa/h;

    const/16 v25, 0x0

    const/16 v22, 0x1

    const/16 v21, 0x1

    const-string v23, "type"

    const-string v24, "TEXT"

    const/16 v26, 0x1

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    invoke-interface {v1, v13, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    new-instance v20, Lqa/h;

    const/16 v21, 0x0

    const-string v23, "description"

    const-string v24, "TEXT"

    const/16 v26, 0x0

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    const-string v9, "description"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 164
    new-instance v20, Lqa/h;

    const/16 v21, 0x2

    const-string v23, "vin"

    const-string v24, "TEXT"

    const/16 v26, 0x1

    invoke-direct/range {v20 .. v26}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v20

    .line 165
    invoke-static {v1, v3, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 166
    new-instance v20, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v24

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v25

    const-string v21, "vehicle"

    const-string v22, "CASCADE"

    const-string v23, "NO ACTION"

    invoke-direct/range {v20 .. v25}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v10, v20

    invoke-interface {v2, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 167
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 168
    new-instance v11, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v14

    const-string v15, "index_capability_error_vin"

    move-object/from16 v20, v9

    const/4 v9, 0x0

    invoke-direct {v11, v15, v12, v14, v9}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v10, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 169
    new-instance v11, Lqa/k;

    const-string v12, "capability_error"

    invoke-direct {v11, v12, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 170
    invoke-static {v0, v12}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 171
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_8

    .line 172
    new-instance v0, Lco/a;

    .line 173
    const-string v2, "capability_error(cz.skodaauto.myskoda.library.deliveredvehicle.data.CapabilityErrorEntity).\n Expected:\n"

    .line 174
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 175
    invoke-direct {v0, v9, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 176
    :cond_8
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 177
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v27, 0x1

    const/16 v22, 0x1

    const-string v24, "id"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    new-instance v21, Lqa/h;

    const/16 v22, 0x0

    const-string v24, "profile_id"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v9, "profile_id"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 179
    new-instance v21, Lqa/h;

    const-string v24, "vin"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    new-instance v21, Lqa/h;

    const-string v24, "name"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "name"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    new-instance v21, Lqa/h;

    const/16 v27, 0x0

    const-string v24, "location_lat"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v11, "location_lat"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    new-instance v21, Lqa/h;

    const-string v24, "location_lng"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v11, "location_lng"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 183
    new-instance v21, Lqa/h;

    const-string v24, "settings_min_battery_charged_state"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v11, "settings_min_battery_charged_state"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 184
    new-instance v21, Lqa/h;

    const-string v24, "settings_target_charged_state"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v11, "settings_target_charged_state"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    new-instance v21, Lqa/h;

    const-string v24, "settings_reduced_current_active"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v11, "settings_reduced_current_active"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    new-instance v21, Lqa/h;

    const-string v24, "settings_cable_lock_active"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    .line 187
    const-string v11, "settings_cable_lock_active"

    invoke-static {v1, v11, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 188
    new-instance v21, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v25

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v26

    const-string v22, "charging_profiles"

    const-string v23, "CASCADE"

    const-string v24, "CASCADE"

    invoke-direct/range {v21 .. v26}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v11, v21

    invoke-interface {v2, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 189
    new-instance v11, Ljava/util/LinkedHashSet;

    invoke-direct {v11}, Ljava/util/LinkedHashSet;-><init>()V

    .line 190
    new-instance v12, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v14

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v15

    move-object/from16 v21, v10

    const-string v10, "index_charging_profile_vin"

    move-object/from16 v22, v13

    const/4 v13, 0x0

    invoke-direct {v12, v10, v14, v15, v13}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v11, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 191
    new-instance v10, Lqa/j;

    filled-new-array {v9, v3}, [Ljava/lang/String;

    move-result-object v12

    invoke-static {v12}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    move-object/from16 v13, v18

    filled-new-array {v13, v13}, [Ljava/lang/String;

    move-result-object v14

    invoke-static {v14}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v14

    const/4 v15, 0x1

    const-string v13, "index_charging_profile_profile_id_vin"

    invoke-direct {v10, v13, v12, v14, v15}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v11, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 192
    new-instance v10, Lqa/k;

    const-string v12, "charging_profile"

    invoke-direct {v10, v12, v1, v2, v11}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 193
    invoke-static {v0, v12}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 194
    invoke-virtual {v10, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_9

    .line 195
    new-instance v0, Lco/a;

    .line 196
    const-string v2, "charging_profile(cz.skodaauto.myskoda.library.charging.data.ChargingProfileEntity).\n Expected:\n"

    .line 197
    invoke-static {v2, v10, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 198
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 199
    :cond_9
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 200
    new-instance v23, Lqa/h;

    const/16 v28, 0x0

    const/16 v25, 0x1

    const/16 v24, 0x1

    const-string v26, "id"

    const-string v27, "INTEGER"

    const/16 v29, 0x1

    invoke-direct/range {v23 .. v29}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v23

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    new-instance v23, Lqa/h;

    const/16 v24, 0x2

    const-string v26, "profile_id"

    const-string v27, "INTEGER"

    invoke-direct/range {v23 .. v29}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v23

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    new-instance v23, Lqa/h;

    const/16 v24, 0x0

    const-string v26, "enabled"

    const-string v27, "INTEGER"

    invoke-direct/range {v23 .. v29}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v23

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 203
    new-instance v23, Lqa/h;

    const-string v26, "start_time"

    const-string v27, "TEXT"

    invoke-direct/range {v23 .. v29}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v23

    const-string v10, "start_time"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    new-instance v23, Lqa/h;

    const-string v26, "end_time"

    const-string v27, "TEXT"

    invoke-direct/range {v23 .. v29}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v23

    .line 205
    const-string v11, "end_time"

    invoke-static {v1, v11, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 206
    new-instance v23, Lqa/i;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v27

    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v28

    const-string v24, "charging_profile"

    const-string v25, "CASCADE"

    const-string v26, "CASCADE"

    invoke-direct/range {v23 .. v28}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v12, v23

    invoke-interface {v2, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 207
    new-instance v12, Ljava/util/LinkedHashSet;

    invoke-direct {v12}, Ljava/util/LinkedHashSet;-><init>()V

    .line 208
    new-instance v13, Lqa/j;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v14

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v15

    move-object/from16 v23, v11

    const-string v11, "index_charging_profile_charging_time_profile_id"

    move-object/from16 v24, v10

    const/4 v10, 0x0

    invoke-direct {v13, v11, v14, v15, v10}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v12, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 209
    new-instance v11, Lqa/k;

    const-string v13, "charging_profile_charging_time"

    invoke-direct {v11, v13, v1, v2, v12}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 210
    invoke-static {v0, v13}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 211
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_a

    .line 212
    new-instance v0, Lco/a;

    .line 213
    const-string v2, "charging_profile_charging_time(cz.skodaauto.myskoda.library.charging.data.ChargingProfileChargingTimeEntity).\n Expected:\n"

    .line 214
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 215
    invoke-direct {v0, v10, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 216
    :cond_a
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 217
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "vin"

    const-string v29, "TEXT"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 218
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "current_profile_id"

    const-string v29, "INTEGER"

    const/16 v31, 0x0

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "current_profile_id"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 219
    new-instance v25, Lqa/h;

    const-string v28, "next_timer_time"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "next_timer_time"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 220
    new-instance v25, Lqa/h;

    const-string v28, "car_captured_timestamp"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 221
    invoke-static {v1, v4, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 222
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 223
    new-instance v11, Lqa/k;

    const-string v12, "charging_profiles"

    invoke-direct {v11, v12, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 224
    invoke-static {v0, v12}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 225
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_b

    .line 226
    new-instance v0, Lco/a;

    .line 227
    const-string v2, "charging_profiles(cz.skodaauto.myskoda.library.charging.data.ChargingProfilesEntity).\n Expected:\n"

    .line 228
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 229
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 230
    :cond_b
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 231
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 232
    new-instance v25, Lqa/h;

    const/16 v26, 0x2

    const-string v28, "profile_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 234
    new-instance v25, Lqa/h;

    const-string v28, "time"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    new-instance v25, Lqa/h;

    const-string v28, "type"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v13, v22

    move-object/from16 v2, v25

    invoke-interface {v1, v13, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    new-instance v25, Lqa/h;

    const-string v28, "days"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v14, v19

    move-object/from16 v2, v25

    invoke-interface {v1, v14, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 237
    new-instance v25, Lqa/h;

    const-string v30, "false"

    const-string v28, "start_air_condition"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 238
    const-string v5, "start_air_condition"

    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 239
    new-instance v25, Lqa/i;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v29

    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v30

    const-string v26, "charging_profile"

    const-string v27, "CASCADE"

    const-string v28, "CASCADE"

    invoke-direct/range {v25 .. v30}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v5, v25

    invoke-interface {v2, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 240
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 241
    new-instance v10, Lqa/j;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v11

    const-string v12, "index_charging_profile_timer_profile_id"

    const/4 v14, 0x0

    invoke-direct {v10, v12, v9, v11, v14}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v5, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 242
    new-instance v9, Lqa/k;

    const-string v10, "charging_profile_timer"

    invoke-direct {v9, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 243
    invoke-static {v0, v10}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 244
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_c

    .line 245
    new-instance v0, Lco/a;

    .line 246
    const-string v2, "charging_profile_timer(cz.skodaauto.myskoda.library.charging.data.ChargingProfileTimerEntity).\n Expected:\n"

    .line 247
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 248
    invoke-direct {v0, v14, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 249
    :cond_c
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 250
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 251
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "vehicle_id"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v5, "vehicle_id"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    new-instance v25, Lqa/h;

    const-string v28, "vehicle_type"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v5, "vehicle_type"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 253
    new-instance v25, Lqa/h;

    const-string v28, "view_type"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "view_type"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 254
    new-instance v25, Lqa/h;

    const-string v28, "modifications_adjust_space_left"

    const-string v29, "INTEGER"

    const/16 v31, 0x0

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "modifications_adjust_space_left"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    new-instance v25, Lqa/h;

    const-string v28, "modifications_adjust_space_right"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "modifications_adjust_space_right"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 256
    new-instance v25, Lqa/h;

    const-string v28, "modifications_adjust_space_top"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "modifications_adjust_space_top"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 257
    new-instance v25, Lqa/h;

    const-string v28, "modifications_adjust_space_bottom"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "modifications_adjust_space_bottom"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    new-instance v25, Lqa/h;

    const-string v28, "modifications_flip_horizontal"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "modifications_flip_horizontal"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    new-instance v25, Lqa/h;

    const-string v28, "modifications_anchor_to"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 260
    const-string v9, "modifications_anchor_to"

    invoke-static {v1, v9, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 261
    new-instance v9, Ljava/util/LinkedHashSet;

    invoke-direct {v9}, Ljava/util/LinkedHashSet;-><init>()V

    .line 262
    new-instance v10, Lqa/k;

    const-string v11, "composite_render"

    invoke-direct {v10, v11, v1, v2, v9}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 263
    invoke-static {v0, v11}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 264
    invoke-virtual {v10, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_d

    .line 265
    new-instance v0, Lco/a;

    .line 266
    const-string v2, "composite_render(cz.skodaauto.myskoda.library.render.data.CompositeRenderEntity).\n Expected:\n"

    .line 267
    invoke-static {v2, v10, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 268
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 269
    :cond_d
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 270
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 271
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "composite_render_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "composite_render_id"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    new-instance v25, Lqa/h;

    const-string v28, "url"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "url"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 273
    new-instance v25, Lqa/h;

    const-string v28, "order"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 274
    const-string v10, "order"

    invoke-static {v1, v10, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 275
    new-instance v25, Lqa/i;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v29

    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v30

    const-string v26, "composite_render"

    const-string v27, "CASCADE"

    const-string v28, "NO ACTION"

    invoke-direct/range {v25 .. v30}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v10, v25

    invoke-interface {v2, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 276
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 277
    new-instance v11, Lqa/j;

    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    const-string v14, "index_composite_render_layer_composite_render_id"

    const/4 v15, 0x0

    invoke-direct {v11, v14, v9, v12, v15}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v10, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 278
    new-instance v9, Lqa/k;

    const-string v11, "composite_render_layer"

    invoke-direct {v9, v11, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 279
    invoke-static {v0, v11}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 280
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_e

    .line 281
    new-instance v0, Lco/a;

    .line 282
    const-string v2, "composite_render_layer(cz.skodaauto.myskoda.library.render.data.CompositeRenderLayerEntity).\n Expected:\n"

    .line 283
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    .line 284
    invoke-direct {v0, v15, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 285
    :cond_e
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 286
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v31, 0x1

    const/16 v26, 0x1

    const-string v28, "vin"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 287
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "systemModelId"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v9, "systemModelId"

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 288
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const-string v28, "name"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v9, v21

    move-object/from16 v2, v25

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 289
    new-instance v25, Lqa/h;

    const/16 v31, 0x1

    const-string v28, "title"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "title"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const-string v28, "licensePlate"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "licensePlate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 291
    new-instance v25, Lqa/h;

    const/16 v31, 0x1

    const-string v28, "state"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v10, v17

    move-object/from16 v2, v25

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 292
    new-instance v25, Lqa/h;

    const-string v28, "devicePlatform"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "devicePlatform"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 293
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const-string v28, "softwareVersion"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "softwareVersion"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 294
    new-instance v25, Lqa/h;

    const-string v28, "connectivity_sunset_impact"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "connectivity_sunset_impact"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 295
    new-instance v25, Lqa/h;

    const-string v30, "false"

    const/16 v31, 0x1

    const-string v28, "isWorkshopMode"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "isWorkshopMode"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 296
    new-instance v25, Lqa/h;

    const-string v30, "0"

    const-string v28, "priority"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "priority"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v31, 0x0

    const-string v28, "spec_title"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_title"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    new-instance v25, Lqa/h;

    const-string v28, "spec_systemCode"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_systemCode"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 299
    new-instance v25, Lqa/h;

    const-string v28, "spec_systemModelId"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_systemModelId"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    new-instance v25, Lqa/h;

    const-string v28, "spec_model"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_model"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 301
    new-instance v25, Lqa/h;

    const-string v28, "spec_manufacturingDate"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_manufacturingDate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 302
    new-instance v25, Lqa/h;

    const-string v28, "spec_gearboxType"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_gearboxType"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 303
    new-instance v25, Lqa/h;

    const-string v28, "spec_modelYear"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_modelYear"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 304
    new-instance v25, Lqa/h;

    const-string v28, "spec_body"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_body"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 305
    new-instance v25, Lqa/h;

    const-string v28, "spec_batteryCapacity"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_batteryCapacity"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 306
    new-instance v25, Lqa/h;

    const-string v28, "spec_trimLevel"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_trimLevel"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    new-instance v25, Lqa/h;

    const-string v28, "spec_maxChargingPowerInKW"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_maxChargingPowerInKW"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 308
    new-instance v25, Lqa/h;

    const-string v28, "spec_colour"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_colour"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 309
    new-instance v25, Lqa/h;

    const-string v28, "spec_length"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_length"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 310
    new-instance v25, Lqa/h;

    const-string v28, "spec_width"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_width"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 311
    new-instance v25, Lqa/h;

    const-string v28, "spec_height"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_height"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 312
    new-instance v25, Lqa/h;

    const-string v28, "spec_enginepowerInKW"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_enginepowerInKW"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 313
    new-instance v25, Lqa/h;

    const-string v28, "spec_enginetype"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_enginetype"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 314
    new-instance v25, Lqa/h;

    const-string v28, "spec_enginecapacityInLiters"

    const-string v29, "REAL"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "spec_enginecapacityInLiters"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    new-instance v25, Lqa/h;

    const-string v28, "servicePartner_id"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 316
    const-string v10, "servicePartner_id"

    invoke-static {v1, v10, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 317
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 318
    new-instance v11, Lqa/k;

    const-string v12, "vehicle"

    invoke-direct {v11, v12, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 319
    const-string v1, "vehicle"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 320
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_f

    .line 321
    new-instance v0, Lco/a;

    .line 322
    const-string v2, "vehicle(cz.skodaauto.myskoda.library.deliveredvehicle.data.DeliveredVehicleEntity).\n Expected:\n"

    .line 323
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 324
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 325
    :cond_f
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 326
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "vin"

    const-string v29, "TEXT"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 327
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "target_temperature_celsius"

    const-string v29, "REAL"

    const/16 v31, 0x0

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "target_temperature_celsius"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    new-instance v25, Lqa/h;

    const-string v28, "min_battery_charged_state_percent"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "min_battery_charged_state_percent"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 329
    new-instance v25, Lqa/h;

    const-string v28, "first_occurring_timer_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "first_occurring_timer_id"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    new-instance v25, Lqa/h;

    const-string v28, "car_captured_timestamp"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 331
    invoke-static {v1, v4, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 332
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 333
    new-instance v11, Lqa/k;

    const-string v12, "departure_plan"

    invoke-direct {v11, v12, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 334
    const-string v1, "departure_plan"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 335
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_10

    .line 336
    new-instance v0, Lco/a;

    .line 337
    const-string v2, "departure_plan(cz.skodaauto.myskoda.feature.departuretimers.data.DeparturePlanEntity).\n Expected:\n"

    .line 338
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 339
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 340
    :cond_10
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 341
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v31, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 342
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "vin"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 343
    new-instance v25, Lqa/h;

    const-string v28, "index"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "index"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 344
    new-instance v25, Lqa/h;

    const-string v28, "is_enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "is_enabled"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 345
    new-instance v25, Lqa/h;

    const-string v28, "is_charging_enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "is_charging_enabled"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 346
    new-instance v25, Lqa/h;

    const-string v28, "is_air_conditioning_enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "is_air_conditioning_enabled"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 347
    new-instance v25, Lqa/h;

    const/16 v31, 0x0

    const-string v28, "target_charged_state"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "target_charged_state"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 348
    new-instance v25, Lqa/h;

    const/16 v31, 0x1

    const-string v28, "timer_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v10, "timer_id"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 349
    new-instance v25, Lqa/h;

    const-string v28, "timer_enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v11, "timer_enabled"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 350
    new-instance v25, Lqa/h;

    const-string v28, "timer_time"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v11, "timer_time"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 351
    new-instance v25, Lqa/h;

    const-string v28, "timer_type"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v11, "timer_type"

    invoke-interface {v1, v11, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 352
    new-instance v25, Lqa/h;

    const-string v28, "timer_days"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    .line 353
    const-string v11, "timer_days"

    invoke-static {v1, v11, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 354
    new-instance v25, Lqa/i;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v29

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v30

    const-string v26, "departure_plan"

    const-string v27, "CASCADE"

    const-string v28, "CASCADE"

    invoke-direct/range {v25 .. v30}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v11, v25

    invoke-interface {v2, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 355
    new-instance v11, Ljava/util/LinkedHashSet;

    invoke-direct {v11}, Ljava/util/LinkedHashSet;-><init>()V

    .line 356
    new-instance v12, Lqa/j;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v14

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v15

    move-object/from16 v17, v5

    const-string v5, "index_departure_timer_vin"

    move-object/from16 v21, v9

    const/4 v9, 0x0

    invoke-direct {v12, v5, v14, v15, v9}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v11, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 357
    new-instance v5, Lqa/k;

    const-string v9, "departure_timer"

    invoke-direct {v5, v9, v1, v2, v11}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 358
    const-string v1, "departure_timer"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 359
    invoke-virtual {v5, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11

    .line 360
    new-instance v0, Lco/a;

    .line 361
    const-string v2, "departure_timer(cz.skodaauto.myskoda.feature.departuretimers.data.DepartureTimerEntity).\n Expected:\n"

    .line 362
    invoke-static {v2, v5, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 363
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 364
    :cond_11
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 365
    new-instance v25, Lqa/h;

    const/16 v30, 0x0

    const/16 v27, 0x1

    const/16 v26, 0x1

    const-string v28, "id"

    const-string v29, "INTEGER"

    const/16 v31, 0x1

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 366
    new-instance v25, Lqa/h;

    const/16 v26, 0x0

    const-string v28, "timer_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 367
    new-instance v25, Lqa/h;

    const-string v28, "charging_time_id"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    const-string v5, "charging_time_id"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 368
    new-instance v25, Lqa/h;

    const-string v28, "enabled"

    const-string v29, "INTEGER"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v25

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 369
    new-instance v25, Lqa/h;

    const-string v28, "start_time"

    const-string v29, "TEXT"

    invoke-direct/range {v25 .. v31}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v24

    move-object/from16 v2, v25

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    new-instance v24, Lqa/h;

    const/16 v29, 0x0

    const/16 v26, 0x1

    const/16 v25, 0x0

    const-string v27, "end_time"

    const-string v28, "TEXT"

    const/16 v30, 0x1

    invoke-direct/range {v24 .. v30}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v23

    move-object/from16 v2, v24

    .line 371
    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 372
    new-instance v22, Lqa/i;

    invoke-static {v10}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v26

    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v27

    const-string v23, "departure_timer"

    const-string v24, "CASCADE"

    const-string v25, "CASCADE"

    invoke-direct/range {v22 .. v27}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v5, v22

    invoke-interface {v2, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 373
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 374
    new-instance v6, Lqa/j;

    invoke-static {v10}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v10

    const-string v11, "index_departure_charging_time_timer_id"

    const/4 v12, 0x0

    invoke-direct {v6, v11, v9, v10, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v5, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 375
    new-instance v6, Lqa/k;

    const-string v9, "departure_charging_time"

    invoke-direct {v6, v9, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 376
    const-string v1, "departure_charging_time"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 377
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_12

    .line 378
    new-instance v0, Lco/a;

    .line 379
    const-string v2, "departure_charging_time(cz.skodaauto.myskoda.feature.departuretimers.data.DepartureChargingTimeEntity).\n Expected:\n"

    .line 380
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 381
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 382
    :cond_12
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 383
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v23, 0x1

    const-string v25, "vin"

    const-string v26, "TEXT"

    const/16 v28, 0x1

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 384
    new-instance v22, Lqa/h;

    const/16 v23, 0x0

    const-string v25, "fleet"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    .line 385
    const-string v5, "fleet"

    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 386
    new-instance v6, Ljava/util/LinkedHashSet;

    invoke-direct {v6}, Ljava/util/LinkedHashSet;-><init>()V

    .line 387
    new-instance v9, Lqa/k;

    invoke-direct {v9, v5, v1, v2, v6}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 388
    invoke-static {v0, v5}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 389
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_13

    .line 390
    new-instance v0, Lco/a;

    .line 391
    const-string v2, "fleet(cz.skodaauto.myskoda.feature.fleet.data.FleetEntity).\n Expected:\n"

    .line 392
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 393
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 394
    :cond_13
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 395
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v28, 0x1

    const/16 v23, 0x1

    const-string v25, "vin"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 396
    new-instance v22, Lqa/h;

    const/16 v28, 0x0

    const/16 v23, 0x0

    const-string v25, "battery_care_mode"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "battery_care_mode"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 397
    new-instance v22, Lqa/h;

    const/16 v28, 0x1

    const-string v25, "in_saved_location"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "in_saved_location"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 398
    new-instance v22, Lqa/h;

    const/16 v28, 0x0

    const-string v25, "charging_errors"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_errors"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 399
    new-instance v22, Lqa/h;

    const-string v25, "car_captured_timestamp"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    invoke-interface {v1, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 400
    new-instance v22, Lqa/h;

    const-string v25, "battery_statuscurrent_charged_state"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "battery_statuscurrent_charged_state"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 401
    new-instance v22, Lqa/h;

    const-string v25, "battery_statuscruising_range_electric"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "battery_statuscruising_range_electric"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 402
    new-instance v22, Lqa/h;

    const-string v25, "charging_settings_charge_current"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_settings_charge_current"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 403
    new-instance v22, Lqa/h;

    const-string v25, "charging_settings_max_charge_current"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_settings_max_charge_current"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 404
    new-instance v22, Lqa/h;

    const-string v25, "charging_settings_plug_unlock"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_settings_plug_unlock"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    new-instance v22, Lqa/h;

    const-string v25, "charging_settings_target_charged_state"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_settings_target_charged_state"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 406
    new-instance v22, Lqa/h;

    const-string v25, "charging_settings_battery_care_mode_target_value"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_settings_battery_care_mode_target_value"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 407
    new-instance v22, Lqa/h;

    const-string v25, "charging_status_charging_state"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_status_charging_state"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 408
    new-instance v22, Lqa/h;

    const-string v25, "charging_status_charging_type"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_status_charging_type"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 409
    new-instance v22, Lqa/h;

    const-string v25, "charging_status_charge_power"

    const-string v26, "REAL"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_status_charge_power"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 410
    new-instance v22, Lqa/h;

    const-string v25, "charging_status_remaining_time_to_complete"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_status_remaining_time_to_complete"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 411
    new-instance v22, Lqa/h;

    const-string v25, "charging_status_charging_rate_in_kilometers_per_hour"

    const-string v26, "REAL"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charging_status_charging_rate_in_kilometers_per_hour"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 412
    new-instance v22, Lqa/h;

    const-string v25, "charge_mode_settings_available_charge_modes"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "charge_mode_settings_available_charge_modes"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 413
    new-instance v22, Lqa/h;

    const-string v25, "charge_mode_settings_preferred_charge_mode"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    .line 414
    const-string v5, "charge_mode_settings_preferred_charge_mode"

    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 415
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 416
    new-instance v6, Lqa/k;

    const-string v9, "charging"

    invoke-direct {v6, v9, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 417
    const-string v1, "charging"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 418
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_14

    .line 419
    new-instance v0, Lco/a;

    .line 420
    const-string v2, "charging(cz.skodaauto.myskoda.library.charging.data.ChargingEntity).\n Expected:\n"

    .line 421
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 422
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 423
    :cond_14
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 424
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v23, 0x1

    const-string v25, "id"

    const-string v26, "INTEGER"

    const/16 v28, 0x1

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 425
    new-instance v22, Lqa/h;

    const/16 v23, 0x0

    const-string v25, "type"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    .line 426
    invoke-static {v1, v13, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 427
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 428
    new-instance v6, Lqa/k;

    const-string v9, "map_tile_type"

    invoke-direct {v6, v9, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 429
    const-string v1, "map_tile_type"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 430
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_15

    .line 431
    new-instance v0, Lco/a;

    .line 432
    const-string v2, "map_tile_type(cz.skodaauto.myskoda.library.map.data.MapTileTypeEntity).\n Expected:\n"

    .line 433
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 434
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 435
    :cond_15
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 436
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v28, 0x1

    const/16 v23, 0x1

    const-string v25, "id"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 437
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const/16 v23, 0x0

    const-string v25, "service_label"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "service_label"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 438
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "exception"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "exception"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 439
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "response_body"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_body"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 440
    new-instance v22, Lqa/h;

    const-string v27, "0"

    const-string v25, "response_code"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_code"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 441
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "response_headers"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_headers"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 442
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "response_message"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_message"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 443
    new-instance v22, Lqa/h;

    const-string v27, "0"

    const-string v25, "response_time"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_time"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 444
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "response_url"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "response_url"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 445
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_body"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_body"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 446
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_headers"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_headers"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 447
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_method"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_method"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 448
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_protocol"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_protocol"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 449
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_state"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_state"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 450
    new-instance v22, Lqa/h;

    const-string v27, "\'\'"

    const-string v25, "request_url"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "request_url"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const-string v25, "log_type"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v5, "log_type"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 452
    new-instance v22, Lqa/h;

    const-string v27, "0"

    const-string v25, "timestamp"

    const-string v26, "INTEGER"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v16

    move-object/from16 v2, v22

    .line 453
    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 454
    new-instance v6, Ljava/util/LinkedHashSet;

    invoke-direct {v6}, Ljava/util/LinkedHashSet;-><init>()V

    .line 455
    new-instance v9, Lqa/k;

    const-string v10, "network_log"

    invoke-direct {v9, v10, v1, v2, v6}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 456
    const-string v1, "network_log"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 457
    invoke-virtual {v9, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_16

    .line 458
    new-instance v0, Lco/a;

    .line 459
    const-string v2, "network_log(cz.skodaauto.myskoda.library.networklogger.data.NetworkLogEntity).\n Expected:\n"

    .line 460
    invoke-static {v2, v9, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 461
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 462
    :cond_16
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 463
    new-instance v22, Lqa/h;

    const/16 v27, 0x0

    const/16 v24, 0x1

    const/16 v28, 0x1

    const/16 v23, 0x1

    const-string v25, "commissionId"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v22

    const-string v6, "commissionId"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 464
    new-instance v22, Lqa/h;

    const/16 v23, 0x0

    const-string v25, "name"

    const-string v26, "TEXT"

    invoke-direct/range {v22 .. v28}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v9, v21

    move-object/from16 v2, v22

    invoke-interface {v1, v9, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 465
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v27, 0x0

    const/16 v22, 0x0

    const-string v24, "vin"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 466
    new-instance v21, Lqa/h;

    const-string v24, "dealerId"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "dealerId"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 467
    new-instance v21, Lqa/h;

    const-string v26, "0"

    const/16 v27, 0x1

    const-string v24, "priority"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "priority"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 468
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const-string v24, "activationStatus"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "activationStatus"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 469
    new-instance v21, Lqa/h;

    const-string v24, "orderStatus"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "orderStatus"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 470
    new-instance v21, Lqa/h;

    const/16 v27, 0x0

    const-string v24, "startDeliveryDate"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "startDeliveryDate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 471
    new-instance v21, Lqa/h;

    const-string v24, "endDeliveryDate"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "endDeliveryDate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 472
    new-instance v21, Lqa/h;

    const-string v24, "spec_model"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_model"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 473
    new-instance v21, Lqa/h;

    const-string v24, "spec_trimLevel"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_trimLevel"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 474
    new-instance v21, Lqa/h;

    const-string v24, "spec_engine"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_engine"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 475
    new-instance v21, Lqa/h;

    const-string v24, "spec_exteriorColor"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_exteriorColor"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 476
    new-instance v21, Lqa/h;

    const-string v24, "spec_interiorColor"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_interiorColor"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 477
    new-instance v21, Lqa/h;

    const-string v24, "spec_batteryCapacity"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_batteryCapacity"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 478
    new-instance v21, Lqa/h;

    const-string v24, "spec_maxPerformanceInKW"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_maxPerformanceInKW"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 479
    new-instance v21, Lqa/h;

    const-string v24, "spec_wltpRangeInM"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_wltpRangeInM"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 480
    new-instance v21, Lqa/h;

    const-string v24, "spec_consumptionInLitPer100km"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_consumptionInLitPer100km"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 481
    new-instance v21, Lqa/h;

    const-string v24, "spec_consumptionInkWhPer100km"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "spec_consumptionInkWhPer100km"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 482
    new-instance v21, Lqa/h;

    const-string v24, "spec_consumptionInKgPer100km"

    const-string v25, "REAL"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    .line 483
    const-string v10, "spec_consumptionInKgPer100km"

    invoke-static {v1, v10, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 484
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 485
    new-instance v11, Lqa/k;

    const-string v12, "ordered_vehicle"

    invoke-direct {v11, v12, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 486
    const-string v1, "ordered_vehicle"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 487
    invoke-virtual {v11, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_17

    .line 488
    new-instance v0, Lco/a;

    .line 489
    const-string v2, "ordered_vehicle(cz.skodaauto.myskoda.library.orderedvehicle.data.OrderedVehicleEntity).\n Expected:\n"

    .line 490
    invoke-static {v2, v11, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 491
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 492
    :cond_17
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 493
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v22, 0x1

    const-string v24, "id"

    const-string v25, "INTEGER"

    const/16 v27, 0x1

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 494
    new-instance v21, Lqa/h;

    const/16 v22, 0x0

    const-string v24, "orderStatus"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "orderStatus"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 495
    new-instance v21, Lqa/h;

    const-string v24, "date"

    const-string v25, "TEXT"

    const/16 v27, 0x0

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "date"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 496
    new-instance v21, Lqa/h;

    const-string v24, "startEstimatedDate"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "startEstimatedDate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 497
    new-instance v21, Lqa/h;

    const-string v24, "endEstimatedDate"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v10, "endEstimatedDate"

    invoke-interface {v1, v10, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 498
    new-instance v21, Lqa/h;

    const-string v24, "commissionId"

    const-string v25, "TEXT"

    const/16 v27, 0x1

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    .line 499
    invoke-static {v1, v6, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 500
    new-instance v21, Lqa/i;

    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v25

    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v26

    const-string v22, "ordered_vehicle"

    const-string v23, "CASCADE"

    const-string v24, "NO ACTION"

    invoke-direct/range {v21 .. v26}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    move-object/from16 v10, v21

    invoke-interface {v2, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 501
    new-instance v10, Ljava/util/LinkedHashSet;

    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 502
    new-instance v11, Lqa/j;

    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    const-string v14, "index_order_checkpoint_commissionId"

    const/4 v15, 0x0

    invoke-direct {v11, v14, v6, v12, v15}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    invoke-interface {v10, v11}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 503
    new-instance v6, Lqa/k;

    const-string v11, "order_checkpoint"

    invoke-direct {v6, v11, v1, v2, v10}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 504
    const-string v1, "order_checkpoint"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 505
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_18

    .line 506
    new-instance v0, Lco/a;

    .line 507
    const-string v2, "order_checkpoint(cz.skodaauto.myskoda.library.orderedvehicle.data.OrderCheckpointEntity).\n Expected:\n"

    .line 508
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 509
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 510
    :cond_18
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 511
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v27, 0x1

    const/16 v22, 0x1

    const-string v24, "vin"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 512
    new-instance v21, Lqa/h;

    const/16 v22, 0x0

    const-string v24, "car_type"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "car_type"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 513
    new-instance v21, Lqa/h;

    const/16 v27, 0x0

    const-string v24, "ad_blue_range"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "ad_blue_range"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 514
    new-instance v21, Lqa/h;

    const-string v24, "total_range"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "total_range"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 515
    new-instance v21, Lqa/h;

    const-string v24, "car_captured_timestamp"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 516
    new-instance v21, Lqa/h;

    const/16 v27, 0x1

    const-string v24, "primary_engine_engine_type"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "primary_engine_engine_type"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 517
    new-instance v21, Lqa/h;

    const/16 v27, 0x0

    const-string v24, "primary_engine_current_soc_in_pct"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "primary_engine_current_soc_in_pct"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 518
    new-instance v21, Lqa/h;

    const-string v24, "primary_engine_current_fuel_level_pct"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "primary_engine_current_fuel_level_pct"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 519
    new-instance v21, Lqa/h;

    const-string v24, "primary_engine_remaining_range"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "primary_engine_remaining_range"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 520
    new-instance v21, Lqa/h;

    const-string v24, "secondary_engine_engine_type"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "secondary_engine_engine_type"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 521
    new-instance v21, Lqa/h;

    const-string v24, "secondary_engine_current_soc_in_pct"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "secondary_engine_current_soc_in_pct"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 522
    new-instance v21, Lqa/h;

    const-string v24, "secondary_engine_current_fuel_level_pct"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    const-string v6, "secondary_engine_current_fuel_level_pct"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 523
    new-instance v21, Lqa/h;

    const-string v24, "secondary_engine_remaining_range"

    const-string v25, "INTEGER"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    .line 524
    const-string v6, "secondary_engine_remaining_range"

    invoke-static {v1, v6, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 525
    new-instance v6, Ljava/util/LinkedHashSet;

    invoke-direct {v6}, Ljava/util/LinkedHashSet;-><init>()V

    .line 526
    new-instance v10, Lqa/k;

    const-string v11, "range_ice"

    invoke-direct {v10, v11, v1, v2, v6}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 527
    const-string v1, "range_ice"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 528
    invoke-virtual {v10, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_19

    .line 529
    new-instance v0, Lco/a;

    .line 530
    const-string v2, "range_ice(cz.skodaauto.myskoda.library.rangeice.data.RangeIceStatusEntity).\n Expected:\n"

    .line 531
    invoke-static {v2, v10, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 532
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 533
    :cond_19
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 534
    new-instance v21, Lqa/h;

    const/16 v26, 0x0

    const/16 v23, 0x1

    const/16 v22, 0x1

    const-string v24, "id"

    const-string v25, "TEXT"

    const/16 v27, 0x1

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v21

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 535
    new-instance v21, Lqa/h;

    const/16 v22, 0x0

    const-string v24, "description"

    const-string v25, "TEXT"

    invoke-direct/range {v21 .. v27}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v6, v20

    move-object/from16 v2, v21

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 536
    new-instance v18, Lqa/h;

    const/16 v23, 0x0

    const/16 v20, 0x1

    const/16 v19, 0x0

    const-string v21, "is_laura_search"

    const-string v22, "INTEGER"

    const/16 v24, 0x0

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v6, "is_laura_search"

    invoke-interface {v1, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 537
    new-instance v18, Lqa/h;

    const-string v21, "timestamp"

    const-string v22, "INTEGER"

    const/16 v24, 0x1

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    .line 538
    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 539
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 540
    new-instance v6, Lqa/k;

    const-string v10, "recent_places"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 541
    const-string v1, "recent_places"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 542
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1a

    .line 543
    new-instance v0, Lco/a;

    .line 544
    const-string v2, "recent_places(cz.skodaauto.myskoda.feature.mapsearch.data.RecentPlaceEntity).\n Expected:\n"

    .line 545
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 546
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 547
    :cond_1a
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 548
    new-instance v18, Lqa/h;

    const/16 v23, 0x0

    const/16 v20, 0x1

    const/16 v19, 0x1

    const-string v21, "id"

    const-string v22, "INTEGER"

    const/16 v24, 0x1

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    invoke-interface {v1, v7, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 549
    new-instance v18, Lqa/h;

    const/16 v19, 0x0

    const-string v21, "includeFerries"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "includeFerries"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 550
    new-instance v18, Lqa/h;

    const-string v21, "includeMotorways"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "includeMotorways"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 551
    new-instance v18, Lqa/h;

    const-string v21, "includeTollRoads"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "includeTollRoads"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 552
    new-instance v18, Lqa/h;

    const-string v21, "includeBorderCrossings"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "includeBorderCrossings"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 553
    new-instance v18, Lqa/h;

    const-string v21, "departureBatteryLevel"

    const-string v22, "INTEGER"

    const/16 v24, 0x0

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "departureBatteryLevel"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 554
    new-instance v18, Lqa/h;

    const-string v21, "arrivalBatteryLevel"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    const-string v5, "arrivalBatteryLevel"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 555
    new-instance v18, Lqa/h;

    const-string v21, "preferPowerpassChargingProviders"

    const-string v22, "INTEGER"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    .line 556
    const-string v5, "preferPowerpassChargingProviders"

    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 557
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 558
    new-instance v6, Lqa/k;

    const-string v10, "route_settings"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 559
    const-string v1, "route_settings"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 560
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1b

    .line 561
    new-instance v0, Lco/a;

    .line 562
    const-string v2, "route_settings(cz.skodaauto.myskoda.library.route.data.RouteSettingsEntity).\n Expected:\n"

    .line 563
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 564
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 565
    :cond_1b
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 566
    new-instance v18, Lqa/h;

    const/16 v23, 0x0

    const/16 v20, 0x1

    const/16 v19, 0x1

    const-string v21, "type"

    const-string v22, "TEXT"

    const/16 v24, 0x1

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    invoke-interface {v1, v13, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 567
    new-instance v18, Lqa/h;

    const/16 v19, 0x0

    const-string v21, "value"

    const-string v22, "TEXT"

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v18

    .line 568
    const-string v5, "value"

    invoke-static {v1, v5, v2}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 569
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 570
    new-instance v6, Lqa/k;

    const-string v10, "token"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 571
    const-string v1, "token"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 572
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1c

    .line 573
    new-instance v0, Lco/a;

    .line 574
    const-string v2, "token(cz.skodaauto.myskoda.library.authcomponent.data.TokenEntity).\n Expected:\n"

    .line 575
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 576
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 577
    :cond_1c
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 578
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x1

    const-string v13, "vin"

    const-string v14, "TEXT"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v3, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 579
    new-instance v18, Lqa/h;

    const/16 v23, 0x0

    const/16 v20, 0x1

    const/16 v19, 0x0

    const-string v21, "vehicle_type"

    const-string v22, "TEXT"

    const/16 v24, 0x1

    invoke-direct/range {v18 .. v24}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v5, v17

    move-object/from16 v2, v18

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 580
    new-instance v10, Lqa/h;

    const/4 v11, 0x0

    const-string v13, "end_mileage"

    const-string v14, "INTEGER"

    const/16 v16, 0x0

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "end_mileage"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 581
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "average_fuel_consumption"

    const-string v15, "REAL"

    const/16 v17, 0x0

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "average_fuel_consumption"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 582
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "average_electric_consumption"

    const-string v16, "REAL"

    const/16 v18, 0x0

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "average_electric_consumption"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 583
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/4 v14, 0x0

    const-string v16, "average_gas_consumption"

    const-string v17, "REAL"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 584
    const-string v2, "average_gas_consumption"

    invoke-static {v1, v2, v13}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 585
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 586
    new-instance v6, Lqa/k;

    const-string v10, "trips_overview"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 587
    const-string v1, "trips_overview"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 588
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1d

    .line 589
    new-instance v0, Lco/a;

    .line 590
    const-string v2, "trips_overview(cz.skodaauto.myskoda.feature.remotetripstatistics.data.TripsOverviewEntity).\n Expected:\n"

    .line 591
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 592
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 593
    :cond_1d
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 594
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x1

    const/4 v11, 0x1

    const-string v13, "id"

    const-string v14, "INTEGER"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 595
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/16 v17, 0x1

    const/4 v12, 0x0

    const-string v14, "userId"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "userId"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 596
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x1

    const/4 v13, 0x0

    const-string v15, "email"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "email"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 597
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x0

    const/4 v14, 0x0

    const-string v16, "firstName"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "firstName"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 598
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x0

    const/4 v15, 0x0

    const-string v17, "lastName"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "lastName"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 599
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x0

    const/16 v16, 0x0

    const-string v18, "nickname"

    const-string v19, "TEXT"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "nickname"

    invoke-interface {v1, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 600
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v22, 0x0

    const/16 v17, 0x0

    const-string v19, "countryCode"

    const-string v20, "TEXT"

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v16

    const-string v5, "countryCode"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 601
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x0

    const/4 v11, 0x0

    const-string v13, "countryOfResidenceCode"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "countryOfResidenceCode"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 602
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "preferredLanguageCode"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "preferredLanguageCode"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 603
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x0

    const/4 v13, 0x0

    const-string v15, "dateOfBirth"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "dateOfBirth"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 604
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x0

    const/4 v14, 0x0

    const-string v16, "phone"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "phone"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 605
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x0

    const/4 v15, 0x0

    const-string v17, "preferredContactChannel"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "preferredContactChannel"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 606
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x0

    const/16 v16, 0x0

    const-string v18, "profilePictureUrl"

    const-string v19, "TEXT"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "profilePictureUrl"

    invoke-interface {v1, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 607
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v17, 0x0

    const-string v19, "billingAddressCountry"

    const-string v20, "TEXT"

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v16

    const-string v5, "billingAddressCountry"

    invoke-interface {v1, v5, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 608
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x0

    const/4 v11, 0x0

    const-string v13, "billingAddressCity"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "billingAddressCity"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 609
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "billingAddressStreet"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "billingAddressStreet"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 610
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x0

    const/4 v13, 0x0

    const-string v15, "billingAddressHouseNumber"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "billingAddressHouseNumber"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 611
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x0

    const/4 v14, 0x0

    const-string v16, "billingAddressZipCode"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "billingAddressZipCode"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 612
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x0

    const/4 v15, 0x0

    const-string v17, "capabilityIds"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 613
    const-string v2, "capabilityIds"

    invoke-static {v1, v2, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 614
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 615
    new-instance v6, Lqa/k;

    const-string v10, "user"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 616
    const-string v1, "user"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 617
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1e

    .line 618
    new-instance v0, Lco/a;

    .line 619
    const-string v2, "user(cz.skodaauto.myskoda.library.user.data.UserEntity).\n Expected:\n"

    .line 620
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 621
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 622
    :cond_1e
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 623
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x1

    const-string v13, "id"

    const-string v14, "INTEGER"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 624
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "themeType"

    const-string v15, "TEXT"

    const/16 v17, 0x1

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "themeType"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 625
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "unitsType"

    const-string v16, "TEXT"

    const/16 v18, 0x1

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "unitsType"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 626
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/4 v14, 0x0

    const-string v16, "automaticWakeUp"

    const-string v17, "INTEGER"

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 627
    const-string v2, "automaticWakeUp"

    invoke-static {v1, v2, v13}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 628
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 629
    new-instance v6, Lqa/k;

    const-string v10, "user_preferences"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 630
    const-string v1, "user_preferences"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 631
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1f

    .line 632
    new-instance v0, Lco/a;

    .line 633
    const-string v2, "user_preferences(cz.skodaauto.myskoda.library.userpreferences.data.UserPreferencesEntity).\n Expected:\n"

    .line 634
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 635
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 636
    :cond_1f
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 637
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x1

    const-string v13, "vin"

    const-string v14, "TEXT"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 638
    invoke-static {v1, v3, v10}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 639
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 640
    new-instance v6, Lqa/k;

    const-string v10, "vehicle_backups_notice"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 641
    const-string v1, "vehicle_backups_notice"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 642
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_20

    .line 643
    new-instance v0, Lco/a;

    .line 644
    const-string v2, "vehicle_backups_notice(cz.skodaauto.myskoda.library.vehiclebackups.data.VehicleBackupsNoticeEntity).\n Expected:\n"

    .line 645
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 646
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 647
    :cond_20
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 648
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/4 v11, 0x1

    const-string v13, "vin"

    const-string v14, "TEXT"

    const/16 v16, 0x1

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v3, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 649
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x2

    const-string v14, "fuel_type"

    const-string v15, "TEXT"

    const/16 v17, 0x1

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "fuel_type"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 650
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "fuel_level_pct"

    const-string v16, "INTEGER"

    const/16 v18, 0x1

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "fuel_level_pct"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 651
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/4 v14, 0x0

    const-string v16, "last_notification_date"

    const-string v17, "TEXT"

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 652
    const-string v2, "last_notification_date"

    invoke-static {v1, v2, v13}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 653
    new-instance v5, Ljava/util/LinkedHashSet;

    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 654
    new-instance v6, Lqa/k;

    const-string v10, "vehicle_fuel_level"

    invoke-direct {v6, v10, v1, v2, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 655
    const-string v1, "vehicle_fuel_level"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 656
    invoke-virtual {v6, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_21

    .line 657
    new-instance v0, Lco/a;

    .line 658
    const-string v2, "vehicle_fuel_level(cz.skodaauto.myskoda.library.rangeice.data.VehicleFuelLevelEntity).\n Expected:\n"

    .line 659
    invoke-static {v2, v6, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 660
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 661
    :cond_21
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 662
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x1

    const/4 v11, 0x1

    const-string v13, "vin"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v3, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 663
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/16 v17, 0x0

    const/4 v12, 0x0

    const-string v14, "car_captured_timestamp"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v4, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 664
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x1

    const/4 v13, 0x0

    const-string v15, "overall_status_doors"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_doors"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 665
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x1

    const/4 v14, 0x0

    const-string v16, "overall_status_windows"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_windows"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 666
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x1

    const/4 v15, 0x0

    const-string v17, "overall_status_locked"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_locked"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 667
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x1

    const/16 v16, 0x0

    const-string v18, "overall_status_lights"

    const-string v19, "TEXT"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_lights"

    invoke-interface {v1, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 668
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v22, 0x1

    const/16 v17, 0x0

    const-string v19, "overall_status_doors_locked"

    const-string v20, "TEXT"

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v16

    const-string v3, "overall_status_doors_locked"

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 669
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x1

    const/4 v11, 0x0

    const-string v13, "overall_status_doors_open"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_doors_open"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 670
    new-instance v11, Lqa/h;

    const-string v16, "\'unknown\'"

    const/4 v13, 0x1

    const/16 v17, 0x1

    const/4 v12, 0x0

    const-string v14, "overall_status_lock_status"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "overall_status_lock_status"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 671
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/4 v13, 0x0

    const-string v15, "detail_status_sun_roof_status"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "detail_status_sun_roof_status"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 672
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x1

    const/4 v14, 0x0

    const-string v16, "detail_status_trunk_status"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "detail_status_trunk_status"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 673
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x1

    const/4 v15, 0x0

    const-string v17, "detail_status_bonnet_status"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "detail_status_bonnet_status"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 674
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x0

    const/16 v16, 0x0

    const-string v18, "render_light_mode_one_x"

    const-string v19, "TEXT"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_light_mode_one_x"

    invoke-interface {v1, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 675
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v22, 0x0

    const/16 v17, 0x0

    const-string v19, "render_light_mode_one_and_half_x"

    const-string v20, "TEXT"

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v16

    const-string v3, "render_light_mode_one_and_half_x"

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 676
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x0

    const/4 v11, 0x0

    const-string v13, "render_light_mode_two_x"

    const-string v14, "TEXT"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_light_mode_two_x"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 677
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "render_light_mode_three_x"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_light_mode_three_x"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 678
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x0

    const/4 v13, 0x0

    const-string v15, "render_dark_mode_one_x"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_dark_mode_one_x"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 679
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x0

    const/4 v14, 0x0

    const-string v16, "render_dark_mode_one_and_half_x"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_dark_mode_one_and_half_x"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 680
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x0

    const/4 v15, 0x0

    const-string v17, "render_dark_mode_two_x"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render_dark_mode_two_x"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 681
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x0

    const/16 v16, 0x0

    const-string v18, "render_dark_mode_three_x"

    const-string v19, "TEXT"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 682
    const-string v2, "render_dark_mode_three_x"

    invoke-static {v1, v2, v15}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 683
    new-instance v3, Ljava/util/LinkedHashSet;

    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 684
    new-instance v4, Lqa/k;

    const-string v5, "vehicle_status"

    invoke-direct {v4, v5, v1, v2, v3}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 685
    const-string v1, "vehicle_status"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v1

    .line 686
    invoke-virtual {v4, v1}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_22

    .line 687
    new-instance v0, Lco/a;

    .line 688
    const-string v2, "vehicle_status(cz.skodaauto.myskoda.library.vehiclestatus.data.VehicleStatusEntity).\n Expected:\n"

    .line 689
    invoke-static {v2, v4, v8, v1}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v1

    const/4 v12, 0x0

    .line 690
    invoke-direct {v0, v12, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0

    .line 691
    :cond_22
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 692
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x1

    const/4 v11, 0x1

    const-string v13, "id"

    const-string v14, "INTEGER"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v7, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 693
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/16 v17, 0x1

    const/4 v12, 0x0

    const-string v14, "name"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-interface {v1, v9, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 694
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x0

    const/4 v13, 0x0

    const-string v15, "render"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "render"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 695
    new-instance v13, Lqa/h;

    const/16 v18, 0x0

    const/4 v15, 0x1

    const/16 v19, 0x0

    const/4 v14, 0x0

    const-string v16, "licencePlate"

    const-string v17, "TEXT"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "licencePlate"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 696
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x0

    const/4 v15, 0x0

    const-string v17, "isDoorLocked"

    const-string v18, "INTEGER"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "isDoorLocked"

    invoke-interface {v1, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 697
    new-instance v15, Lqa/h;

    const/16 v20, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x1

    const/16 v16, 0x0

    const-string v18, "isCharging"

    const-string v19, "INTEGER"

    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "isCharging"

    invoke-interface {v1, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 698
    new-instance v16, Lqa/h;

    const/16 v21, 0x0

    const/16 v18, 0x1

    const/16 v22, 0x0

    const/16 v17, 0x0

    const-string v19, "drivingRange"

    const-string v20, "INTEGER"

    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    move-object/from16 v2, v16

    const-string v3, "drivingRange"

    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 699
    new-instance v9, Lqa/h;

    const/4 v14, 0x0

    const/4 v11, 0x1

    const/4 v15, 0x0

    const/4 v10, 0x0

    const-string v12, "remainingCharging"

    const-string v13, "INTEGER"

    invoke-direct/range {v9 .. v15}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "remainingCharging"

    invoke-interface {v1, v2, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 700
    new-instance v10, Lqa/h;

    const/4 v15, 0x0

    const/4 v12, 0x1

    const/16 v16, 0x0

    const/4 v11, 0x0

    const-string v13, "battery"

    const-string v14, "INTEGER"

    invoke-direct/range {v10 .. v16}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "battery"

    invoke-interface {v1, v2, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 701
    new-instance v11, Lqa/h;

    const/16 v16, 0x0

    const/4 v13, 0x1

    const/4 v12, 0x0

    const-string v14, "parkingAddress"

    const-string v15, "TEXT"

    invoke-direct/range {v11 .. v17}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "parkingAddress"

    invoke-interface {v1, v2, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 702
    new-instance v12, Lqa/h;

    const/16 v17, 0x0

    const/4 v14, 0x1

    const/16 v18, 0x0

    const/4 v13, 0x0

    const-string v15, "parkingMapUrl"

    const-string v16, "TEXT"

    invoke-direct/range {v12 .. v18}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "parkingMapUrl"

    invoke-interface {v1, v2, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 703
    new-instance v13, Lqa/h;

    const-string v18, "false"

    const/4 v15, 0x1

    const/16 v19, 0x1

    const/4 v14, 0x0

    const-string v16, "isInMotion"

    const-string v17, "INTEGER"

    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    const-string v2, "isInMotion"

    invoke-interface {v1, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 704
    new-instance v14, Lqa/h;

    const/16 v19, 0x0

    const/16 v16, 0x1

    const/16 v20, 0x1

    const/4 v15, 0x0

    const-string v17, "updated"

    const-string v18, "TEXT"

    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 705
    const-string v2, "updated"

    invoke-static {v1, v2, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    move-result-object v2

    .line 706
    new-instance v3, Ljava/util/LinkedHashSet;

    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 707
    new-instance v4, Lqa/k;

    const-string v5, "widget"

    invoke-direct {v4, v5, v1, v2, v3}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 708
    const-string v1, "widget"

    invoke-static {v0, v1}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    move-result-object v0

    .line 709
    invoke-virtual {v4, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_23

    .line 710
    new-instance v1, Lco/a;

    .line 711
    const-string v2, "widget(cz.skodaauto.myskoda.feature.widget.data.WidgetEntity).\n Expected:\n"

    .line 712
    invoke-static {v2, v4, v8, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    move-result-object v0

    const/4 v12, 0x0

    .line 713
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v1

    .line 714
    :cond_23
    new-instance v0, Lco/a;

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lco/a;-><init>(ZLjava/lang/String;)V

    return-object v0
.end method


# virtual methods
.method public final a(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lb61/a;->d:I

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
    const-string p0, "CREATE TABLE IF NOT EXISTS `air_conditioning_status` (`vin` TEXT NOT NULL, `state` TEXT NOT NULL, `window_heating_enabled` INTEGER, `target_temperature_at` TEXT, `air_conditioning_without_external_power` INTEGER, `air_conditioning_at_unlock` INTEGER, `steering_wheel_position` TEXT NOT NULL, `heater_source` TEXT NOT NULL, `charger_connection_state` TEXT, `air_conditioning_errors` TEXT NOT NULL, `car_captured_timestamp` TEXT, `target_temperature_value` REAL, `target_temperature_unit` TEXT, `window_heating_front` TEXT NOT NULL, `window_heating_rear` TEXT NOT NULL, `seat_heating_front_left` INTEGER, `seat_heating_front_right` INTEGER, `seat_heating_rear_left` INTEGER, `seat_heating_rear_right` INTEGER, `air_conditioning_running_request_value` TEXT, `air_conditioning_running_request_target_temperature_value` REAL, `air_conditioning_running_request_target_temperature_unit` TEXT, `air_conditioning_outside_temperaturetimestamp` TEXT, `air_conditioning_outside_temperatureoutside_temperaturevalue` REAL, `air_conditioning_outside_temperatureoutside_temperatureunit` TEXT, PRIMARY KEY(`vin`))"

    .line 12
    .line 13
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "CREATE TABLE IF NOT EXISTS `air_conditioning_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `air_conditioning_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 17
    .line 18
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_air_conditioning_timers_vin` ON `air_conditioning_timers` (`vin`)"

    .line 22
    .line 23
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p0, "CREATE TABLE IF NOT EXISTS `active_ventilation_status` (`vin` TEXT NOT NULL, `estimated_to_reach_target` TEXT, `state` TEXT NOT NULL, `duration` INTEGER NOT NULL, `car_captured_timestamp` TEXT, `outside_temperature_timestamp` TEXT, `outside_temperature_outside_temperaturevalue` REAL, `outside_temperature_outside_temperatureunit` TEXT, PRIMARY KEY(`vin`))"

    .line 27
    .line 28
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string p0, "CREATE TABLE IF NOT EXISTS `active_ventilation_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `active_ventilation_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 32
    .line 33
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_active_ventilation_timers_vin` ON `active_ventilation_timers` (`vin`)"

    .line 37
    .line 38
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string p0, "CREATE TABLE IF NOT EXISTS `app_log` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `timestamp` TEXT NOT NULL, `level` TEXT NOT NULL, `tag` TEXT NOT NULL, `message` TEXT NOT NULL)"

    .line 42
    .line 43
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string p0, "CREATE TABLE IF NOT EXISTS `auxiliary_heating_status` (`vin` TEXT NOT NULL, `estimated_date_time_to_reach_target_temperature` TEXT, `state` TEXT NOT NULL, `duration` INTEGER NOT NULL, `start_mode` TEXT NOT NULL, `heating_errors` TEXT, `car_captured_timestamp` TEXT, `target_temperature_value` REAL, `target_temperature_unit` TEXT, `outside_temperature_timestamp` TEXT, `outside_temperature_outside_temperaturevalue` REAL, `outside_temperature_outside_temperatureunit` TEXT, PRIMARY KEY(`vin`))"

    .line 47
    .line 48
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string p0, "CREATE TABLE IF NOT EXISTS `auxiliary_heating_timers` (`id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`vin`) REFERENCES `auxiliary_heating_status`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 52
    .line 53
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_auxiliary_heating_timers_vin` ON `auxiliary_heating_timers` (`vin`)"

    .line 57
    .line 58
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string p0, "CREATE TABLE IF NOT EXISTS `capability` (`id` TEXT NOT NULL, `serviceExpiration` TEXT, `statuses` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`id`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 62
    .line 63
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_capability_vin` ON `capability` (`vin`)"

    .line 67
    .line 68
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string p0, "CREATE TABLE IF NOT EXISTS `capability_error` (`type` TEXT NOT NULL, `description` TEXT, `vin` TEXT NOT NULL, PRIMARY KEY(`type`, `vin`), FOREIGN KEY(`vin`) REFERENCES `vehicle`(`vin`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 72
    .line 73
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_capability_error_vin` ON `capability_error` (`vin`)"

    .line 77
    .line 78
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `profile_id` INTEGER NOT NULL, `vin` TEXT NOT NULL, `name` TEXT NOT NULL, `location_lat` REAL, `location_lng` REAL, `settings_min_battery_charged_state` INTEGER, `settings_target_charged_state` INTEGER, `settings_reduced_current_active` INTEGER, `settings_cable_lock_active` INTEGER, FOREIGN KEY(`vin`) REFERENCES `charging_profiles`(`vin`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 82
    .line 83
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_vin` ON `charging_profile` (`vin`)"

    .line 87
    .line 88
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const-string p0, "CREATE UNIQUE INDEX IF NOT EXISTS `index_charging_profile_profile_id_vin` ON `charging_profile` (`profile_id`, `vin`)"

    .line 92
    .line 93
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile_charging_time` (`id` INTEGER NOT NULL, `profile_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `start_time` TEXT NOT NULL, `end_time` TEXT NOT NULL, PRIMARY KEY(`id`, `profile_id`), FOREIGN KEY(`profile_id`) REFERENCES `charging_profile`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 97
    .line 98
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_charging_time_profile_id` ON `charging_profile_charging_time` (`profile_id`)"

    .line 102
    .line 103
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profiles` (`vin` TEXT NOT NULL, `current_profile_id` INTEGER, `next_timer_time` TEXT, `car_captured_timestamp` TEXT, PRIMARY KEY(`vin`))"

    .line 107
    .line 108
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging_profile_timer` (`id` INTEGER NOT NULL, `profile_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `time` TEXT NOT NULL, `type` TEXT NOT NULL, `days` TEXT NOT NULL, `start_air_condition` INTEGER NOT NULL DEFAULT false, PRIMARY KEY(`id`, `profile_id`), FOREIGN KEY(`profile_id`) REFERENCES `charging_profile`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 112
    .line 113
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_charging_profile_timer_profile_id` ON `charging_profile_timer` (`profile_id`)"

    .line 117
    .line 118
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string p0, "CREATE TABLE IF NOT EXISTS `composite_render` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vehicle_id` TEXT NOT NULL, `vehicle_type` TEXT NOT NULL, `view_type` TEXT NOT NULL, `modifications_adjust_space_left` INTEGER, `modifications_adjust_space_right` INTEGER, `modifications_adjust_space_top` INTEGER, `modifications_adjust_space_bottom` INTEGER, `modifications_flip_horizontal` INTEGER, `modifications_anchor_to` TEXT)"

    .line 122
    .line 123
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string p0, "CREATE TABLE IF NOT EXISTS `composite_render_layer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `composite_render_id` INTEGER NOT NULL, `url` TEXT NOT NULL, `order` INTEGER NOT NULL, FOREIGN KEY(`composite_render_id`) REFERENCES `composite_render`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 127
    .line 128
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_composite_render_layer_composite_render_id` ON `composite_render_layer` (`composite_render_id`)"

    .line 132
    .line 133
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle` (`vin` TEXT NOT NULL, `systemModelId` TEXT NOT NULL, `name` TEXT, `title` TEXT NOT NULL, `licensePlate` TEXT, `state` TEXT NOT NULL, `devicePlatform` TEXT NOT NULL, `softwareVersion` TEXT, `connectivity_sunset_impact` TEXT, `isWorkshopMode` INTEGER NOT NULL DEFAULT false, `priority` INTEGER NOT NULL DEFAULT 0, `spec_title` TEXT, `spec_systemCode` TEXT, `spec_systemModelId` TEXT, `spec_model` TEXT, `spec_manufacturingDate` TEXT, `spec_gearboxType` TEXT, `spec_modelYear` TEXT, `spec_body` TEXT, `spec_batteryCapacity` INTEGER, `spec_trimLevel` TEXT, `spec_maxChargingPowerInKW` INTEGER, `spec_colour` TEXT, `spec_length` INTEGER, `spec_width` INTEGER, `spec_height` INTEGER, `spec_enginepowerInKW` INTEGER, `spec_enginetype` TEXT, `spec_enginecapacityInLiters` REAL, `servicePartner_id` TEXT, PRIMARY KEY(`vin`))"

    .line 137
    .line 138
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_plan` (`vin` TEXT NOT NULL, `target_temperature_celsius` REAL, `min_battery_charged_state_percent` INTEGER, `first_occurring_timer_id` INTEGER, `car_captured_timestamp` TEXT, PRIMARY KEY(`vin`))"

    .line 142
    .line 143
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_timer` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vin` TEXT NOT NULL, `index` INTEGER NOT NULL, `is_enabled` INTEGER NOT NULL, `is_charging_enabled` INTEGER NOT NULL, `is_air_conditioning_enabled` INTEGER NOT NULL, `target_charged_state` INTEGER, `timer_id` INTEGER NOT NULL, `timer_enabled` INTEGER NOT NULL, `timer_time` TEXT NOT NULL, `timer_type` TEXT NOT NULL, `timer_days` TEXT NOT NULL, FOREIGN KEY(`vin`) REFERENCES `departure_plan`(`vin`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 147
    .line 148
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_departure_timer_vin` ON `departure_timer` (`vin`)"

    .line 152
    .line 153
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    const-string p0, "CREATE TABLE IF NOT EXISTS `departure_charging_time` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timer_id` INTEGER NOT NULL, `charging_time_id` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, `start_time` TEXT NOT NULL, `end_time` TEXT NOT NULL, FOREIGN KEY(`timer_id`) REFERENCES `departure_timer`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 157
    .line 158
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_departure_charging_time_timer_id` ON `departure_charging_time` (`timer_id`)"

    .line 162
    .line 163
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string p0, "CREATE TABLE IF NOT EXISTS `fleet` (`vin` TEXT NOT NULL, `fleet` INTEGER NOT NULL, PRIMARY KEY(`vin`))"

    .line 167
    .line 168
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const-string p0, "CREATE TABLE IF NOT EXISTS `charging` (`vin` TEXT NOT NULL, `battery_care_mode` TEXT, `in_saved_location` INTEGER NOT NULL, `charging_errors` TEXT, `car_captured_timestamp` TEXT, `battery_statuscurrent_charged_state` INTEGER, `battery_statuscruising_range_electric` INTEGER, `charging_settings_charge_current` TEXT, `charging_settings_max_charge_current` INTEGER, `charging_settings_plug_unlock` TEXT, `charging_settings_target_charged_state` INTEGER, `charging_settings_battery_care_mode_target_value` INTEGER, `charging_status_charging_state` TEXT, `charging_status_charging_type` TEXT, `charging_status_charge_power` REAL, `charging_status_remaining_time_to_complete` INTEGER, `charging_status_charging_rate_in_kilometers_per_hour` REAL, `charge_mode_settings_available_charge_modes` TEXT, `charge_mode_settings_preferred_charge_mode` TEXT, PRIMARY KEY(`vin`))"

    .line 172
    .line 173
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    const-string p0, "CREATE TABLE IF NOT EXISTS `map_tile_type` (`id` INTEGER NOT NULL, `type` TEXT NOT NULL, PRIMARY KEY(`id`))"

    .line 177
    .line 178
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    const-string p0, "CREATE TABLE IF NOT EXISTS `network_log` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `service_label` TEXT NOT NULL DEFAULT \'\', `exception` TEXT NOT NULL DEFAULT \'\', `response_body` TEXT NOT NULL DEFAULT \'\', `response_code` INTEGER NOT NULL DEFAULT 0, `response_headers` TEXT NOT NULL DEFAULT \'\', `response_message` TEXT NOT NULL DEFAULT \'\', `response_time` INTEGER NOT NULL DEFAULT 0, `response_url` TEXT NOT NULL DEFAULT \'\', `request_body` TEXT NOT NULL DEFAULT \'\', `request_headers` TEXT NOT NULL DEFAULT \'\', `request_method` TEXT NOT NULL DEFAULT \'\', `request_protocol` TEXT NOT NULL DEFAULT \'\', `request_state` TEXT NOT NULL DEFAULT \'\', `request_url` TEXT NOT NULL DEFAULT \'\', `log_type` TEXT NOT NULL, `timestamp` INTEGER NOT NULL DEFAULT 0)"

    .line 182
    .line 183
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    const-string p0, "CREATE TABLE IF NOT EXISTS `ordered_vehicle` (`commissionId` TEXT NOT NULL, `name` TEXT NOT NULL, `vin` TEXT, `dealerId` TEXT, `priority` INTEGER NOT NULL DEFAULT 0, `activationStatus` TEXT NOT NULL, `orderStatus` TEXT NOT NULL, `startDeliveryDate` TEXT, `endDeliveryDate` TEXT, `spec_model` TEXT, `spec_trimLevel` TEXT, `spec_engine` TEXT, `spec_exteriorColor` TEXT, `spec_interiorColor` TEXT, `spec_batteryCapacity` INTEGER, `spec_maxPerformanceInKW` INTEGER, `spec_wltpRangeInM` INTEGER, `spec_consumptionInLitPer100km` REAL, `spec_consumptionInkWhPer100km` REAL, `spec_consumptionInKgPer100km` REAL, PRIMARY KEY(`commissionId`))"

    .line 187
    .line 188
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string p0, "CREATE TABLE IF NOT EXISTS `order_checkpoint` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `orderStatus` TEXT NOT NULL, `date` TEXT, `startEstimatedDate` TEXT, `endEstimatedDate` TEXT, `commissionId` TEXT NOT NULL, FOREIGN KEY(`commissionId`) REFERENCES `ordered_vehicle`(`commissionId`) ON UPDATE NO ACTION ON DELETE CASCADE )"

    .line 192
    .line 193
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_order_checkpoint_commissionId` ON `order_checkpoint` (`commissionId`)"

    .line 197
    .line 198
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    const-string p0, "CREATE TABLE IF NOT EXISTS `range_ice` (`vin` TEXT NOT NULL, `car_type` TEXT NOT NULL, `ad_blue_range` INTEGER, `total_range` INTEGER, `car_captured_timestamp` TEXT, `primary_engine_engine_type` TEXT NOT NULL, `primary_engine_current_soc_in_pct` INTEGER, `primary_engine_current_fuel_level_pct` INTEGER, `primary_engine_remaining_range` INTEGER, `secondary_engine_engine_type` TEXT, `secondary_engine_current_soc_in_pct` INTEGER, `secondary_engine_current_fuel_level_pct` INTEGER, `secondary_engine_remaining_range` INTEGER, PRIMARY KEY(`vin`))"

    .line 202
    .line 203
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    const-string p0, "CREATE TABLE IF NOT EXISTS `recent_places` (`id` TEXT NOT NULL, `description` TEXT NOT NULL, `is_laura_search` INTEGER, `timestamp` INTEGER NOT NULL, PRIMARY KEY(`id`))"

    .line 207
    .line 208
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    const-string p0, "CREATE TABLE IF NOT EXISTS `route_settings` (`id` INTEGER NOT NULL, `includeFerries` INTEGER NOT NULL, `includeMotorways` INTEGER NOT NULL, `includeTollRoads` INTEGER NOT NULL, `includeBorderCrossings` INTEGER NOT NULL, `departureBatteryLevel` INTEGER, `arrivalBatteryLevel` INTEGER, `preferPowerpassChargingProviders` INTEGER, PRIMARY KEY(`id`))"

    .line 212
    .line 213
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    const-string p0, "CREATE TABLE IF NOT EXISTS `token` (`type` TEXT NOT NULL, `value` TEXT NOT NULL, PRIMARY KEY(`type`))"

    .line 217
    .line 218
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const-string p0, "CREATE TABLE IF NOT EXISTS `trips_overview` (`vin` TEXT NOT NULL, `vehicle_type` TEXT NOT NULL, `end_mileage` INTEGER, `average_fuel_consumption` REAL, `average_electric_consumption` REAL, `average_gas_consumption` REAL, PRIMARY KEY(`vin`))"

    .line 222
    .line 223
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string p0, "CREATE TABLE IF NOT EXISTS `user` (`id` INTEGER NOT NULL, `userId` TEXT NOT NULL, `email` TEXT NOT NULL, `firstName` TEXT, `lastName` TEXT, `nickname` TEXT, `countryCode` TEXT, `countryOfResidenceCode` TEXT, `preferredLanguageCode` TEXT, `dateOfBirth` TEXT, `phone` TEXT, `preferredContactChannel` TEXT, `profilePictureUrl` TEXT, `billingAddressCountry` TEXT, `billingAddressCity` TEXT, `billingAddressStreet` TEXT, `billingAddressHouseNumber` TEXT, `billingAddressZipCode` TEXT, `capabilityIds` TEXT, PRIMARY KEY(`id`))"

    .line 227
    .line 228
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    const-string p0, "CREATE TABLE IF NOT EXISTS `user_preferences` (`id` INTEGER NOT NULL, `themeType` TEXT NOT NULL, `unitsType` TEXT NOT NULL, `automaticWakeUp` INTEGER, PRIMARY KEY(`id`))"

    .line 232
    .line 233
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_backups_notice` (`vin` TEXT NOT NULL, PRIMARY KEY(`vin`))"

    .line 237
    .line 238
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_fuel_level` (`vin` TEXT NOT NULL, `fuel_type` TEXT NOT NULL, `fuel_level_pct` INTEGER NOT NULL, `last_notification_date` TEXT, PRIMARY KEY(`vin`, `fuel_type`))"

    .line 242
    .line 243
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    const-string p0, "CREATE TABLE IF NOT EXISTS `vehicle_status` (`vin` TEXT NOT NULL, `car_captured_timestamp` TEXT, `overall_status_doors` TEXT NOT NULL, `overall_status_windows` TEXT NOT NULL, `overall_status_locked` TEXT NOT NULL, `overall_status_lights` TEXT NOT NULL, `overall_status_doors_locked` TEXT NOT NULL, `overall_status_doors_open` TEXT NOT NULL, `overall_status_lock_status` TEXT NOT NULL DEFAULT \'unknown\', `detail_status_sun_roof_status` TEXT NOT NULL, `detail_status_trunk_status` TEXT NOT NULL, `detail_status_bonnet_status` TEXT NOT NULL, `render_light_mode_one_x` TEXT, `render_light_mode_one_and_half_x` TEXT, `render_light_mode_two_x` TEXT, `render_light_mode_three_x` TEXT, `render_dark_mode_one_x` TEXT, `render_dark_mode_one_and_half_x` TEXT, `render_dark_mode_two_x` TEXT, `render_dark_mode_three_x` TEXT, PRIMARY KEY(`vin`))"

    .line 247
    .line 248
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    const-string p0, "CREATE TABLE IF NOT EXISTS `widget` (`id` INTEGER NOT NULL, `name` TEXT NOT NULL, `render` TEXT, `licencePlate` TEXT, `isDoorLocked` INTEGER, `isCharging` INTEGER NOT NULL, `drivingRange` INTEGER, `remainingCharging` INTEGER, `battery` INTEGER, `parkingAddress` TEXT, `parkingMapUrl` TEXT, `isInMotion` INTEGER NOT NULL DEFAULT false, `updated` TEXT NOT NULL, PRIMARY KEY(`id`))"

    .line 252
    .line 253
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    const-string p0, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    .line 257
    .line 258
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    const-string p0, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'a71c80c4b2bc821ea82200c2630dabf1\')"

    .line 262
    .line 263
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    return-void

    .line 267
    :pswitch_0
    const-string p0, "connection"

    .line 268
    .line 269
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    const-string p0, "CREATE TABLE IF NOT EXISTS `Dependency` (`work_spec_id` TEXT NOT NULL, `prerequisite_id` TEXT NOT NULL, PRIMARY KEY(`work_spec_id`, `prerequisite_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE , FOREIGN KEY(`prerequisite_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 273
    .line 274
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_Dependency_work_spec_id` ON `Dependency` (`work_spec_id`)"

    .line 278
    .line 279
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_Dependency_prerequisite_id` ON `Dependency` (`prerequisite_id`)"

    .line 283
    .line 284
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    const-string p0, "CREATE TABLE IF NOT EXISTS `WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `input_merger_class_name` TEXT NOT NULL, `input` BLOB NOT NULL, `output` BLOB NOT NULL, `initial_delay` INTEGER NOT NULL, `interval_duration` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NULL, `backoff_delay_duration` INTEGER NOT NULL, `last_enqueue_time` INTEGER NOT NULL DEFAULT -1, `minimum_retention_duration` INTEGER NOT NULL, `schedule_requested_at` INTEGER NOT NULL, `run_in_foreground` INTEGER NOT NULL, `out_of_quota_policy` INTEGER NOT NULL, `period_count` INTEGER NOT NULL DEFAULT 0, `generation` INTEGER NOT NULL DEFAULT 0, `next_schedule_time_override` INTEGER NOT NULL DEFAULT 9223372036854775807, `next_schedule_time_override_generation` INTEGER NOT NULL DEFAULT 0, `stop_reason` INTEGER NOT NULL DEFAULT -256, `trace_tag` TEXT, `backoff_on_system_interruptions` INTEGER, `required_network_type` INTEGER NOT NULL, `required_network_request` BLOB NOT NULL DEFAULT x\'\', `requires_charging` INTEGER NOT NULL, `requires_device_idle` INTEGER NOT NULL, `requires_battery_not_low` INTEGER NOT NULL, `requires_storage_not_low` INTEGER NOT NULL, `trigger_content_update_delay` INTEGER NOT NULL, `trigger_max_content_delay` INTEGER NOT NULL, `content_uri_triggers` BLOB NOT NULL, PRIMARY KEY(`id`))"

    .line 288
    .line 289
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_schedule_requested_at` ON `WorkSpec` (`schedule_requested_at`)"

    .line 293
    .line 294
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_WorkSpec_last_enqueue_time` ON `WorkSpec` (`last_enqueue_time`)"

    .line 298
    .line 299
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    const-string p0, "CREATE TABLE IF NOT EXISTS `WorkTag` (`tag` TEXT NOT NULL, `work_spec_id` TEXT NOT NULL, PRIMARY KEY(`tag`, `work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 303
    .line 304
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_WorkTag_work_spec_id` ON `WorkTag` (`work_spec_id`)"

    .line 308
    .line 309
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    const-string p0, "CREATE TABLE IF NOT EXISTS `SystemIdInfo` (`work_spec_id` TEXT NOT NULL, `generation` INTEGER NOT NULL DEFAULT 0, `system_id` INTEGER NOT NULL, PRIMARY KEY(`work_spec_id`, `generation`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 313
    .line 314
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    const-string p0, "CREATE TABLE IF NOT EXISTS `WorkName` (`name` TEXT NOT NULL, `work_spec_id` TEXT NOT NULL, PRIMARY KEY(`name`, `work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 318
    .line 319
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    const-string p0, "CREATE INDEX IF NOT EXISTS `index_WorkName_work_spec_id` ON `WorkName` (`work_spec_id`)"

    .line 323
    .line 324
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    const-string p0, "CREATE TABLE IF NOT EXISTS `WorkProgress` (`work_spec_id` TEXT NOT NULL, `progress` BLOB NOT NULL, PRIMARY KEY(`work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )"

    .line 328
    .line 329
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    const-string p0, "CREATE TABLE IF NOT EXISTS `Preference` (`key` TEXT NOT NULL, `long_value` INTEGER, PRIMARY KEY(`key`))"

    .line 333
    .line 334
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    const-string p0, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    .line 338
    .line 339
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    const-string p0, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'08b926448d86528e697981ddd30459f7\')"

    .line 343
    .line 344
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    return-void

    .line 348
    :pswitch_1
    const-string p0, "connection"

    .line 349
    .line 350
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 351
    .line 352
    .line 353
    const-string p0, "CREATE TABLE IF NOT EXISTS `event` (`id` TEXT NOT NULL, `eventType` TEXT NOT NULL, `payload` TEXT NOT NULL, `timestamp` INTEGER NOT NULL, `toadStamp` INTEGER NOT NULL, PRIMARY KEY(`id`))"

    .line 354
    .line 355
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    const-string p0, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    .line 359
    .line 360
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    const-string p0, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'d9dfb9c7242ddd2a6d926b92b4445acd\')"

    .line 364
    .line 365
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    return-void

    .line 369
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lb61/a;->d:I

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
    const-string p0, "DROP TABLE IF EXISTS `air_conditioning_status`"

    .line 12
    .line 13
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "DROP TABLE IF EXISTS `air_conditioning_timers`"

    .line 17
    .line 18
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p0, "DROP TABLE IF EXISTS `active_ventilation_status`"

    .line 22
    .line 23
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p0, "DROP TABLE IF EXISTS `active_ventilation_timers`"

    .line 27
    .line 28
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string p0, "DROP TABLE IF EXISTS `app_log`"

    .line 32
    .line 33
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string p0, "DROP TABLE IF EXISTS `auxiliary_heating_status`"

    .line 37
    .line 38
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string p0, "DROP TABLE IF EXISTS `auxiliary_heating_timers`"

    .line 42
    .line 43
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string p0, "DROP TABLE IF EXISTS `capability`"

    .line 47
    .line 48
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string p0, "DROP TABLE IF EXISTS `capability_error`"

    .line 52
    .line 53
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string p0, "DROP TABLE IF EXISTS `charging_profile`"

    .line 57
    .line 58
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string p0, "DROP TABLE IF EXISTS `charging_profile_charging_time`"

    .line 62
    .line 63
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string p0, "DROP TABLE IF EXISTS `charging_profiles`"

    .line 67
    .line 68
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string p0, "DROP TABLE IF EXISTS `charging_profile_timer`"

    .line 72
    .line 73
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const-string p0, "DROP TABLE IF EXISTS `composite_render`"

    .line 77
    .line 78
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string p0, "DROP TABLE IF EXISTS `composite_render_layer`"

    .line 82
    .line 83
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string p0, "DROP TABLE IF EXISTS `vehicle`"

    .line 87
    .line 88
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const-string p0, "DROP TABLE IF EXISTS `departure_plan`"

    .line 92
    .line 93
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const-string p0, "DROP TABLE IF EXISTS `departure_timer`"

    .line 97
    .line 98
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string p0, "DROP TABLE IF EXISTS `departure_charging_time`"

    .line 102
    .line 103
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const-string p0, "DROP TABLE IF EXISTS `fleet`"

    .line 107
    .line 108
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const-string p0, "DROP TABLE IF EXISTS `charging`"

    .line 112
    .line 113
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    const-string p0, "DROP TABLE IF EXISTS `map_tile_type`"

    .line 117
    .line 118
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string p0, "DROP TABLE IF EXISTS `network_log`"

    .line 122
    .line 123
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string p0, "DROP TABLE IF EXISTS `ordered_vehicle`"

    .line 127
    .line 128
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string p0, "DROP TABLE IF EXISTS `order_checkpoint`"

    .line 132
    .line 133
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string p0, "DROP TABLE IF EXISTS `range_ice`"

    .line 137
    .line 138
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string p0, "DROP TABLE IF EXISTS `recent_places`"

    .line 142
    .line 143
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    const-string p0, "DROP TABLE IF EXISTS `route_settings`"

    .line 147
    .line 148
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string p0, "DROP TABLE IF EXISTS `token`"

    .line 152
    .line 153
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    const-string p0, "DROP TABLE IF EXISTS `trips_overview`"

    .line 157
    .line 158
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    const-string p0, "DROP TABLE IF EXISTS `user`"

    .line 162
    .line 163
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string p0, "DROP TABLE IF EXISTS `user_preferences`"

    .line 167
    .line 168
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const-string p0, "DROP TABLE IF EXISTS `vehicle_backups_notice`"

    .line 172
    .line 173
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    const-string p0, "DROP TABLE IF EXISTS `vehicle_fuel_level`"

    .line 177
    .line 178
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    const-string p0, "DROP TABLE IF EXISTS `vehicle_status`"

    .line 182
    .line 183
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    const-string p0, "DROP TABLE IF EXISTS `widget`"

    .line 187
    .line 188
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :pswitch_0
    const-string p0, "connection"

    .line 193
    .line 194
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    const-string p0, "DROP TABLE IF EXISTS `Dependency`"

    .line 198
    .line 199
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    const-string p0, "DROP TABLE IF EXISTS `WorkSpec`"

    .line 203
    .line 204
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    const-string p0, "DROP TABLE IF EXISTS `WorkTag`"

    .line 208
    .line 209
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    const-string p0, "DROP TABLE IF EXISTS `SystemIdInfo`"

    .line 213
    .line 214
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    const-string p0, "DROP TABLE IF EXISTS `WorkName`"

    .line 218
    .line 219
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    const-string p0, "DROP TABLE IF EXISTS `WorkProgress`"

    .line 223
    .line 224
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    const-string p0, "DROP TABLE IF EXISTS `Preference`"

    .line 228
    .line 229
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    return-void

    .line 233
    :pswitch_1
    const-string p0, "connection"

    .line 234
    .line 235
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    const-string p0, "DROP TABLE IF EXISTS `event`"

    .line 239
    .line 240
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    return-void

    .line 244
    nop

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final r(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lb61/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    const-string p0, "connection"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final s(Lua/a;)V
    .locals 1

    .line 1
    iget v0, p0, Lb61/a;->d:I

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
    const-string v0, "PRAGMA foreign_keys = ON"

    .line 12
    .line 13
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lb61/a;->e:Lla/u;

    .line 17
    .line 18
    check-cast p0, Lcz/skodaauto/myskoda/app/main/system/ApplicationDatabase_Impl;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lla/u;->n(Lua/a;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_0
    const-string v0, "connection"

    .line 25
    .line 26
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "PRAGMA foreign_keys = ON"

    .line 30
    .line 31
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lb61/a;->e:Lla/u;

    .line 35
    .line 36
    check-cast p0, Landroidx/work/impl/WorkDatabase_Impl;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lla/u;->n(Lua/a;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_1
    const-string v0, "connection"

    .line 43
    .line 44
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lb61/a;->e:Lla/u;

    .line 48
    .line 49
    check-cast p0, Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lla/u;->n(Lua/a;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final t(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lb61/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    const-string p0, "connection"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final u(Lua/a;)V
    .locals 0

    .line 1
    iget p0, p0, Lb61/a;->d:I

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
    invoke-static {p1}, Ljp/ue;->a(Lua/a;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    const-string p0, "connection"

    .line 16
    .line 17
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1}, Ljp/ue;->a(Lua/a;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_1
    const-string p0, "connection"

    .line 25
    .line 26
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {p1}, Ljp/ue;->a(Lua/a;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final v(Lua/a;)Lco/a;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lb61/a;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-direct/range {p0 .. p1}, Lb61/a;->w(Lua/a;)Lco/a;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    return-object v0

    .line 15
    :pswitch_0
    const-string v0, "connection"

    .line 16
    .line 17
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 23
    .line 24
    .line 25
    new-instance v2, Lqa/h;

    .line 26
    .line 27
    const/4 v7, 0x0

    .line 28
    const/4 v4, 0x1

    .line 29
    const/4 v3, 0x1

    .line 30
    const-string v5, "work_spec_id"

    .line 31
    .line 32
    const-string v6, "TEXT"

    .line 33
    .line 34
    const/4 v8, 0x1

    .line 35
    invoke-direct/range {v2 .. v8}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v3, "work_spec_id"

    .line 39
    .line 40
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    new-instance v4, Lqa/h;

    .line 44
    .line 45
    const/4 v9, 0x0

    .line 46
    const/4 v6, 0x1

    .line 47
    const/4 v5, 0x2

    .line 48
    const-string v7, "prerequisite_id"

    .line 49
    .line 50
    const-string v8, "TEXT"

    .line 51
    .line 52
    const/4 v10, 0x1

    .line 53
    invoke-direct/range {v4 .. v10}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 54
    .line 55
    .line 56
    const-string v2, "prerequisite_id"

    .line 57
    .line 58
    invoke-static {v0, v2, v4}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    new-instance v5, Lqa/i;

    .line 63
    .line 64
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    const-string v11, "id"

    .line 69
    .line 70
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v10

    .line 74
    const-string v6, "WorkSpec"

    .line 75
    .line 76
    const-string v7, "CASCADE"

    .line 77
    .line 78
    const-string v8, "CASCADE"

    .line 79
    .line 80
    invoke-direct/range {v5 .. v10}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v4, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    new-instance v12, Lqa/i;

    .line 87
    .line 88
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object v16

    .line 92
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v17

    .line 96
    const-string v13, "WorkSpec"

    .line 97
    .line 98
    const-string v14, "CASCADE"

    .line 99
    .line 100
    const-string v15, "CASCADE"

    .line 101
    .line 102
    invoke-direct/range {v12 .. v17}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 103
    .line 104
    .line 105
    invoke-interface {v4, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    new-instance v5, Ljava/util/LinkedHashSet;

    .line 109
    .line 110
    invoke-direct {v5}, Ljava/util/LinkedHashSet;-><init>()V

    .line 111
    .line 112
    .line 113
    new-instance v6, Lqa/j;

    .line 114
    .line 115
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    const-string v8, "ASC"

    .line 120
    .line 121
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object v9

    .line 125
    const-string v10, "index_Dependency_work_spec_id"

    .line 126
    .line 127
    const/4 v12, 0x0

    .line 128
    invoke-direct {v6, v10, v7, v9, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 129
    .line 130
    .line 131
    invoke-interface {v5, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    new-instance v6, Lqa/j;

    .line 135
    .line 136
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 141
    .line 142
    .line 143
    move-result-object v7

    .line 144
    const-string v9, "index_Dependency_prerequisite_id"

    .line 145
    .line 146
    invoke-direct {v6, v9, v2, v7, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v5, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    new-instance v2, Lqa/k;

    .line 153
    .line 154
    const-string v6, "Dependency"

    .line 155
    .line 156
    invoke-direct {v2, v6, v0, v4, v5}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 157
    .line 158
    .line 159
    invoke-static {v1, v6}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    invoke-virtual {v2, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    const-string v5, "\n Found:\n"

    .line 168
    .line 169
    if-nez v4, :cond_0

    .line 170
    .line 171
    new-instance v1, Lco/a;

    .line 172
    .line 173
    const-string v3, "Dependency(androidx.work.impl.model.Dependency).\n Expected:\n"

    .line 174
    .line 175
    invoke-static {v3, v2, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :cond_0
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 185
    .line 186
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 187
    .line 188
    .line 189
    new-instance v13, Lqa/h;

    .line 190
    .line 191
    const/16 v18, 0x0

    .line 192
    .line 193
    const/4 v15, 0x1

    .line 194
    const/16 v19, 0x1

    .line 195
    .line 196
    const/4 v14, 0x1

    .line 197
    const-string v16, "id"

    .line 198
    .line 199
    const-string v17, "TEXT"

    .line 200
    .line 201
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 202
    .line 203
    .line 204
    invoke-interface {v0, v11, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    new-instance v14, Lqa/h;

    .line 208
    .line 209
    const/16 v19, 0x0

    .line 210
    .line 211
    const/16 v16, 0x1

    .line 212
    .line 213
    const/16 v20, 0x1

    .line 214
    .line 215
    const/4 v15, 0x0

    .line 216
    const-string v17, "state"

    .line 217
    .line 218
    const-string v18, "INTEGER"

    .line 219
    .line 220
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 221
    .line 222
    .line 223
    const-string v2, "state"

    .line 224
    .line 225
    invoke-interface {v0, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    new-instance v15, Lqa/h;

    .line 229
    .line 230
    const/16 v20, 0x0

    .line 231
    .line 232
    const/16 v17, 0x1

    .line 233
    .line 234
    const/16 v21, 0x1

    .line 235
    .line 236
    const/16 v16, 0x0

    .line 237
    .line 238
    const-string v18, "worker_class_name"

    .line 239
    .line 240
    const-string v19, "TEXT"

    .line 241
    .line 242
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 243
    .line 244
    .line 245
    const-string v2, "worker_class_name"

    .line 246
    .line 247
    invoke-interface {v0, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    new-instance v16, Lqa/h;

    .line 251
    .line 252
    const/16 v21, 0x0

    .line 253
    .line 254
    const/16 v18, 0x1

    .line 255
    .line 256
    const/16 v22, 0x1

    .line 257
    .line 258
    const/16 v17, 0x0

    .line 259
    .line 260
    const-string v19, "input_merger_class_name"

    .line 261
    .line 262
    const-string v20, "TEXT"

    .line 263
    .line 264
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 265
    .line 266
    .line 267
    move-object/from16 v2, v16

    .line 268
    .line 269
    const-string v4, "input_merger_class_name"

    .line 270
    .line 271
    invoke-interface {v0, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    new-instance v13, Lqa/h;

    .line 275
    .line 276
    const/16 v18, 0x0

    .line 277
    .line 278
    const/4 v15, 0x1

    .line 279
    const/16 v19, 0x1

    .line 280
    .line 281
    const/4 v14, 0x0

    .line 282
    const-string v16, "input"

    .line 283
    .line 284
    const-string v17, "BLOB"

    .line 285
    .line 286
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 287
    .line 288
    .line 289
    const-string v2, "input"

    .line 290
    .line 291
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    new-instance v14, Lqa/h;

    .line 295
    .line 296
    const/16 v19, 0x0

    .line 297
    .line 298
    const/16 v16, 0x1

    .line 299
    .line 300
    const/16 v20, 0x1

    .line 301
    .line 302
    const/4 v15, 0x0

    .line 303
    const-string v17, "output"

    .line 304
    .line 305
    const-string v18, "BLOB"

    .line 306
    .line 307
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 308
    .line 309
    .line 310
    const-string v2, "output"

    .line 311
    .line 312
    invoke-interface {v0, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    new-instance v15, Lqa/h;

    .line 316
    .line 317
    const/16 v20, 0x0

    .line 318
    .line 319
    const/16 v17, 0x1

    .line 320
    .line 321
    const/16 v21, 0x1

    .line 322
    .line 323
    const/16 v16, 0x0

    .line 324
    .line 325
    const-string v18, "initial_delay"

    .line 326
    .line 327
    const-string v19, "INTEGER"

    .line 328
    .line 329
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 330
    .line 331
    .line 332
    const-string v2, "initial_delay"

    .line 333
    .line 334
    invoke-interface {v0, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    new-instance v16, Lqa/h;

    .line 338
    .line 339
    const/16 v21, 0x0

    .line 340
    .line 341
    const/16 v18, 0x1

    .line 342
    .line 343
    const/16 v17, 0x0

    .line 344
    .line 345
    const-string v19, "interval_duration"

    .line 346
    .line 347
    const-string v20, "INTEGER"

    .line 348
    .line 349
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 350
    .line 351
    .line 352
    move-object/from16 v2, v16

    .line 353
    .line 354
    const-string v4, "interval_duration"

    .line 355
    .line 356
    invoke-interface {v0, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    new-instance v13, Lqa/h;

    .line 360
    .line 361
    const/16 v18, 0x0

    .line 362
    .line 363
    const/4 v15, 0x1

    .line 364
    const/16 v19, 0x1

    .line 365
    .line 366
    const/4 v14, 0x0

    .line 367
    const-string v16, "flex_duration"

    .line 368
    .line 369
    const-string v17, "INTEGER"

    .line 370
    .line 371
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 372
    .line 373
    .line 374
    const-string v2, "flex_duration"

    .line 375
    .line 376
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    new-instance v14, Lqa/h;

    .line 380
    .line 381
    const/16 v19, 0x0

    .line 382
    .line 383
    const/16 v16, 0x1

    .line 384
    .line 385
    const/16 v20, 0x1

    .line 386
    .line 387
    const/4 v15, 0x0

    .line 388
    const-string v17, "run_attempt_count"

    .line 389
    .line 390
    const-string v18, "INTEGER"

    .line 391
    .line 392
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 393
    .line 394
    .line 395
    const-string v2, "run_attempt_count"

    .line 396
    .line 397
    invoke-interface {v0, v2, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    new-instance v15, Lqa/h;

    .line 401
    .line 402
    const/16 v20, 0x0

    .line 403
    .line 404
    const/16 v17, 0x1

    .line 405
    .line 406
    const/16 v21, 0x1

    .line 407
    .line 408
    const/16 v16, 0x0

    .line 409
    .line 410
    const-string v18, "backoff_policy"

    .line 411
    .line 412
    const-string v19, "INTEGER"

    .line 413
    .line 414
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 415
    .line 416
    .line 417
    const-string v2, "backoff_policy"

    .line 418
    .line 419
    invoke-interface {v0, v2, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    new-instance v16, Lqa/h;

    .line 423
    .line 424
    const/16 v21, 0x0

    .line 425
    .line 426
    const/16 v18, 0x1

    .line 427
    .line 428
    const/16 v17, 0x0

    .line 429
    .line 430
    const-string v19, "backoff_delay_duration"

    .line 431
    .line 432
    const-string v20, "INTEGER"

    .line 433
    .line 434
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 435
    .line 436
    .line 437
    move-object/from16 v2, v16

    .line 438
    .line 439
    const-string v4, "backoff_delay_duration"

    .line 440
    .line 441
    invoke-interface {v0, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    new-instance v13, Lqa/h;

    .line 445
    .line 446
    const-string v18, "-1"

    .line 447
    .line 448
    const/4 v15, 0x1

    .line 449
    const/16 v19, 0x1

    .line 450
    .line 451
    const/4 v14, 0x0

    .line 452
    const-string v16, "last_enqueue_time"

    .line 453
    .line 454
    const-string v17, "INTEGER"

    .line 455
    .line 456
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 457
    .line 458
    .line 459
    const-string v2, "last_enqueue_time"

    .line 460
    .line 461
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    new-instance v14, Lqa/h;

    .line 465
    .line 466
    const/16 v19, 0x0

    .line 467
    .line 468
    const/16 v16, 0x1

    .line 469
    .line 470
    const/16 v20, 0x1

    .line 471
    .line 472
    const/4 v15, 0x0

    .line 473
    const-string v17, "minimum_retention_duration"

    .line 474
    .line 475
    const-string v18, "INTEGER"

    .line 476
    .line 477
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 478
    .line 479
    .line 480
    const-string v4, "minimum_retention_duration"

    .line 481
    .line 482
    invoke-interface {v0, v4, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    new-instance v15, Lqa/h;

    .line 486
    .line 487
    const/16 v20, 0x0

    .line 488
    .line 489
    const/16 v17, 0x1

    .line 490
    .line 491
    const/16 v21, 0x1

    .line 492
    .line 493
    const/16 v16, 0x0

    .line 494
    .line 495
    const-string v18, "schedule_requested_at"

    .line 496
    .line 497
    const-string v19, "INTEGER"

    .line 498
    .line 499
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 500
    .line 501
    .line 502
    const-string v4, "schedule_requested_at"

    .line 503
    .line 504
    invoke-interface {v0, v4, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    new-instance v16, Lqa/h;

    .line 508
    .line 509
    const/16 v21, 0x0

    .line 510
    .line 511
    const/16 v18, 0x1

    .line 512
    .line 513
    const/16 v17, 0x0

    .line 514
    .line 515
    const-string v19, "run_in_foreground"

    .line 516
    .line 517
    const-string v20, "INTEGER"

    .line 518
    .line 519
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 520
    .line 521
    .line 522
    move-object/from16 v6, v16

    .line 523
    .line 524
    const-string v7, "run_in_foreground"

    .line 525
    .line 526
    invoke-interface {v0, v7, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 527
    .line 528
    .line 529
    new-instance v13, Lqa/h;

    .line 530
    .line 531
    const/16 v18, 0x0

    .line 532
    .line 533
    const/4 v15, 0x1

    .line 534
    const/16 v19, 0x1

    .line 535
    .line 536
    const/4 v14, 0x0

    .line 537
    const-string v16, "out_of_quota_policy"

    .line 538
    .line 539
    const-string v17, "INTEGER"

    .line 540
    .line 541
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 542
    .line 543
    .line 544
    const-string v6, "out_of_quota_policy"

    .line 545
    .line 546
    invoke-interface {v0, v6, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    new-instance v14, Lqa/h;

    .line 550
    .line 551
    const-string v19, "0"

    .line 552
    .line 553
    const/16 v16, 0x1

    .line 554
    .line 555
    const/16 v20, 0x1

    .line 556
    .line 557
    const/4 v15, 0x0

    .line 558
    const-string v17, "period_count"

    .line 559
    .line 560
    const-string v18, "INTEGER"

    .line 561
    .line 562
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 563
    .line 564
    .line 565
    const-string v6, "period_count"

    .line 566
    .line 567
    invoke-interface {v0, v6, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 568
    .line 569
    .line 570
    new-instance v15, Lqa/h;

    .line 571
    .line 572
    const-string v20, "0"

    .line 573
    .line 574
    const/16 v17, 0x1

    .line 575
    .line 576
    const/16 v21, 0x1

    .line 577
    .line 578
    const/16 v16, 0x0

    .line 579
    .line 580
    const-string v18, "generation"

    .line 581
    .line 582
    const-string v19, "INTEGER"

    .line 583
    .line 584
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 585
    .line 586
    .line 587
    const-string v6, "generation"

    .line 588
    .line 589
    invoke-interface {v0, v6, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    new-instance v16, Lqa/h;

    .line 593
    .line 594
    const-string v21, "9223372036854775807"

    .line 595
    .line 596
    const/16 v18, 0x1

    .line 597
    .line 598
    const/16 v17, 0x0

    .line 599
    .line 600
    const-string v19, "next_schedule_time_override"

    .line 601
    .line 602
    const-string v20, "INTEGER"

    .line 603
    .line 604
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 605
    .line 606
    .line 607
    move-object/from16 v7, v16

    .line 608
    .line 609
    const-string v9, "next_schedule_time_override"

    .line 610
    .line 611
    invoke-interface {v0, v9, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    new-instance v13, Lqa/h;

    .line 615
    .line 616
    const-string v18, "0"

    .line 617
    .line 618
    const/4 v15, 0x1

    .line 619
    const/16 v19, 0x1

    .line 620
    .line 621
    const/4 v14, 0x0

    .line 622
    const-string v16, "next_schedule_time_override_generation"

    .line 623
    .line 624
    const-string v17, "INTEGER"

    .line 625
    .line 626
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 627
    .line 628
    .line 629
    const-string v7, "next_schedule_time_override_generation"

    .line 630
    .line 631
    invoke-interface {v0, v7, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 632
    .line 633
    .line 634
    new-instance v14, Lqa/h;

    .line 635
    .line 636
    const-string v19, "-256"

    .line 637
    .line 638
    const/16 v16, 0x1

    .line 639
    .line 640
    const/16 v20, 0x1

    .line 641
    .line 642
    const/4 v15, 0x0

    .line 643
    const-string v17, "stop_reason"

    .line 644
    .line 645
    const-string v18, "INTEGER"

    .line 646
    .line 647
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 648
    .line 649
    .line 650
    const-string v7, "stop_reason"

    .line 651
    .line 652
    invoke-interface {v0, v7, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    new-instance v15, Lqa/h;

    .line 656
    .line 657
    const/16 v20, 0x0

    .line 658
    .line 659
    const/16 v17, 0x1

    .line 660
    .line 661
    const/16 v21, 0x0

    .line 662
    .line 663
    const/16 v16, 0x0

    .line 664
    .line 665
    const-string v18, "trace_tag"

    .line 666
    .line 667
    const-string v19, "TEXT"

    .line 668
    .line 669
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 670
    .line 671
    .line 672
    const-string v7, "trace_tag"

    .line 673
    .line 674
    invoke-interface {v0, v7, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 675
    .line 676
    .line 677
    new-instance v16, Lqa/h;

    .line 678
    .line 679
    const/16 v21, 0x0

    .line 680
    .line 681
    const/16 v18, 0x1

    .line 682
    .line 683
    const/16 v22, 0x0

    .line 684
    .line 685
    const/16 v17, 0x0

    .line 686
    .line 687
    const-string v19, "backoff_on_system_interruptions"

    .line 688
    .line 689
    const-string v20, "INTEGER"

    .line 690
    .line 691
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 692
    .line 693
    .line 694
    move-object/from16 v7, v16

    .line 695
    .line 696
    const-string v9, "backoff_on_system_interruptions"

    .line 697
    .line 698
    invoke-interface {v0, v9, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 699
    .line 700
    .line 701
    new-instance v13, Lqa/h;

    .line 702
    .line 703
    const/16 v18, 0x0

    .line 704
    .line 705
    const/4 v15, 0x1

    .line 706
    const/16 v19, 0x1

    .line 707
    .line 708
    const/4 v14, 0x0

    .line 709
    const-string v16, "required_network_type"

    .line 710
    .line 711
    const-string v17, "INTEGER"

    .line 712
    .line 713
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 714
    .line 715
    .line 716
    const-string v7, "required_network_type"

    .line 717
    .line 718
    invoke-interface {v0, v7, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 719
    .line 720
    .line 721
    new-instance v14, Lqa/h;

    .line 722
    .line 723
    const-string v19, "x\'\'"

    .line 724
    .line 725
    const/16 v16, 0x1

    .line 726
    .line 727
    const/16 v20, 0x1

    .line 728
    .line 729
    const/4 v15, 0x0

    .line 730
    const-string v17, "required_network_request"

    .line 731
    .line 732
    const-string v18, "BLOB"

    .line 733
    .line 734
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 735
    .line 736
    .line 737
    const-string v7, "required_network_request"

    .line 738
    .line 739
    invoke-interface {v0, v7, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 740
    .line 741
    .line 742
    new-instance v15, Lqa/h;

    .line 743
    .line 744
    const/16 v20, 0x0

    .line 745
    .line 746
    const/16 v17, 0x1

    .line 747
    .line 748
    const/16 v21, 0x1

    .line 749
    .line 750
    const/16 v16, 0x0

    .line 751
    .line 752
    const-string v18, "requires_charging"

    .line 753
    .line 754
    const-string v19, "INTEGER"

    .line 755
    .line 756
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 757
    .line 758
    .line 759
    const-string v7, "requires_charging"

    .line 760
    .line 761
    invoke-interface {v0, v7, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 762
    .line 763
    .line 764
    new-instance v16, Lqa/h;

    .line 765
    .line 766
    const/16 v21, 0x0

    .line 767
    .line 768
    const/16 v18, 0x1

    .line 769
    .line 770
    const/16 v22, 0x1

    .line 771
    .line 772
    const/16 v17, 0x0

    .line 773
    .line 774
    const-string v19, "requires_device_idle"

    .line 775
    .line 776
    const-string v20, "INTEGER"

    .line 777
    .line 778
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 779
    .line 780
    .line 781
    move-object/from16 v7, v16

    .line 782
    .line 783
    const-string v9, "requires_device_idle"

    .line 784
    .line 785
    invoke-interface {v0, v9, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    new-instance v13, Lqa/h;

    .line 789
    .line 790
    const/16 v18, 0x0

    .line 791
    .line 792
    const/4 v15, 0x1

    .line 793
    const/16 v19, 0x1

    .line 794
    .line 795
    const/4 v14, 0x0

    .line 796
    const-string v16, "requires_battery_not_low"

    .line 797
    .line 798
    const-string v17, "INTEGER"

    .line 799
    .line 800
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 801
    .line 802
    .line 803
    const-string v7, "requires_battery_not_low"

    .line 804
    .line 805
    invoke-interface {v0, v7, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 806
    .line 807
    .line 808
    new-instance v14, Lqa/h;

    .line 809
    .line 810
    const/16 v19, 0x0

    .line 811
    .line 812
    const/16 v16, 0x1

    .line 813
    .line 814
    const/16 v20, 0x1

    .line 815
    .line 816
    const/4 v15, 0x0

    .line 817
    const-string v17, "requires_storage_not_low"

    .line 818
    .line 819
    const-string v18, "INTEGER"

    .line 820
    .line 821
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 822
    .line 823
    .line 824
    const-string v7, "requires_storage_not_low"

    .line 825
    .line 826
    invoke-interface {v0, v7, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 827
    .line 828
    .line 829
    new-instance v15, Lqa/h;

    .line 830
    .line 831
    const/16 v20, 0x0

    .line 832
    .line 833
    const/16 v17, 0x1

    .line 834
    .line 835
    const/16 v21, 0x1

    .line 836
    .line 837
    const/16 v16, 0x0

    .line 838
    .line 839
    const-string v18, "trigger_content_update_delay"

    .line 840
    .line 841
    const-string v19, "INTEGER"

    .line 842
    .line 843
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 844
    .line 845
    .line 846
    const-string v7, "trigger_content_update_delay"

    .line 847
    .line 848
    invoke-interface {v0, v7, v15}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 849
    .line 850
    .line 851
    new-instance v16, Lqa/h;

    .line 852
    .line 853
    const/16 v21, 0x0

    .line 854
    .line 855
    const/16 v18, 0x1

    .line 856
    .line 857
    const/16 v17, 0x0

    .line 858
    .line 859
    const-string v19, "trigger_max_content_delay"

    .line 860
    .line 861
    const-string v20, "INTEGER"

    .line 862
    .line 863
    invoke-direct/range {v16 .. v22}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 864
    .line 865
    .line 866
    move-object/from16 v7, v16

    .line 867
    .line 868
    const-string v9, "trigger_max_content_delay"

    .line 869
    .line 870
    invoke-interface {v0, v9, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 871
    .line 872
    .line 873
    new-instance v13, Lqa/h;

    .line 874
    .line 875
    const/16 v18, 0x0

    .line 876
    .line 877
    const/4 v15, 0x1

    .line 878
    const/16 v19, 0x1

    .line 879
    .line 880
    const/4 v14, 0x0

    .line 881
    const-string v16, "content_uri_triggers"

    .line 882
    .line 883
    const-string v17, "BLOB"

    .line 884
    .line 885
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 886
    .line 887
    .line 888
    const-string v7, "content_uri_triggers"

    .line 889
    .line 890
    invoke-static {v0, v7, v13}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 891
    .line 892
    .line 893
    move-result-object v7

    .line 894
    new-instance v9, Ljava/util/LinkedHashSet;

    .line 895
    .line 896
    invoke-direct {v9}, Ljava/util/LinkedHashSet;-><init>()V

    .line 897
    .line 898
    .line 899
    new-instance v10, Lqa/j;

    .line 900
    .line 901
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 902
    .line 903
    .line 904
    move-result-object v4

    .line 905
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 906
    .line 907
    .line 908
    move-result-object v13

    .line 909
    const-string v14, "index_WorkSpec_schedule_requested_at"

    .line 910
    .line 911
    invoke-direct {v10, v14, v4, v13, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 912
    .line 913
    .line 914
    invoke-interface {v9, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 915
    .line 916
    .line 917
    new-instance v4, Lqa/j;

    .line 918
    .line 919
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 920
    .line 921
    .line 922
    move-result-object v2

    .line 923
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 924
    .line 925
    .line 926
    move-result-object v10

    .line 927
    const-string v13, "index_WorkSpec_last_enqueue_time"

    .line 928
    .line 929
    invoke-direct {v4, v13, v2, v10, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 930
    .line 931
    .line 932
    invoke-interface {v9, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 933
    .line 934
    .line 935
    new-instance v2, Lqa/k;

    .line 936
    .line 937
    const-string v4, "WorkSpec"

    .line 938
    .line 939
    invoke-direct {v2, v4, v0, v7, v9}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 940
    .line 941
    .line 942
    invoke-static {v1, v4}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 943
    .line 944
    .line 945
    move-result-object v0

    .line 946
    invoke-virtual {v2, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 947
    .line 948
    .line 949
    move-result v4

    .line 950
    if-nez v4, :cond_1

    .line 951
    .line 952
    new-instance v1, Lco/a;

    .line 953
    .line 954
    const-string v3, "WorkSpec(androidx.work.impl.model.WorkSpec).\n Expected:\n"

    .line 955
    .line 956
    invoke-static {v3, v2, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 957
    .line 958
    .line 959
    move-result-object v0

    .line 960
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 961
    .line 962
    .line 963
    goto/16 :goto_0

    .line 964
    .line 965
    :cond_1
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 966
    .line 967
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 968
    .line 969
    .line 970
    new-instance v13, Lqa/h;

    .line 971
    .line 972
    const/16 v18, 0x0

    .line 973
    .line 974
    const/4 v15, 0x1

    .line 975
    const/4 v14, 0x1

    .line 976
    const-string v16, "tag"

    .line 977
    .line 978
    const-string v17, "TEXT"

    .line 979
    .line 980
    const/16 v19, 0x1

    .line 981
    .line 982
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 983
    .line 984
    .line 985
    const-string v2, "tag"

    .line 986
    .line 987
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 988
    .line 989
    .line 990
    new-instance v14, Lqa/h;

    .line 991
    .line 992
    const/16 v19, 0x0

    .line 993
    .line 994
    const/16 v16, 0x1

    .line 995
    .line 996
    const/4 v15, 0x2

    .line 997
    const-string v17, "work_spec_id"

    .line 998
    .line 999
    const-string v18, "TEXT"

    .line 1000
    .line 1001
    const/16 v20, 0x1

    .line 1002
    .line 1003
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1004
    .line 1005
    .line 1006
    invoke-static {v0, v3, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v2

    .line 1010
    new-instance v13, Lqa/i;

    .line 1011
    .line 1012
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v17

    .line 1016
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v18

    .line 1020
    const-string v14, "WorkSpec"

    .line 1021
    .line 1022
    const-string v15, "CASCADE"

    .line 1023
    .line 1024
    const-string v16, "CASCADE"

    .line 1025
    .line 1026
    invoke-direct/range {v13 .. v18}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 1027
    .line 1028
    .line 1029
    invoke-interface {v2, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1030
    .line 1031
    .line 1032
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 1033
    .line 1034
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1035
    .line 1036
    .line 1037
    new-instance v7, Lqa/j;

    .line 1038
    .line 1039
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v9

    .line 1043
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1044
    .line 1045
    .line 1046
    move-result-object v10

    .line 1047
    const-string v13, "index_WorkTag_work_spec_id"

    .line 1048
    .line 1049
    invoke-direct {v7, v13, v9, v10, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 1050
    .line 1051
    .line 1052
    invoke-interface {v4, v7}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1053
    .line 1054
    .line 1055
    new-instance v7, Lqa/k;

    .line 1056
    .line 1057
    const-string v9, "WorkTag"

    .line 1058
    .line 1059
    invoke-direct {v7, v9, v0, v2, v4}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1060
    .line 1061
    .line 1062
    invoke-static {v1, v9}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    invoke-virtual {v7, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1067
    .line 1068
    .line 1069
    move-result v2

    .line 1070
    if-nez v2, :cond_2

    .line 1071
    .line 1072
    new-instance v1, Lco/a;

    .line 1073
    .line 1074
    const-string v2, "WorkTag(androidx.work.impl.model.WorkTag).\n Expected:\n"

    .line 1075
    .line 1076
    invoke-static {v2, v7, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1077
    .line 1078
    .line 1079
    move-result-object v0

    .line 1080
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1081
    .line 1082
    .line 1083
    goto/16 :goto_0

    .line 1084
    .line 1085
    :cond_2
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 1086
    .line 1087
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1088
    .line 1089
    .line 1090
    new-instance v13, Lqa/h;

    .line 1091
    .line 1092
    const/16 v18, 0x0

    .line 1093
    .line 1094
    const/4 v15, 0x1

    .line 1095
    const/4 v14, 0x1

    .line 1096
    const-string v16, "work_spec_id"

    .line 1097
    .line 1098
    const-string v17, "TEXT"

    .line 1099
    .line 1100
    const/16 v19, 0x1

    .line 1101
    .line 1102
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1103
    .line 1104
    .line 1105
    invoke-interface {v0, v3, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1106
    .line 1107
    .line 1108
    new-instance v14, Lqa/h;

    .line 1109
    .line 1110
    const-string v19, "0"

    .line 1111
    .line 1112
    const/16 v16, 0x1

    .line 1113
    .line 1114
    const/4 v15, 0x2

    .line 1115
    const-string v17, "generation"

    .line 1116
    .line 1117
    const-string v18, "INTEGER"

    .line 1118
    .line 1119
    const/16 v20, 0x1

    .line 1120
    .line 1121
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1122
    .line 1123
    .line 1124
    invoke-interface {v0, v6, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1125
    .line 1126
    .line 1127
    new-instance v15, Lqa/h;

    .line 1128
    .line 1129
    const/16 v20, 0x0

    .line 1130
    .line 1131
    const/16 v17, 0x1

    .line 1132
    .line 1133
    const/16 v16, 0x0

    .line 1134
    .line 1135
    const-string v18, "system_id"

    .line 1136
    .line 1137
    const-string v19, "INTEGER"

    .line 1138
    .line 1139
    const/16 v21, 0x1

    .line 1140
    .line 1141
    invoke-direct/range {v15 .. v21}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1142
    .line 1143
    .line 1144
    const-string v2, "system_id"

    .line 1145
    .line 1146
    invoke-static {v0, v2, v15}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    new-instance v13, Lqa/i;

    .line 1151
    .line 1152
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v17

    .line 1156
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v18

    .line 1160
    const-string v14, "WorkSpec"

    .line 1161
    .line 1162
    const-string v15, "CASCADE"

    .line 1163
    .line 1164
    const-string v16, "CASCADE"

    .line 1165
    .line 1166
    invoke-direct/range {v13 .. v18}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 1167
    .line 1168
    .line 1169
    invoke-interface {v2, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1170
    .line 1171
    .line 1172
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 1173
    .line 1174
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1175
    .line 1176
    .line 1177
    new-instance v6, Lqa/k;

    .line 1178
    .line 1179
    const-string v7, "SystemIdInfo"

    .line 1180
    .line 1181
    invoke-direct {v6, v7, v0, v2, v4}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1182
    .line 1183
    .line 1184
    invoke-static {v1, v7}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1185
    .line 1186
    .line 1187
    move-result-object v0

    .line 1188
    invoke-virtual {v6, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1189
    .line 1190
    .line 1191
    move-result v2

    .line 1192
    if-nez v2, :cond_3

    .line 1193
    .line 1194
    new-instance v1, Lco/a;

    .line 1195
    .line 1196
    const-string v2, "SystemIdInfo(androidx.work.impl.model.SystemIdInfo).\n Expected:\n"

    .line 1197
    .line 1198
    invoke-static {v2, v6, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v0

    .line 1202
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1203
    .line 1204
    .line 1205
    goto/16 :goto_0

    .line 1206
    .line 1207
    :cond_3
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 1208
    .line 1209
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1210
    .line 1211
    .line 1212
    new-instance v13, Lqa/h;

    .line 1213
    .line 1214
    const/16 v18, 0x0

    .line 1215
    .line 1216
    const/4 v15, 0x1

    .line 1217
    const/4 v14, 0x1

    .line 1218
    const-string v16, "name"

    .line 1219
    .line 1220
    const-string v17, "TEXT"

    .line 1221
    .line 1222
    const/16 v19, 0x1

    .line 1223
    .line 1224
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1225
    .line 1226
    .line 1227
    const-string v2, "name"

    .line 1228
    .line 1229
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1230
    .line 1231
    .line 1232
    new-instance v14, Lqa/h;

    .line 1233
    .line 1234
    const/16 v19, 0x0

    .line 1235
    .line 1236
    const/16 v16, 0x1

    .line 1237
    .line 1238
    const/4 v15, 0x2

    .line 1239
    const-string v17, "work_spec_id"

    .line 1240
    .line 1241
    const-string v18, "TEXT"

    .line 1242
    .line 1243
    const/16 v20, 0x1

    .line 1244
    .line 1245
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1246
    .line 1247
    .line 1248
    invoke-static {v0, v3, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v2

    .line 1252
    new-instance v13, Lqa/i;

    .line 1253
    .line 1254
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v17

    .line 1258
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v18

    .line 1262
    const-string v14, "WorkSpec"

    .line 1263
    .line 1264
    const-string v15, "CASCADE"

    .line 1265
    .line 1266
    const-string v16, "CASCADE"

    .line 1267
    .line 1268
    invoke-direct/range {v13 .. v18}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 1269
    .line 1270
    .line 1271
    invoke-interface {v2, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1272
    .line 1273
    .line 1274
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 1275
    .line 1276
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1277
    .line 1278
    .line 1279
    new-instance v6, Lqa/j;

    .line 1280
    .line 1281
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v7

    .line 1285
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1286
    .line 1287
    .line 1288
    move-result-object v8

    .line 1289
    const-string v9, "index_WorkName_work_spec_id"

    .line 1290
    .line 1291
    invoke-direct {v6, v9, v7, v8, v12}, Lqa/j;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 1292
    .line 1293
    .line 1294
    invoke-interface {v4, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1295
    .line 1296
    .line 1297
    new-instance v6, Lqa/k;

    .line 1298
    .line 1299
    const-string v7, "WorkName"

    .line 1300
    .line 1301
    invoke-direct {v6, v7, v0, v2, v4}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1302
    .line 1303
    .line 1304
    invoke-static {v1, v7}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v0

    .line 1308
    invoke-virtual {v6, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1309
    .line 1310
    .line 1311
    move-result v2

    .line 1312
    if-nez v2, :cond_4

    .line 1313
    .line 1314
    new-instance v1, Lco/a;

    .line 1315
    .line 1316
    const-string v2, "WorkName(androidx.work.impl.model.WorkName).\n Expected:\n"

    .line 1317
    .line 1318
    invoke-static {v2, v6, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v0

    .line 1322
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1323
    .line 1324
    .line 1325
    goto/16 :goto_0

    .line 1326
    .line 1327
    :cond_4
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 1328
    .line 1329
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1330
    .line 1331
    .line 1332
    new-instance v13, Lqa/h;

    .line 1333
    .line 1334
    const/16 v18, 0x0

    .line 1335
    .line 1336
    const/4 v15, 0x1

    .line 1337
    const/4 v14, 0x1

    .line 1338
    const-string v16, "work_spec_id"

    .line 1339
    .line 1340
    const-string v17, "TEXT"

    .line 1341
    .line 1342
    const/16 v19, 0x1

    .line 1343
    .line 1344
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1345
    .line 1346
    .line 1347
    invoke-interface {v0, v3, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1348
    .line 1349
    .line 1350
    new-instance v14, Lqa/h;

    .line 1351
    .line 1352
    const/16 v19, 0x0

    .line 1353
    .line 1354
    const/16 v16, 0x1

    .line 1355
    .line 1356
    const/4 v15, 0x0

    .line 1357
    const-string v17, "progress"

    .line 1358
    .line 1359
    const-string v18, "BLOB"

    .line 1360
    .line 1361
    const/16 v20, 0x1

    .line 1362
    .line 1363
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1364
    .line 1365
    .line 1366
    const-string v2, "progress"

    .line 1367
    .line 1368
    invoke-static {v0, v2, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v2

    .line 1372
    new-instance v13, Lqa/i;

    .line 1373
    .line 1374
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v17

    .line 1378
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1379
    .line 1380
    .line 1381
    move-result-object v18

    .line 1382
    const-string v14, "WorkSpec"

    .line 1383
    .line 1384
    const-string v15, "CASCADE"

    .line 1385
    .line 1386
    const-string v16, "CASCADE"

    .line 1387
    .line 1388
    invoke-direct/range {v13 .. v18}, Lqa/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 1389
    .line 1390
    .line 1391
    invoke-interface {v2, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1392
    .line 1393
    .line 1394
    new-instance v3, Ljava/util/LinkedHashSet;

    .line 1395
    .line 1396
    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1397
    .line 1398
    .line 1399
    new-instance v4, Lqa/k;

    .line 1400
    .line 1401
    const-string v6, "WorkProgress"

    .line 1402
    .line 1403
    invoke-direct {v4, v6, v0, v2, v3}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1404
    .line 1405
    .line 1406
    invoke-static {v1, v6}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v0

    .line 1410
    invoke-virtual {v4, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1411
    .line 1412
    .line 1413
    move-result v2

    .line 1414
    if-nez v2, :cond_5

    .line 1415
    .line 1416
    new-instance v1, Lco/a;

    .line 1417
    .line 1418
    const-string v2, "WorkProgress(androidx.work.impl.model.WorkProgress).\n Expected:\n"

    .line 1419
    .line 1420
    invoke-static {v2, v4, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v0

    .line 1424
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1425
    .line 1426
    .line 1427
    goto :goto_0

    .line 1428
    :cond_5
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 1429
    .line 1430
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1431
    .line 1432
    .line 1433
    new-instance v13, Lqa/h;

    .line 1434
    .line 1435
    const/16 v18, 0x0

    .line 1436
    .line 1437
    const/4 v15, 0x1

    .line 1438
    const/4 v14, 0x1

    .line 1439
    const-string v16, "key"

    .line 1440
    .line 1441
    const-string v17, "TEXT"

    .line 1442
    .line 1443
    const/16 v19, 0x1

    .line 1444
    .line 1445
    invoke-direct/range {v13 .. v19}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1446
    .line 1447
    .line 1448
    const-string v2, "key"

    .line 1449
    .line 1450
    invoke-interface {v0, v2, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1451
    .line 1452
    .line 1453
    new-instance v14, Lqa/h;

    .line 1454
    .line 1455
    const/16 v19, 0x0

    .line 1456
    .line 1457
    const/16 v16, 0x1

    .line 1458
    .line 1459
    const/4 v15, 0x0

    .line 1460
    const-string v17, "long_value"

    .line 1461
    .line 1462
    const-string v18, "INTEGER"

    .line 1463
    .line 1464
    const/16 v20, 0x0

    .line 1465
    .line 1466
    invoke-direct/range {v14 .. v20}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1467
    .line 1468
    .line 1469
    const-string v2, "long_value"

    .line 1470
    .line 1471
    invoke-static {v0, v2, v14}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1472
    .line 1473
    .line 1474
    move-result-object v2

    .line 1475
    new-instance v3, Ljava/util/LinkedHashSet;

    .line 1476
    .line 1477
    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1478
    .line 1479
    .line 1480
    new-instance v4, Lqa/k;

    .line 1481
    .line 1482
    const-string v6, "Preference"

    .line 1483
    .line 1484
    invoke-direct {v4, v6, v0, v2, v3}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1485
    .line 1486
    .line 1487
    invoke-static {v1, v6}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v0

    .line 1491
    invoke-virtual {v4, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1492
    .line 1493
    .line 1494
    move-result v1

    .line 1495
    if-nez v1, :cond_6

    .line 1496
    .line 1497
    new-instance v1, Lco/a;

    .line 1498
    .line 1499
    const-string v2, "Preference(androidx.work.impl.model.Preference).\n Expected:\n"

    .line 1500
    .line 1501
    invoke-static {v2, v4, v5, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1502
    .line 1503
    .line 1504
    move-result-object v0

    .line 1505
    invoke-direct {v1, v12, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1506
    .line 1507
    .line 1508
    goto :goto_0

    .line 1509
    :cond_6
    new-instance v1, Lco/a;

    .line 1510
    .line 1511
    const/4 v0, 0x1

    .line 1512
    const/4 v2, 0x0

    .line 1513
    invoke-direct {v1, v0, v2}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1514
    .line 1515
    .line 1516
    :goto_0
    return-object v1

    .line 1517
    :pswitch_1
    const-string v0, "connection"

    .line 1518
    .line 1519
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1520
    .line 1521
    .line 1522
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 1523
    .line 1524
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1525
    .line 1526
    .line 1527
    new-instance v2, Lqa/h;

    .line 1528
    .line 1529
    const/4 v7, 0x0

    .line 1530
    const/4 v4, 0x1

    .line 1531
    const/4 v3, 0x1

    .line 1532
    const-string v5, "id"

    .line 1533
    .line 1534
    const-string v6, "TEXT"

    .line 1535
    .line 1536
    const/4 v8, 0x1

    .line 1537
    invoke-direct/range {v2 .. v8}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1538
    .line 1539
    .line 1540
    const-string v3, "id"

    .line 1541
    .line 1542
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1543
    .line 1544
    .line 1545
    new-instance v4, Lqa/h;

    .line 1546
    .line 1547
    const/4 v9, 0x0

    .line 1548
    const/4 v6, 0x1

    .line 1549
    const/4 v5, 0x0

    .line 1550
    const-string v7, "eventType"

    .line 1551
    .line 1552
    const-string v8, "TEXT"

    .line 1553
    .line 1554
    const/4 v10, 0x1

    .line 1555
    invoke-direct/range {v4 .. v10}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1556
    .line 1557
    .line 1558
    const-string v2, "eventType"

    .line 1559
    .line 1560
    invoke-interface {v0, v2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1561
    .line 1562
    .line 1563
    new-instance v5, Lqa/h;

    .line 1564
    .line 1565
    const/4 v10, 0x0

    .line 1566
    const/4 v7, 0x1

    .line 1567
    const/4 v6, 0x0

    .line 1568
    const-string v8, "payload"

    .line 1569
    .line 1570
    const-string v9, "TEXT"

    .line 1571
    .line 1572
    const/4 v11, 0x1

    .line 1573
    invoke-direct/range {v5 .. v11}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1574
    .line 1575
    .line 1576
    const-string v2, "payload"

    .line 1577
    .line 1578
    invoke-interface {v0, v2, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1579
    .line 1580
    .line 1581
    new-instance v6, Lqa/h;

    .line 1582
    .line 1583
    const/4 v11, 0x0

    .line 1584
    const/4 v8, 0x1

    .line 1585
    const/4 v7, 0x0

    .line 1586
    const-string v9, "timestamp"

    .line 1587
    .line 1588
    const-string v10, "INTEGER"

    .line 1589
    .line 1590
    const/4 v12, 0x1

    .line 1591
    invoke-direct/range {v6 .. v12}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1592
    .line 1593
    .line 1594
    const-string v2, "timestamp"

    .line 1595
    .line 1596
    invoke-interface {v0, v2, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1597
    .line 1598
    .line 1599
    new-instance v7, Lqa/h;

    .line 1600
    .line 1601
    const/4 v12, 0x0

    .line 1602
    const/4 v9, 0x1

    .line 1603
    const/4 v8, 0x0

    .line 1604
    const-string v10, "toadStamp"

    .line 1605
    .line 1606
    const-string v11, "INTEGER"

    .line 1607
    .line 1608
    const/4 v13, 0x1

    .line 1609
    invoke-direct/range {v7 .. v13}, Lqa/h;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1610
    .line 1611
    .line 1612
    const-string v2, "toadStamp"

    .line 1613
    .line 1614
    invoke-static {v0, v2, v7}, Lf2/m0;->p(Ljava/util/LinkedHashMap;Ljava/lang/String;Lqa/h;)Ljava/util/LinkedHashSet;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v2

    .line 1618
    new-instance v3, Ljava/util/LinkedHashSet;

    .line 1619
    .line 1620
    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 1621
    .line 1622
    .line 1623
    new-instance v4, Lqa/k;

    .line 1624
    .line 1625
    const-string v5, "event"

    .line 1626
    .line 1627
    invoke-direct {v4, v5, v0, v2, v3}, Lqa/k;-><init>(Ljava/lang/String;Ljava/util/Map;Ljava/util/AbstractSet;Ljava/util/AbstractSet;)V

    .line 1628
    .line 1629
    .line 1630
    invoke-static {v1, v5}, Ljp/df;->e(Lua/a;Ljava/lang/String;)Lqa/k;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v0

    .line 1634
    invoke-virtual {v4, v0}, Lqa/k;->equals(Ljava/lang/Object;)Z

    .line 1635
    .line 1636
    .line 1637
    move-result v1

    .line 1638
    if-nez v1, :cond_7

    .line 1639
    .line 1640
    new-instance v1, Lco/a;

    .line 1641
    .line 1642
    const-string v2, "event(technology.cariad.cat.network.tracing.offline.entities.EventEntity).\n Expected:\n"

    .line 1643
    .line 1644
    const-string v3, "\n Found:\n"

    .line 1645
    .line 1646
    invoke-static {v2, v4, v3, v0}, Lf2/m0;->j(Ljava/lang/String;Lqa/k;Ljava/lang/String;Lqa/k;)Ljava/lang/String;

    .line 1647
    .line 1648
    .line 1649
    move-result-object v0

    .line 1650
    const/4 v2, 0x0

    .line 1651
    invoke-direct {v1, v2, v0}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1652
    .line 1653
    .line 1654
    goto :goto_1

    .line 1655
    :cond_7
    new-instance v1, Lco/a;

    .line 1656
    .line 1657
    const/4 v0, 0x1

    .line 1658
    const/4 v2, 0x0

    .line 1659
    invoke-direct {v1, v0, v2}, Lco/a;-><init>(ZLjava/lang/String;)V

    .line 1660
    .line 1661
    .line 1662
    :goto_1
    return-object v1

    .line 1663
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
