.class public final synthetic Lif0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lif0/u;Ljava/lang/String;)V
    .locals 0

    .line 1
    const/4 p1, 0x3

    iput p1, p0, Lif0/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lif0/d;->e:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 2
    iput p2, p0, Lif0/d;->d:I

    iput-object p1, p0, Lif0/d;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lod0/e;)V
    .locals 0

    .line 3
    const/16 p2, 0x1d

    iput p2, p0, Lif0/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lif0/d;->e:Ljava/lang/String;

    return-void
.end method

.method private final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lif0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lua/a;

    .line 4
    .line 5
    const-string v0, "_connection"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "SELECT output FROM workspec WHERE id IN\n             (SELECT prerequisite_id FROM dependency WHERE work_spec_id=?)"

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x1

    .line 17
    :try_start_0
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 23
    .line 24
    .line 25
    :goto_0
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    invoke-interface {p1, v0}, Lua/c;->getBlob(I)[B

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sget-object v1, Leb/h;->b:Leb/h;

    .line 37
    .line 38
    invoke-static {v0}, Lkp/b6;->b([B)Leb/h;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :goto_1
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 53
    .line 54
    .line 55
    throw p0
.end method

.method private final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lif0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lua/a;

    .line 4
    .line 5
    const-string v0, "_connection"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "DELETE FROM workspec WHERE id=?"

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x1

    .line 17
    :try_start_0
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method private final c(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object p0, p0, Lif0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lua/a;

    .line 4
    .line 5
    const-string v0, "_connection"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "SELECT id, state FROM workspec WHERE id IN (SELECT work_spec_id FROM workname WHERE name=?)"

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x1

    .line 17
    :try_start_0
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 23
    .line 24
    .line 25
    :goto_0
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-interface {p1, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {p1, v0}, Lua/c;->getLong(I)J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    long-to-int v2, v2

    .line 41
    invoke-static {v2}, Ljp/z0;->g(I)Leb/h0;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    new-instance v3, Lmb/m;

    .line 46
    .line 47
    const-string v4, "id"

    .line 48
    .line 49
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v1, v3, Lmb/m;->a:Ljava/lang/String;

    .line 56
    .line 57
    iput-object v2, v3, Lmb/m;->b:Leb/h0;

    .line 58
    .line 59
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :catchall_0
    move-exception p0

    .line 64
    goto :goto_1

    .line 65
    :cond_0
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 66
    .line 67
    .line 68
    return-object p0

    .line 69
    :goto_1
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 70
    .line 71
    .line 72
    throw p0
.end method

.method private final d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lif0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lua/a;

    .line 4
    .line 5
    const-string v0, "_connection"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "SELECT DISTINCT tag FROM worktag WHERE work_spec_id=?"

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x1

    .line 17
    :try_start_0
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 23
    .line 24
    .line 25
    :goto_0
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    invoke-interface {p1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :goto_1
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 47
    .line 48
    .line 49
    throw p0
.end method

.method private final e(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Landroidx/work/impl/WorkDatabase;

    .line 2
    .line 3
    const-string v0, "db"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lmb/o;->A:Lj9/d;

    .line 9
    .line 10
    invoke-virtual {p1}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string v1, "name"

    .line 18
    .line 19
    iget-object p0, p0, Lif0/d;->e:Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p1, Lmb/s;->a:Lla/u;

    .line 25
    .line 26
    new-instance v2, Ll2/v1;

    .line 27
    .line 28
    const/16 v3, 0x9

    .line 29
    .line 30
    invoke-direct {v2, v3, p0, p1}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    invoke-static {v1, p0, p0, v2}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/util/List;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Lj9/d;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string p1, "apply(...)"

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    check-cast p0, Ljava/util/List;

    .line 50
    .line 51
    return-object p0
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 79

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lif0/d;->d:I

    .line 4
    .line 5
    const-string v2, "$this$sdkViewModel"

    .line 6
    .line 7
    const-string v3, "fleet"

    .line 8
    .line 9
    const-string v4, "SELECT * FROM fleet WHERE vin = ? LIMIT 1"

    .line 10
    .line 11
    const-string v5, "vin"

    .line 12
    .line 13
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    const-string v9, "_connection"

    .line 16
    .line 17
    const/4 v10, 0x1

    .line 18
    iget-object v11, v0, Lif0/d;->e:Ljava/lang/String;

    .line 19
    .line 20
    packed-switch v1, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    move-object/from16 v0, p1

    .line 24
    .line 25
    check-cast v0, Lua/a;

    .line 26
    .line 27
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string v1, "SELECT * FROM charging WHERE vin = ? LIMIT 1"

    .line 31
    .line 32
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    :try_start_0
    invoke-interface {v1, v10, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const-string v2, "battery_care_mode"

    .line 44
    .line 45
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    const-string v3, "in_saved_location"

    .line 50
    .line 51
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    const-string v4, "charging_errors"

    .line 56
    .line 57
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    const-string v5, "car_captured_timestamp"

    .line 62
    .line 63
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    const-string v6, "battery_statuscurrent_charged_state"

    .line 68
    .line 69
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    const-string v9, "battery_statuscruising_range_electric"

    .line 74
    .line 75
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    const-string v11, "charging_settings_charge_current"

    .line 80
    .line 81
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    const-string v12, "charging_settings_max_charge_current"

    .line 86
    .line 87
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    const-string v13, "charging_settings_plug_unlock"

    .line 92
    .line 93
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v13

    .line 97
    const-string v14, "charging_settings_target_charged_state"

    .line 98
    .line 99
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v14

    .line 103
    const-string v15, "charging_settings_battery_care_mode_target_value"

    .line 104
    .line 105
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 106
    .line 107
    .line 108
    move-result v15

    .line 109
    const-string v7, "charging_status_charging_state"

    .line 110
    .line 111
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    const-string v8, "charging_status_charging_type"

    .line 116
    .line 117
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    const-string v10, "charging_status_charge_power"

    .line 122
    .line 123
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 124
    .line 125
    .line 126
    move-result v10

    .line 127
    move/from16 p0, v10

    .line 128
    .line 129
    const-string v10, "charging_status_remaining_time_to_complete"

    .line 130
    .line 131
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 132
    .line 133
    .line 134
    move-result v10

    .line 135
    move/from16 p1, v10

    .line 136
    .line 137
    const-string v10, "charging_status_charging_rate_in_kilometers_per_hour"

    .line 138
    .line 139
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 140
    .line 141
    .line 142
    move-result v10

    .line 143
    move/from16 v16, v10

    .line 144
    .line 145
    const-string v10, "charge_mode_settings_available_charge_modes"

    .line 146
    .line 147
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    move-result v10

    .line 151
    move/from16 v17, v10

    .line 152
    .line 153
    const-string v10, "charge_mode_settings_preferred_charge_mode"

    .line 154
    .line 155
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 156
    .line 157
    .line 158
    move-result v10

    .line 159
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 160
    .line 161
    .line 162
    move-result v18

    .line 163
    if-eqz v18, :cond_1c

    .line 164
    .line 165
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v20

    .line 169
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-eqz v0, :cond_0

    .line 174
    .line 175
    const/16 v21, 0x0

    .line 176
    .line 177
    goto :goto_0

    .line 178
    :cond_0
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    move-object/from16 v21, v0

    .line 183
    .line 184
    :goto_0
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 185
    .line 186
    .line 187
    move-result-wide v2

    .line 188
    long-to-int v0, v2

    .line 189
    if-eqz v0, :cond_1

    .line 190
    .line 191
    const/16 v22, 0x1

    .line 192
    .line 193
    goto :goto_1

    .line 194
    :cond_1
    const/16 v22, 0x0

    .line 195
    .line 196
    :goto_1
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    if-eqz v0, :cond_2

    .line 201
    .line 202
    const/16 v23, 0x0

    .line 203
    .line 204
    goto :goto_2

    .line 205
    :cond_2
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    move-object/from16 v23, v0

    .line 210
    .line 211
    :goto_2
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 212
    .line 213
    .line 214
    move-result v0

    .line 215
    if-eqz v0, :cond_3

    .line 216
    .line 217
    const/4 v0, 0x0

    .line 218
    goto :goto_3

    .line 219
    :cond_3
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    :goto_3
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 224
    .line 225
    .line 226
    move-result-object v28

    .line 227
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 228
    .line 229
    .line 230
    move-result v0

    .line 231
    if-eqz v0, :cond_5

    .line 232
    .line 233
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    if-nez v0, :cond_4

    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_4
    const/16 v24, 0x0

    .line 241
    .line 242
    goto :goto_7

    .line 243
    :catchall_0
    move-exception v0

    .line 244
    goto/16 :goto_1e

    .line 245
    .line 246
    :cond_5
    :goto_4
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 247
    .line 248
    .line 249
    move-result v0

    .line 250
    if-eqz v0, :cond_6

    .line 251
    .line 252
    const/4 v0, 0x0

    .line 253
    goto :goto_5

    .line 254
    :cond_6
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 255
    .line 256
    .line 257
    move-result-wide v2

    .line 258
    long-to-int v0, v2

    .line 259
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    :goto_5
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    if-eqz v2, :cond_7

    .line 268
    .line 269
    const/4 v2, 0x0

    .line 270
    goto :goto_6

    .line 271
    :cond_7
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 272
    .line 273
    .line 274
    move-result-wide v2

    .line 275
    long-to-int v2, v2

    .line 276
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    :goto_6
    new-instance v3, Lod0/c;

    .line 281
    .line 282
    invoke-direct {v3, v0, v2}, Lod0/c;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 283
    .line 284
    .line 285
    move-object/from16 v24, v3

    .line 286
    .line 287
    :goto_7
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    if-eqz v0, :cond_9

    .line 292
    .line 293
    invoke-interface {v1, v12}, Lua/c;->isNull(I)Z

    .line 294
    .line 295
    .line 296
    move-result v0

    .line 297
    if-eqz v0, :cond_9

    .line 298
    .line 299
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 300
    .line 301
    .line 302
    move-result v0

    .line 303
    if-eqz v0, :cond_9

    .line 304
    .line 305
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 306
    .line 307
    .line 308
    move-result v0

    .line 309
    if-eqz v0, :cond_9

    .line 310
    .line 311
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    if-nez v0, :cond_8

    .line 316
    .line 317
    goto :goto_8

    .line 318
    :cond_8
    const/16 v25, 0x0

    .line 319
    .line 320
    goto :goto_e

    .line 321
    :cond_9
    :goto_8
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 322
    .line 323
    .line 324
    move-result v0

    .line 325
    if-eqz v0, :cond_a

    .line 326
    .line 327
    const/16 v33, 0x0

    .line 328
    .line 329
    goto :goto_9

    .line 330
    :cond_a
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    move-object/from16 v33, v0

    .line 335
    .line 336
    :goto_9
    invoke-interface {v1, v12}, Lua/c;->isNull(I)Z

    .line 337
    .line 338
    .line 339
    move-result v0

    .line 340
    if-eqz v0, :cond_b

    .line 341
    .line 342
    const/16 v30, 0x0

    .line 343
    .line 344
    goto :goto_a

    .line 345
    :cond_b
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 346
    .line 347
    .line 348
    move-result-wide v2

    .line 349
    long-to-int v0, v2

    .line 350
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    move-object/from16 v30, v0

    .line 355
    .line 356
    :goto_a
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 357
    .line 358
    .line 359
    move-result v0

    .line 360
    if-eqz v0, :cond_c

    .line 361
    .line 362
    const/16 v34, 0x0

    .line 363
    .line 364
    goto :goto_b

    .line 365
    :cond_c
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    move-object/from16 v34, v0

    .line 370
    .line 371
    :goto_b
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 372
    .line 373
    .line 374
    move-result v0

    .line 375
    if-eqz v0, :cond_d

    .line 376
    .line 377
    const/16 v31, 0x0

    .line 378
    .line 379
    goto :goto_c

    .line 380
    :cond_d
    invoke-interface {v1, v14}, Lua/c;->getLong(I)J

    .line 381
    .line 382
    .line 383
    move-result-wide v2

    .line 384
    long-to-int v0, v2

    .line 385
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 386
    .line 387
    .line 388
    move-result-object v0

    .line 389
    move-object/from16 v31, v0

    .line 390
    .line 391
    :goto_c
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 392
    .line 393
    .line 394
    move-result v0

    .line 395
    if-eqz v0, :cond_e

    .line 396
    .line 397
    const/16 v32, 0x0

    .line 398
    .line 399
    goto :goto_d

    .line 400
    :cond_e
    invoke-interface {v1, v15}, Lua/c;->getLong(I)J

    .line 401
    .line 402
    .line 403
    move-result-wide v2

    .line 404
    long-to-int v0, v2

    .line 405
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 406
    .line 407
    .line 408
    move-result-object v0

    .line 409
    move-object/from16 v32, v0

    .line 410
    .line 411
    :goto_d
    new-instance v29, Lod0/s;

    .line 412
    .line 413
    invoke-direct/range {v29 .. v34}, Lod0/s;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    move-object/from16 v25, v29

    .line 417
    .line 418
    :goto_e
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 419
    .line 420
    .line 421
    move-result v0

    .line 422
    if-eqz v0, :cond_12

    .line 423
    .line 424
    invoke-interface {v1, v8}, Lua/c;->isNull(I)Z

    .line 425
    .line 426
    .line 427
    move-result v0

    .line 428
    if-eqz v0, :cond_12

    .line 429
    .line 430
    move/from16 v0, p0

    .line 431
    .line 432
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 433
    .line 434
    .line 435
    move-result v2

    .line 436
    if-eqz v2, :cond_11

    .line 437
    .line 438
    move/from16 v2, p1

    .line 439
    .line 440
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 441
    .line 442
    .line 443
    move-result v3

    .line 444
    if-eqz v3, :cond_10

    .line 445
    .line 446
    move/from16 v3, v16

    .line 447
    .line 448
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 449
    .line 450
    .line 451
    move-result v4

    .line 452
    if-nez v4, :cond_f

    .line 453
    .line 454
    goto :goto_12

    .line 455
    :cond_f
    const/16 v26, 0x0

    .line 456
    .line 457
    :goto_f
    move/from16 v0, v17

    .line 458
    .line 459
    goto/16 :goto_18

    .line 460
    .line 461
    :cond_10
    :goto_10
    move/from16 v3, v16

    .line 462
    .line 463
    goto :goto_12

    .line 464
    :cond_11
    :goto_11
    move/from16 v2, p1

    .line 465
    .line 466
    goto :goto_10

    .line 467
    :cond_12
    move/from16 v0, p0

    .line 468
    .line 469
    goto :goto_11

    .line 470
    :goto_12
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 471
    .line 472
    .line 473
    move-result v4

    .line 474
    if-eqz v4, :cond_13

    .line 475
    .line 476
    const/16 v30, 0x0

    .line 477
    .line 478
    goto :goto_13

    .line 479
    :cond_13
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v4

    .line 483
    move-object/from16 v30, v4

    .line 484
    .line 485
    :goto_13
    invoke-interface {v1, v8}, Lua/c;->isNull(I)Z

    .line 486
    .line 487
    .line 488
    move-result v4

    .line 489
    if-eqz v4, :cond_14

    .line 490
    .line 491
    const/16 v31, 0x0

    .line 492
    .line 493
    goto :goto_14

    .line 494
    :cond_14
    invoke-interface {v1, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 495
    .line 496
    .line 497
    move-result-object v4

    .line 498
    move-object/from16 v31, v4

    .line 499
    .line 500
    :goto_14
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 501
    .line 502
    .line 503
    move-result v4

    .line 504
    if-eqz v4, :cond_15

    .line 505
    .line 506
    const/16 v32, 0x0

    .line 507
    .line 508
    goto :goto_15

    .line 509
    :cond_15
    invoke-interface {v1, v0}, Lua/c;->getDouble(I)D

    .line 510
    .line 511
    .line 512
    move-result-wide v4

    .line 513
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    move-object/from16 v32, v0

    .line 518
    .line 519
    :goto_15
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 520
    .line 521
    .line 522
    move-result v0

    .line 523
    if-eqz v0, :cond_16

    .line 524
    .line 525
    const/16 v33, 0x0

    .line 526
    .line 527
    goto :goto_16

    .line 528
    :cond_16
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 529
    .line 530
    .line 531
    move-result-wide v4

    .line 532
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 533
    .line 534
    .line 535
    move-result-object v0

    .line 536
    move-object/from16 v33, v0

    .line 537
    .line 538
    :goto_16
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 539
    .line 540
    .line 541
    move-result v0

    .line 542
    if-eqz v0, :cond_17

    .line 543
    .line 544
    const/16 v34, 0x0

    .line 545
    .line 546
    goto :goto_17

    .line 547
    :cond_17
    invoke-interface {v1, v3}, Lua/c;->getDouble(I)D

    .line 548
    .line 549
    .line 550
    move-result-wide v2

    .line 551
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 552
    .line 553
    .line 554
    move-result-object v0

    .line 555
    move-object/from16 v34, v0

    .line 556
    .line 557
    :goto_17
    new-instance v29, Lod0/t;

    .line 558
    .line 559
    invoke-direct/range {v29 .. v34}, Lod0/t;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Long;Ljava/lang/Double;)V

    .line 560
    .line 561
    .line 562
    move-object/from16 v26, v29

    .line 563
    .line 564
    goto :goto_f

    .line 565
    :goto_18
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 566
    .line 567
    .line 568
    move-result v2

    .line 569
    if-eqz v2, :cond_19

    .line 570
    .line 571
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 572
    .line 573
    .line 574
    move-result v2

    .line 575
    if-nez v2, :cond_18

    .line 576
    .line 577
    goto :goto_19

    .line 578
    :cond_18
    const/16 v27, 0x0

    .line 579
    .line 580
    goto :goto_1c

    .line 581
    :cond_19
    :goto_19
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 582
    .line 583
    .line 584
    move-result v2

    .line 585
    if-eqz v2, :cond_1a

    .line 586
    .line 587
    const/4 v0, 0x0

    .line 588
    goto :goto_1a

    .line 589
    :cond_1a
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    :goto_1a
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 594
    .line 595
    .line 596
    move-result v2

    .line 597
    if-eqz v2, :cond_1b

    .line 598
    .line 599
    const/4 v7, 0x0

    .line 600
    goto :goto_1b

    .line 601
    :cond_1b
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 602
    .line 603
    .line 604
    move-result-object v7

    .line 605
    :goto_1b
    new-instance v2, Lod0/b;

    .line 606
    .line 607
    invoke-direct {v2, v0, v7}, Lod0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 608
    .line 609
    .line 610
    move-object/from16 v27, v2

    .line 611
    .line 612
    :goto_1c
    new-instance v19, Lod0/f;

    .line 613
    .line 614
    invoke-direct/range {v19 .. v28}, Lod0/f;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lod0/c;Lod0/s;Lod0/t;Lod0/b;Ljava/time/OffsetDateTime;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 615
    .line 616
    .line 617
    move-object/from16 v7, v19

    .line 618
    .line 619
    goto :goto_1d

    .line 620
    :cond_1c
    const/4 v7, 0x0

    .line 621
    :goto_1d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 622
    .line 623
    .line 624
    return-object v7

    .line 625
    :goto_1e
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 626
    .line 627
    .line 628
    throw v0

    .line 629
    :pswitch_0
    invoke-direct/range {p0 .. p1}, Lif0/d;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 630
    .line 631
    .line 632
    move-result-object v0

    .line 633
    return-object v0

    .line 634
    :pswitch_1
    invoke-direct/range {p0 .. p1}, Lif0/d;->d(Ljava/lang/Object;)Ljava/lang/Object;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    return-object v0

    .line 639
    :pswitch_2
    invoke-direct/range {p0 .. p1}, Lif0/d;->c(Ljava/lang/Object;)Ljava/lang/Object;

    .line 640
    .line 641
    .line 642
    move-result-object v0

    .line 643
    return-object v0

    .line 644
    :pswitch_3
    invoke-direct/range {p0 .. p1}, Lif0/d;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 645
    .line 646
    .line 647
    move-result-object v0

    .line 648
    return-object v0

    .line 649
    :pswitch_4
    move-object/from16 v0, p1

    .line 650
    .line 651
    check-cast v0, Lua/a;

    .line 652
    .line 653
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    const-string v1, "UPDATE workspec SET run_attempt_count=run_attempt_count+1 WHERE id=?"

    .line 657
    .line 658
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 659
    .line 660
    .line 661
    move-result-object v1

    .line 662
    const/4 v2, 0x1

    .line 663
    :try_start_1
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 664
    .line 665
    .line 666
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 667
    .line 668
    .line 669
    invoke-static {v0}, Ljp/ze;->b(Lua/a;)I

    .line 670
    .line 671
    .line 672
    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 673
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 674
    .line 675
    .line 676
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 677
    .line 678
    .line 679
    move-result-object v0

    .line 680
    return-object v0

    .line 681
    :catchall_1
    move-exception v0

    .line 682
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 683
    .line 684
    .line 685
    throw v0

    .line 686
    :pswitch_5
    invoke-direct/range {p0 .. p1}, Lif0/d;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 687
    .line 688
    .line 689
    move-result-object v0

    .line 690
    return-object v0

    .line 691
    :pswitch_6
    move-object/from16 v0, p1

    .line 692
    .line 693
    check-cast v0, Lua/a;

    .line 694
    .line 695
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 696
    .line 697
    .line 698
    const-string v1, "UPDATE workspec SET period_count=period_count+1 WHERE id=?"

    .line 699
    .line 700
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 701
    .line 702
    .line 703
    move-result-object v1

    .line 704
    const/4 v2, 0x1

    .line 705
    :try_start_2
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 706
    .line 707
    .line 708
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 709
    .line 710
    .line 711
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 712
    .line 713
    .line 714
    return-object v6

    .line 715
    :catchall_2
    move-exception v0

    .line 716
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 717
    .line 718
    .line 719
    throw v0

    .line 720
    :pswitch_7
    move-object/from16 v0, p1

    .line 721
    .line 722
    check-cast v0, Lua/a;

    .line 723
    .line 724
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 725
    .line 726
    .line 727
    const-string v1, "UPDATE workspec SET run_attempt_count=0 WHERE id=?"

    .line 728
    .line 729
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 730
    .line 731
    .line 732
    move-result-object v1

    .line 733
    const/4 v2, 0x1

    .line 734
    :try_start_3
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 735
    .line 736
    .line 737
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 738
    .line 739
    .line 740
    invoke-static {v0}, Ljp/ze;->b(Lua/a;)I

    .line 741
    .line 742
    .line 743
    move-result v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 744
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 745
    .line 746
    .line 747
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 748
    .line 749
    .line 750
    move-result-object v0

    .line 751
    return-object v0

    .line 752
    :catchall_3
    move-exception v0

    .line 753
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 754
    .line 755
    .line 756
    throw v0

    .line 757
    :pswitch_8
    move-object/from16 v0, p1

    .line 758
    .line 759
    check-cast v0, Lua/a;

    .line 760
    .line 761
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 762
    .line 763
    .line 764
    const-string v1, "UPDATE workspec SET stop_reason = CASE WHEN state=1 THEN 1 ELSE -256 END, state=5 WHERE id=?"

    .line 765
    .line 766
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 767
    .line 768
    .line 769
    move-result-object v1

    .line 770
    const/4 v2, 0x1

    .line 771
    :try_start_4
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 772
    .line 773
    .line 774
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 775
    .line 776
    .line 777
    invoke-static {v0}, Ljp/ze;->b(Lua/a;)I

    .line 778
    .line 779
    .line 780
    move-result v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 781
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 782
    .line 783
    .line 784
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 785
    .line 786
    .line 787
    move-result-object v0

    .line 788
    return-object v0

    .line 789
    :catchall_4
    move-exception v0

    .line 790
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 791
    .line 792
    .line 793
    throw v0

    .line 794
    :pswitch_9
    move-object/from16 v0, p1

    .line 795
    .line 796
    check-cast v0, Lua/a;

    .line 797
    .line 798
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    const-string v1, "SELECT id FROM workspec WHERE state NOT IN (2, 3, 5) AND id IN (SELECT work_spec_id FROM workname WHERE name=?)"

    .line 802
    .line 803
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 804
    .line 805
    .line 806
    move-result-object v1

    .line 807
    const/4 v2, 0x1

    .line 808
    :try_start_5
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 809
    .line 810
    .line 811
    new-instance v0, Ljava/util/ArrayList;

    .line 812
    .line 813
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 814
    .line 815
    .line 816
    :goto_1f
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 817
    .line 818
    .line 819
    move-result v2

    .line 820
    if-eqz v2, :cond_1d

    .line 821
    .line 822
    const/4 v2, 0x0

    .line 823
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 824
    .line 825
    .line 826
    move-result-object v3

    .line 827
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 828
    .line 829
    .line 830
    goto :goto_1f

    .line 831
    :catchall_5
    move-exception v0

    .line 832
    goto :goto_20

    .line 833
    :cond_1d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 834
    .line 835
    .line 836
    return-object v0

    .line 837
    :goto_20
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 838
    .line 839
    .line 840
    throw v0

    .line 841
    :pswitch_a
    move-object/from16 v0, p1

    .line 842
    .line 843
    check-cast v0, Lua/a;

    .line 844
    .line 845
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 846
    .line 847
    .line 848
    const-string v1, "SELECT state FROM workspec WHERE id=?"

    .line 849
    .line 850
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 851
    .line 852
    .line 853
    move-result-object v1

    .line 854
    const/4 v2, 0x1

    .line 855
    :try_start_6
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 856
    .line 857
    .line 858
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 859
    .line 860
    .line 861
    move-result v0

    .line 862
    if-eqz v0, :cond_1f

    .line 863
    .line 864
    const/4 v2, 0x0

    .line 865
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 866
    .line 867
    .line 868
    move-result v0

    .line 869
    if-eqz v0, :cond_1e

    .line 870
    .line 871
    const/4 v0, 0x0

    .line 872
    goto :goto_21

    .line 873
    :cond_1e
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 874
    .line 875
    .line 876
    move-result-wide v2

    .line 877
    long-to-int v0, v2

    .line 878
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 879
    .line 880
    .line 881
    move-result-object v0

    .line 882
    :goto_21
    if-nez v0, :cond_20

    .line 883
    .line 884
    :cond_1f
    const/4 v7, 0x0

    .line 885
    goto :goto_22

    .line 886
    :cond_20
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 887
    .line 888
    .line 889
    move-result v0

    .line 890
    invoke-static {v0}, Ljp/z0;->g(I)Leb/h0;

    .line 891
    .line 892
    .line 893
    move-result-object v7
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 894
    goto :goto_22

    .line 895
    :catchall_6
    move-exception v0

    .line 896
    goto :goto_23

    .line 897
    :goto_22
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 898
    .line 899
    .line 900
    return-object v7

    .line 901
    :goto_23
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 902
    .line 903
    .line 904
    throw v0

    .line 905
    :pswitch_b
    move-object/from16 v0, p1

    .line 906
    .line 907
    check-cast v0, Lua/a;

    .line 908
    .line 909
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 910
    .line 911
    .line 912
    const-string v1, "SELECT * FROM workspec WHERE id=?"

    .line 913
    .line 914
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 915
    .line 916
    .line 917
    move-result-object v1

    .line 918
    const/4 v2, 0x1

    .line 919
    :try_start_7
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 920
    .line 921
    .line 922
    const-string v0, "id"

    .line 923
    .line 924
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 925
    .line 926
    .line 927
    move-result v0

    .line 928
    const-string v2, "state"

    .line 929
    .line 930
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 931
    .line 932
    .line 933
    move-result v2

    .line 934
    const-string v3, "worker_class_name"

    .line 935
    .line 936
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 937
    .line 938
    .line 939
    move-result v3

    .line 940
    const-string v4, "input_merger_class_name"

    .line 941
    .line 942
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 943
    .line 944
    .line 945
    move-result v4

    .line 946
    const-string v5, "input"

    .line 947
    .line 948
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 949
    .line 950
    .line 951
    move-result v5

    .line 952
    const-string v6, "output"

    .line 953
    .line 954
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 955
    .line 956
    .line 957
    move-result v6

    .line 958
    const-string v7, "initial_delay"

    .line 959
    .line 960
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 961
    .line 962
    .line 963
    move-result v7

    .line 964
    const-string v8, "interval_duration"

    .line 965
    .line 966
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 967
    .line 968
    .line 969
    move-result v8

    .line 970
    const-string v9, "flex_duration"

    .line 971
    .line 972
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 973
    .line 974
    .line 975
    move-result v9

    .line 976
    const-string v10, "run_attempt_count"

    .line 977
    .line 978
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 979
    .line 980
    .line 981
    move-result v10

    .line 982
    const-string v11, "backoff_policy"

    .line 983
    .line 984
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 985
    .line 986
    .line 987
    move-result v11

    .line 988
    const-string v12, "backoff_delay_duration"

    .line 989
    .line 990
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 991
    .line 992
    .line 993
    move-result v12

    .line 994
    const-string v13, "last_enqueue_time"

    .line 995
    .line 996
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 997
    .line 998
    .line 999
    move-result v13

    .line 1000
    const-string v14, "minimum_retention_duration"

    .line 1001
    .line 1002
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1003
    .line 1004
    .line 1005
    move-result v14

    .line 1006
    const-string v15, "schedule_requested_at"

    .line 1007
    .line 1008
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1009
    .line 1010
    .line 1011
    move-result v15

    .line 1012
    move/from16 p0, v15

    .line 1013
    .line 1014
    const-string v15, "run_in_foreground"

    .line 1015
    .line 1016
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1017
    .line 1018
    .line 1019
    move-result v15

    .line 1020
    move/from16 p1, v15

    .line 1021
    .line 1022
    const-string v15, "out_of_quota_policy"

    .line 1023
    .line 1024
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1025
    .line 1026
    .line 1027
    move-result v15

    .line 1028
    move/from16 v16, v15

    .line 1029
    .line 1030
    const-string v15, "period_count"

    .line 1031
    .line 1032
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1033
    .line 1034
    .line 1035
    move-result v15

    .line 1036
    move/from16 v17, v15

    .line 1037
    .line 1038
    const-string v15, "generation"

    .line 1039
    .line 1040
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1041
    .line 1042
    .line 1043
    move-result v15

    .line 1044
    move/from16 v18, v15

    .line 1045
    .line 1046
    const-string v15, "next_schedule_time_override"

    .line 1047
    .line 1048
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1049
    .line 1050
    .line 1051
    move-result v15

    .line 1052
    move/from16 v19, v15

    .line 1053
    .line 1054
    const-string v15, "next_schedule_time_override_generation"

    .line 1055
    .line 1056
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1057
    .line 1058
    .line 1059
    move-result v15

    .line 1060
    move/from16 v20, v15

    .line 1061
    .line 1062
    const-string v15, "stop_reason"

    .line 1063
    .line 1064
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1065
    .line 1066
    .line 1067
    move-result v15

    .line 1068
    move/from16 v21, v15

    .line 1069
    .line 1070
    const-string v15, "trace_tag"

    .line 1071
    .line 1072
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1073
    .line 1074
    .line 1075
    move-result v15

    .line 1076
    move/from16 v22, v15

    .line 1077
    .line 1078
    const-string v15, "backoff_on_system_interruptions"

    .line 1079
    .line 1080
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1081
    .line 1082
    .line 1083
    move-result v15

    .line 1084
    move/from16 v23, v15

    .line 1085
    .line 1086
    const-string v15, "required_network_type"

    .line 1087
    .line 1088
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1089
    .line 1090
    .line 1091
    move-result v15

    .line 1092
    move/from16 v24, v15

    .line 1093
    .line 1094
    const-string v15, "required_network_request"

    .line 1095
    .line 1096
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1097
    .line 1098
    .line 1099
    move-result v15

    .line 1100
    move/from16 v25, v15

    .line 1101
    .line 1102
    const-string v15, "requires_charging"

    .line 1103
    .line 1104
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1105
    .line 1106
    .line 1107
    move-result v15

    .line 1108
    move/from16 v26, v15

    .line 1109
    .line 1110
    const-string v15, "requires_device_idle"

    .line 1111
    .line 1112
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1113
    .line 1114
    .line 1115
    move-result v15

    .line 1116
    move/from16 v27, v15

    .line 1117
    .line 1118
    const-string v15, "requires_battery_not_low"

    .line 1119
    .line 1120
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1121
    .line 1122
    .line 1123
    move-result v15

    .line 1124
    move/from16 v28, v15

    .line 1125
    .line 1126
    const-string v15, "requires_storage_not_low"

    .line 1127
    .line 1128
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1129
    .line 1130
    .line 1131
    move-result v15

    .line 1132
    move/from16 v29, v15

    .line 1133
    .line 1134
    const-string v15, "trigger_content_update_delay"

    .line 1135
    .line 1136
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1137
    .line 1138
    .line 1139
    move-result v15

    .line 1140
    move/from16 v30, v15

    .line 1141
    .line 1142
    const-string v15, "trigger_max_content_delay"

    .line 1143
    .line 1144
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1145
    .line 1146
    .line 1147
    move-result v15

    .line 1148
    move/from16 v31, v15

    .line 1149
    .line 1150
    const-string v15, "content_uri_triggers"

    .line 1151
    .line 1152
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1153
    .line 1154
    .line 1155
    move-result v15

    .line 1156
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1157
    .line 1158
    .line 1159
    move-result v32

    .line 1160
    if-eqz v32, :cond_2a

    .line 1161
    .line 1162
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v34

    .line 1166
    move v0, v14

    .line 1167
    move/from16 v32, v15

    .line 1168
    .line 1169
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1170
    .line 1171
    .line 1172
    move-result-wide v14

    .line 1173
    long-to-int v2, v14

    .line 1174
    invoke-static {v2}, Ljp/z0;->g(I)Leb/h0;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v35

    .line 1178
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v36

    .line 1182
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v37

    .line 1186
    invoke-interface {v1, v5}, Lua/c;->getBlob(I)[B

    .line 1187
    .line 1188
    .line 1189
    move-result-object v2

    .line 1190
    sget-object v3, Leb/h;->b:Leb/h;

    .line 1191
    .line 1192
    invoke-static {v2}, Lkp/b6;->b([B)Leb/h;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v38

    .line 1196
    invoke-interface {v1, v6}, Lua/c;->getBlob(I)[B

    .line 1197
    .line 1198
    .line 1199
    move-result-object v2

    .line 1200
    invoke-static {v2}, Lkp/b6;->b([B)Leb/h;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v39

    .line 1204
    invoke-interface {v1, v7}, Lua/c;->getLong(I)J

    .line 1205
    .line 1206
    .line 1207
    move-result-wide v40

    .line 1208
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1209
    .line 1210
    .line 1211
    move-result-wide v42

    .line 1212
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 1213
    .line 1214
    .line 1215
    move-result-wide v44

    .line 1216
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 1217
    .line 1218
    .line 1219
    move-result-wide v2

    .line 1220
    long-to-int v2, v2

    .line 1221
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 1222
    .line 1223
    .line 1224
    move-result-wide v3

    .line 1225
    long-to-int v3, v3

    .line 1226
    invoke-static {v3}, Ljp/z0;->d(I)Leb/a;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v48

    .line 1230
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 1231
    .line 1232
    .line 1233
    move-result-wide v49

    .line 1234
    invoke-interface {v1, v13}, Lua/c;->getLong(I)J

    .line 1235
    .line 1236
    .line 1237
    move-result-wide v51

    .line 1238
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1239
    .line 1240
    .line 1241
    move-result-wide v53

    .line 1242
    move/from16 v0, p0

    .line 1243
    .line 1244
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1245
    .line 1246
    .line 1247
    move-result-wide v55

    .line 1248
    move/from16 v0, p1

    .line 1249
    .line 1250
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1251
    .line 1252
    .line 1253
    move-result-wide v3

    .line 1254
    long-to-int v0, v3

    .line 1255
    if-eqz v0, :cond_21

    .line 1256
    .line 1257
    const/16 v57, 0x1

    .line 1258
    .line 1259
    :goto_24
    move/from16 v0, v16

    .line 1260
    .line 1261
    goto :goto_25

    .line 1262
    :cond_21
    const/16 v57, 0x0

    .line 1263
    .line 1264
    goto :goto_24

    .line 1265
    :goto_25
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1266
    .line 1267
    .line 1268
    move-result-wide v3

    .line 1269
    long-to-int v0, v3

    .line 1270
    invoke-static {v0}, Ljp/z0;->f(I)Leb/e0;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v58

    .line 1274
    move/from16 v0, v17

    .line 1275
    .line 1276
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1277
    .line 1278
    .line 1279
    move-result-wide v3

    .line 1280
    long-to-int v0, v3

    .line 1281
    move/from16 v3, v18

    .line 1282
    .line 1283
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1284
    .line 1285
    .line 1286
    move-result-wide v3

    .line 1287
    long-to-int v3, v3

    .line 1288
    move/from16 v4, v19

    .line 1289
    .line 1290
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 1291
    .line 1292
    .line 1293
    move-result-wide v61

    .line 1294
    move/from16 v4, v20

    .line 1295
    .line 1296
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 1297
    .line 1298
    .line 1299
    move-result-wide v4

    .line 1300
    long-to-int v4, v4

    .line 1301
    move/from16 v5, v21

    .line 1302
    .line 1303
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 1304
    .line 1305
    .line 1306
    move-result-wide v5

    .line 1307
    long-to-int v5, v5

    .line 1308
    move/from16 v6, v22

    .line 1309
    .line 1310
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 1311
    .line 1312
    .line 1313
    move-result v7

    .line 1314
    if-eqz v7, :cond_22

    .line 1315
    .line 1316
    const/16 v65, 0x0

    .line 1317
    .line 1318
    :goto_26
    move/from16 v6, v23

    .line 1319
    .line 1320
    goto :goto_27

    .line 1321
    :cond_22
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1322
    .line 1323
    .line 1324
    move-result-object v6

    .line 1325
    move-object/from16 v65, v6

    .line 1326
    .line 1327
    goto :goto_26

    .line 1328
    :goto_27
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 1329
    .line 1330
    .line 1331
    move-result v7

    .line 1332
    if-eqz v7, :cond_23

    .line 1333
    .line 1334
    const/4 v6, 0x0

    .line 1335
    goto :goto_28

    .line 1336
    :cond_23
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1337
    .line 1338
    .line 1339
    move-result-wide v6

    .line 1340
    long-to-int v6, v6

    .line 1341
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v6

    .line 1345
    :goto_28
    if-eqz v6, :cond_25

    .line 1346
    .line 1347
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 1348
    .line 1349
    .line 1350
    move-result v6

    .line 1351
    if-eqz v6, :cond_24

    .line 1352
    .line 1353
    const/4 v6, 0x1

    .line 1354
    goto :goto_29

    .line 1355
    :cond_24
    const/4 v6, 0x0

    .line 1356
    :goto_29
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1357
    .line 1358
    .line 1359
    move-result-object v7

    .line 1360
    move-object/from16 v66, v7

    .line 1361
    .line 1362
    :goto_2a
    move/from16 v6, v24

    .line 1363
    .line 1364
    goto :goto_2b

    .line 1365
    :catchall_7
    move-exception v0

    .line 1366
    goto/16 :goto_35

    .line 1367
    .line 1368
    :cond_25
    const/16 v66, 0x0

    .line 1369
    .line 1370
    goto :goto_2a

    .line 1371
    :goto_2b
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1372
    .line 1373
    .line 1374
    move-result-wide v6

    .line 1375
    long-to-int v6, v6

    .line 1376
    invoke-static {v6}, Ljp/z0;->e(I)Leb/x;

    .line 1377
    .line 1378
    .line 1379
    move-result-object v69

    .line 1380
    move/from16 v6, v25

    .line 1381
    .line 1382
    invoke-interface {v1, v6}, Lua/c;->getBlob(I)[B

    .line 1383
    .line 1384
    .line 1385
    move-result-object v6

    .line 1386
    invoke-static {v6}, Ljp/z0;->m([B)Lnb/d;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v68

    .line 1390
    move/from16 v6, v26

    .line 1391
    .line 1392
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1393
    .line 1394
    .line 1395
    move-result-wide v6

    .line 1396
    long-to-int v6, v6

    .line 1397
    if-eqz v6, :cond_26

    .line 1398
    .line 1399
    const/16 v70, 0x1

    .line 1400
    .line 1401
    :goto_2c
    move/from16 v6, v27

    .line 1402
    .line 1403
    goto :goto_2d

    .line 1404
    :cond_26
    const/16 v70, 0x0

    .line 1405
    .line 1406
    goto :goto_2c

    .line 1407
    :goto_2d
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1408
    .line 1409
    .line 1410
    move-result-wide v6

    .line 1411
    long-to-int v6, v6

    .line 1412
    if-eqz v6, :cond_27

    .line 1413
    .line 1414
    const/16 v71, 0x1

    .line 1415
    .line 1416
    :goto_2e
    move/from16 v6, v28

    .line 1417
    .line 1418
    goto :goto_2f

    .line 1419
    :cond_27
    const/16 v71, 0x0

    .line 1420
    .line 1421
    goto :goto_2e

    .line 1422
    :goto_2f
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1423
    .line 1424
    .line 1425
    move-result-wide v6

    .line 1426
    long-to-int v6, v6

    .line 1427
    if-eqz v6, :cond_28

    .line 1428
    .line 1429
    const/16 v72, 0x1

    .line 1430
    .line 1431
    :goto_30
    move/from16 v6, v29

    .line 1432
    .line 1433
    goto :goto_31

    .line 1434
    :cond_28
    const/16 v72, 0x0

    .line 1435
    .line 1436
    goto :goto_30

    .line 1437
    :goto_31
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1438
    .line 1439
    .line 1440
    move-result-wide v6

    .line 1441
    long-to-int v6, v6

    .line 1442
    if-eqz v6, :cond_29

    .line 1443
    .line 1444
    const/16 v73, 0x1

    .line 1445
    .line 1446
    :goto_32
    move/from16 v6, v30

    .line 1447
    .line 1448
    goto :goto_33

    .line 1449
    :cond_29
    const/16 v73, 0x0

    .line 1450
    .line 1451
    goto :goto_32

    .line 1452
    :goto_33
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1453
    .line 1454
    .line 1455
    move-result-wide v74

    .line 1456
    move/from16 v6, v31

    .line 1457
    .line 1458
    invoke-interface {v1, v6}, Lua/c;->getLong(I)J

    .line 1459
    .line 1460
    .line 1461
    move-result-wide v76

    .line 1462
    move/from16 v6, v32

    .line 1463
    .line 1464
    invoke-interface {v1, v6}, Lua/c;->getBlob(I)[B

    .line 1465
    .line 1466
    .line 1467
    move-result-object v6

    .line 1468
    invoke-static {v6}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 1469
    .line 1470
    .line 1471
    move-result-object v78

    .line 1472
    new-instance v46, Leb/e;

    .line 1473
    .line 1474
    move-object/from16 v67, v46

    .line 1475
    .line 1476
    invoke-direct/range {v67 .. v78}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 1477
    .line 1478
    .line 1479
    move-object/from16 v46, v67

    .line 1480
    .line 1481
    new-instance v33, Lmb/o;

    .line 1482
    .line 1483
    move/from16 v59, v0

    .line 1484
    .line 1485
    move/from16 v47, v2

    .line 1486
    .line 1487
    move/from16 v60, v3

    .line 1488
    .line 1489
    move/from16 v63, v4

    .line 1490
    .line 1491
    move/from16 v64, v5

    .line 1492
    .line 1493
    invoke-direct/range {v33 .. v66}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 1494
    .line 1495
    .line 1496
    move-object/from16 v7, v33

    .line 1497
    .line 1498
    goto :goto_34

    .line 1499
    :cond_2a
    const/4 v7, 0x0

    .line 1500
    :goto_34
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1501
    .line 1502
    .line 1503
    return-object v7

    .line 1504
    :goto_35
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1505
    .line 1506
    .line 1507
    throw v0

    .line 1508
    :pswitch_c
    move-object/from16 v0, p1

    .line 1509
    .line 1510
    check-cast v0, Lua/a;

    .line 1511
    .line 1512
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1513
    .line 1514
    .line 1515
    const-string v1, "DELETE from WorkProgress where work_spec_id=?"

    .line 1516
    .line 1517
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v1

    .line 1521
    const/4 v2, 0x1

    .line 1522
    :try_start_8
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1523
    .line 1524
    .line 1525
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_8

    .line 1526
    .line 1527
    .line 1528
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1529
    .line 1530
    .line 1531
    return-object v6

    .line 1532
    :catchall_8
    move-exception v0

    .line 1533
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1534
    .line 1535
    .line 1536
    throw v0

    .line 1537
    :pswitch_d
    move-object/from16 v0, p1

    .line 1538
    .line 1539
    check-cast v0, Lua/a;

    .line 1540
    .line 1541
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1542
    .line 1543
    .line 1544
    const-string v1, "SELECT name FROM workname WHERE work_spec_id=?"

    .line 1545
    .line 1546
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1547
    .line 1548
    .line 1549
    move-result-object v1

    .line 1550
    const/4 v2, 0x1

    .line 1551
    :try_start_9
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1552
    .line 1553
    .line 1554
    new-instance v0, Ljava/util/ArrayList;

    .line 1555
    .line 1556
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1557
    .line 1558
    .line 1559
    :goto_36
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1560
    .line 1561
    .line 1562
    move-result v2

    .line 1563
    if-eqz v2, :cond_2b

    .line 1564
    .line 1565
    const/4 v2, 0x0

    .line 1566
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1567
    .line 1568
    .line 1569
    move-result-object v3

    .line 1570
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_9

    .line 1571
    .line 1572
    .line 1573
    goto :goto_36

    .line 1574
    :catchall_9
    move-exception v0

    .line 1575
    goto :goto_37

    .line 1576
    :cond_2b
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1577
    .line 1578
    .line 1579
    return-object v0

    .line 1580
    :goto_37
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1581
    .line 1582
    .line 1583
    throw v0

    .line 1584
    :pswitch_e
    move-object/from16 v0, p1

    .line 1585
    .line 1586
    check-cast v0, Lua/a;

    .line 1587
    .line 1588
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1589
    .line 1590
    .line 1591
    const-string v1, "DELETE FROM SystemIdInfo where work_spec_id=?"

    .line 1592
    .line 1593
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1594
    .line 1595
    .line 1596
    move-result-object v1

    .line 1597
    const/4 v2, 0x1

    .line 1598
    :try_start_a
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1599
    .line 1600
    .line 1601
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_a

    .line 1602
    .line 1603
    .line 1604
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1605
    .line 1606
    .line 1607
    return-object v6

    .line 1608
    :catchall_a
    move-exception v0

    .line 1609
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1610
    .line 1611
    .line 1612
    throw v0

    .line 1613
    :pswitch_f
    move-object/from16 v0, p1

    .line 1614
    .line 1615
    check-cast v0, Lua/a;

    .line 1616
    .line 1617
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1618
    .line 1619
    .line 1620
    const-string v1, "SELECT long_value FROM Preference where `key`=?"

    .line 1621
    .line 1622
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1623
    .line 1624
    .line 1625
    move-result-object v1

    .line 1626
    const/4 v2, 0x1

    .line 1627
    :try_start_b
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1628
    .line 1629
    .line 1630
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1631
    .line 1632
    .line 1633
    move-result v0

    .line 1634
    if-eqz v0, :cond_2c

    .line 1635
    .line 1636
    const/4 v2, 0x0

    .line 1637
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 1638
    .line 1639
    .line 1640
    move-result v0

    .line 1641
    if-eqz v0, :cond_2d

    .line 1642
    .line 1643
    :cond_2c
    const/4 v7, 0x0

    .line 1644
    goto :goto_38

    .line 1645
    :cond_2d
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1646
    .line 1647
    .line 1648
    move-result-wide v2

    .line 1649
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v7
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_b

    .line 1653
    goto :goto_38

    .line 1654
    :catchall_b
    move-exception v0

    .line 1655
    goto :goto_39

    .line 1656
    :goto_38
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1657
    .line 1658
    .line 1659
    return-object v7

    .line 1660
    :goto_39
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1661
    .line 1662
    .line 1663
    throw v0

    .line 1664
    :pswitch_10
    move-object/from16 v0, p1

    .line 1665
    .line 1666
    check-cast v0, Lua/a;

    .line 1667
    .line 1668
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1669
    .line 1670
    .line 1671
    const-string v1, "SELECT COUNT(*)=0 FROM dependency WHERE work_spec_id=? AND prerequisite_id IN (SELECT id FROM workspec WHERE state!=2)"

    .line 1672
    .line 1673
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1674
    .line 1675
    .line 1676
    move-result-object v1

    .line 1677
    const/4 v2, 0x1

    .line 1678
    :try_start_c
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1679
    .line 1680
    .line 1681
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1682
    .line 1683
    .line 1684
    move-result v0

    .line 1685
    if-eqz v0, :cond_2e

    .line 1686
    .line 1687
    const/4 v2, 0x0

    .line 1688
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1689
    .line 1690
    .line 1691
    move-result-wide v3
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_c

    .line 1692
    long-to-int v0, v3

    .line 1693
    if-eqz v0, :cond_2e

    .line 1694
    .line 1695
    const/4 v8, 0x1

    .line 1696
    goto :goto_3a

    .line 1697
    :catchall_c
    move-exception v0

    .line 1698
    goto :goto_3b

    .line 1699
    :cond_2e
    const/4 v8, 0x0

    .line 1700
    :goto_3a
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1701
    .line 1702
    .line 1703
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1704
    .line 1705
    .line 1706
    move-result-object v0

    .line 1707
    return-object v0

    .line 1708
    :goto_3b
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1709
    .line 1710
    .line 1711
    throw v0

    .line 1712
    :pswitch_11
    move-object/from16 v0, p1

    .line 1713
    .line 1714
    check-cast v0, Lua/a;

    .line 1715
    .line 1716
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1717
    .line 1718
    .line 1719
    const-string v1, "SELECT work_spec_id FROM dependency WHERE prerequisite_id=?"

    .line 1720
    .line 1721
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1722
    .line 1723
    .line 1724
    move-result-object v1

    .line 1725
    const/4 v2, 0x1

    .line 1726
    :try_start_d
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1727
    .line 1728
    .line 1729
    new-instance v0, Ljava/util/ArrayList;

    .line 1730
    .line 1731
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1732
    .line 1733
    .line 1734
    :goto_3c
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1735
    .line 1736
    .line 1737
    move-result v2

    .line 1738
    if-eqz v2, :cond_2f

    .line 1739
    .line 1740
    const/4 v2, 0x0

    .line 1741
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1742
    .line 1743
    .line 1744
    move-result-object v3

    .line 1745
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_d

    .line 1746
    .line 1747
    .line 1748
    goto :goto_3c

    .line 1749
    :catchall_d
    move-exception v0

    .line 1750
    goto :goto_3d

    .line 1751
    :cond_2f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1752
    .line 1753
    .line 1754
    return-object v0

    .line 1755
    :goto_3d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1756
    .line 1757
    .line 1758
    throw v0

    .line 1759
    :pswitch_12
    move-object/from16 v0, p1

    .line 1760
    .line 1761
    check-cast v0, Lua/a;

    .line 1762
    .line 1763
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1764
    .line 1765
    .line 1766
    const-string v1, "SELECT COUNT(*)>0 FROM dependency WHERE prerequisite_id=?"

    .line 1767
    .line 1768
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1769
    .line 1770
    .line 1771
    move-result-object v1

    .line 1772
    const/4 v2, 0x1

    .line 1773
    :try_start_e
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1774
    .line 1775
    .line 1776
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1777
    .line 1778
    .line 1779
    move-result v0

    .line 1780
    if-eqz v0, :cond_30

    .line 1781
    .line 1782
    const/4 v2, 0x0

    .line 1783
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1784
    .line 1785
    .line 1786
    move-result-wide v3
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_e

    .line 1787
    long-to-int v0, v3

    .line 1788
    if-eqz v0, :cond_31

    .line 1789
    .line 1790
    const/4 v8, 0x1

    .line 1791
    goto :goto_3e

    .line 1792
    :catchall_e
    move-exception v0

    .line 1793
    goto :goto_3f

    .line 1794
    :cond_30
    const/4 v2, 0x0

    .line 1795
    :cond_31
    move v8, v2

    .line 1796
    :goto_3e
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1797
    .line 1798
    .line 1799
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1800
    .line 1801
    .line 1802
    move-result-object v0

    .line 1803
    return-object v0

    .line 1804
    :goto_3f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1805
    .line 1806
    .line 1807
    throw v0

    .line 1808
    :pswitch_13
    const/4 v2, 0x0

    .line 1809
    move-object/from16 v0, p1

    .line 1810
    .line 1811
    check-cast v0, Lua/a;

    .line 1812
    .line 1813
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1814
    .line 1815
    .line 1816
    invoke-interface {v0, v4}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1817
    .line 1818
    .line 1819
    move-result-object v1

    .line 1820
    const/4 v0, 0x1

    .line 1821
    :try_start_f
    invoke-interface {v1, v0, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1822
    .line 1823
    .line 1824
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1825
    .line 1826
    .line 1827
    move-result v0

    .line 1828
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1829
    .line 1830
    .line 1831
    move-result v3

    .line 1832
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1833
    .line 1834
    .line 1835
    move-result v4

    .line 1836
    if-eqz v4, :cond_33

    .line 1837
    .line 1838
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1839
    .line 1840
    .line 1841
    move-result-object v0

    .line 1842
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1843
    .line 1844
    .line 1845
    move-result-wide v3

    .line 1846
    long-to-int v3, v3

    .line 1847
    if-eqz v3, :cond_32

    .line 1848
    .line 1849
    const/4 v8, 0x1

    .line 1850
    goto :goto_40

    .line 1851
    :cond_32
    move v8, v2

    .line 1852
    :goto_40
    new-instance v7, Lm20/b;

    .line 1853
    .line 1854
    invoke-direct {v7, v0, v8}, Lm20/b;-><init>(Ljava/lang/String;Z)V
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_f

    .line 1855
    .line 1856
    .line 1857
    goto :goto_41

    .line 1858
    :catchall_f
    move-exception v0

    .line 1859
    goto :goto_42

    .line 1860
    :cond_33
    const/4 v7, 0x0

    .line 1861
    :goto_41
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1862
    .line 1863
    .line 1864
    return-object v7

    .line 1865
    :goto_42
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1866
    .line 1867
    .line 1868
    throw v0

    .line 1869
    :pswitch_14
    const/4 v2, 0x0

    .line 1870
    move-object/from16 v0, p1

    .line 1871
    .line 1872
    check-cast v0, Lua/a;

    .line 1873
    .line 1874
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1875
    .line 1876
    .line 1877
    invoke-interface {v0, v4}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1878
    .line 1879
    .line 1880
    move-result-object v1

    .line 1881
    const/4 v0, 0x1

    .line 1882
    :try_start_10
    invoke-interface {v1, v0, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 1883
    .line 1884
    .line 1885
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1886
    .line 1887
    .line 1888
    move-result v0

    .line 1889
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1890
    .line 1891
    .line 1892
    move-result v3

    .line 1893
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1894
    .line 1895
    .line 1896
    move-result v4

    .line 1897
    if-eqz v4, :cond_35

    .line 1898
    .line 1899
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1900
    .line 1901
    .line 1902
    move-result-object v0

    .line 1903
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1904
    .line 1905
    .line 1906
    move-result-wide v3

    .line 1907
    long-to-int v3, v3

    .line 1908
    if-eqz v3, :cond_34

    .line 1909
    .line 1910
    const/4 v8, 0x1

    .line 1911
    goto :goto_43

    .line 1912
    :cond_34
    move v8, v2

    .line 1913
    :goto_43
    new-instance v7, Lm20/b;

    .line 1914
    .line 1915
    invoke-direct {v7, v0, v8}, Lm20/b;-><init>(Ljava/lang/String;Z)V
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_10

    .line 1916
    .line 1917
    .line 1918
    goto :goto_44

    .line 1919
    :catchall_10
    move-exception v0

    .line 1920
    goto :goto_45

    .line 1921
    :cond_35
    const/4 v7, 0x0

    .line 1922
    :goto_44
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1923
    .line 1924
    .line 1925
    return-object v7

    .line 1926
    :goto_45
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1927
    .line 1928
    .line 1929
    throw v0

    .line 1930
    :pswitch_15
    move-object/from16 v0, p1

    .line 1931
    .line 1932
    check-cast v0, Ljava/lang/String;

    .line 1933
    .line 1934
    const-string v1, "it"

    .line 1935
    .line 1936
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1937
    .line 1938
    .line 1939
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 1940
    .line 1941
    .line 1942
    move-result v1

    .line 1943
    if-eqz v1, :cond_37

    .line 1944
    .line 1945
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 1946
    .line 1947
    .line 1948
    move-result v1

    .line 1949
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 1950
    .line 1951
    .line 1952
    move-result v2

    .line 1953
    if-ge v1, v2, :cond_36

    .line 1954
    .line 1955
    goto :goto_46

    .line 1956
    :cond_36
    move-object v11, v0

    .line 1957
    goto :goto_46

    .line 1958
    :cond_37
    invoke-static {v11, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1959
    .line 1960
    .line 1961
    move-result-object v11

    .line 1962
    :goto_46
    return-object v11

    .line 1963
    :pswitch_16
    move-object/from16 v0, p1

    .line 1964
    .line 1965
    check-cast v0, Lhi/a;

    .line 1966
    .line 1967
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1968
    .line 1969
    .line 1970
    const-class v1, Ldh/u;

    .line 1971
    .line 1972
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1973
    .line 1974
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1975
    .line 1976
    .line 1977
    move-result-object v1

    .line 1978
    check-cast v0, Lii/a;

    .line 1979
    .line 1980
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1981
    .line 1982
    .line 1983
    move-result-object v0

    .line 1984
    check-cast v0, Ldh/u;

    .line 1985
    .line 1986
    new-instance v1, Lkh/k;

    .line 1987
    .line 1988
    new-instance v2, Lai/e;

    .line 1989
    .line 1990
    const/16 v3, 0xa

    .line 1991
    .line 1992
    const/4 v4, 0x0

    .line 1993
    invoke-direct {v2, v0, v11, v4, v3}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1994
    .line 1995
    .line 1996
    new-instance v3, Ljh/b;

    .line 1997
    .line 1998
    const/4 v5, 0x2

    .line 1999
    invoke-direct {v3, v0, v11, v4, v5}, Ljh/b;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 2000
    .line 2001
    .line 2002
    invoke-direct {v1, v2, v3}, Lkh/k;-><init>(Lai/e;Ljh/b;)V

    .line 2003
    .line 2004
    .line 2005
    return-object v1

    .line 2006
    :pswitch_17
    move-object/from16 v0, p1

    .line 2007
    .line 2008
    check-cast v0, Lua/a;

    .line 2009
    .line 2010
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2011
    .line 2012
    .line 2013
    const-string v1, "DELETE from recent_places WHERE id = ?"

    .line 2014
    .line 2015
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2016
    .line 2017
    .line 2018
    move-result-object v1

    .line 2019
    const/4 v2, 0x1

    .line 2020
    :try_start_11
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 2021
    .line 2022
    .line 2023
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_11

    .line 2024
    .line 2025
    .line 2026
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2027
    .line 2028
    .line 2029
    return-object v6

    .line 2030
    :catchall_11
    move-exception v0

    .line 2031
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2032
    .line 2033
    .line 2034
    throw v0

    .line 2035
    :pswitch_18
    move-object/from16 v1, p1

    .line 2036
    .line 2037
    check-cast v1, Lhi/a;

    .line 2038
    .line 2039
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2040
    .line 2041
    .line 2042
    const-class v2, Lsi/f;

    .line 2043
    .line 2044
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2045
    .line 2046
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2047
    .line 2048
    .line 2049
    move-result-object v2

    .line 2050
    check-cast v1, Lii/a;

    .line 2051
    .line 2052
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 2053
    .line 2054
    .line 2055
    move-result-object v1

    .line 2056
    check-cast v1, Lsi/f;

    .line 2057
    .line 2058
    new-instance v2, Lig/i;

    .line 2059
    .line 2060
    new-instance v4, Lbq0/i;

    .line 2061
    .line 2062
    const/16 v3, 0x13

    .line 2063
    .line 2064
    const/4 v8, 0x0

    .line 2065
    invoke-direct {v4, v1, v8, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 2066
    .line 2067
    .line 2068
    new-instance v5, Lif0/d0;

    .line 2069
    .line 2070
    iget-object v3, v0, Lif0/d;->e:Ljava/lang/String;

    .line 2071
    .line 2072
    const/4 v0, 0x1

    .line 2073
    invoke-direct {v5, v0, v1, v3, v8}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 2074
    .line 2075
    .line 2076
    new-instance v6, Lhz/a;

    .line 2077
    .line 2078
    const/16 v1, 0x19

    .line 2079
    .line 2080
    invoke-direct {v6, v1}, Lhz/a;-><init>(I)V

    .line 2081
    .line 2082
    .line 2083
    new-instance v7, Lhz/a;

    .line 2084
    .line 2085
    const/16 v1, 0x1a

    .line 2086
    .line 2087
    invoke-direct {v7, v1}, Lhz/a;-><init>(I)V

    .line 2088
    .line 2089
    .line 2090
    invoke-direct/range {v2 .. v7}, Lig/i;-><init>(Ljava/lang/String;Lbq0/i;Lif0/d0;Lhz/a;Lhz/a;)V

    .line 2091
    .line 2092
    .line 2093
    invoke-static {v2}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2094
    .line 2095
    .line 2096
    move-result-object v1

    .line 2097
    new-instance v3, Lig/g;

    .line 2098
    .line 2099
    invoke-direct {v3, v2, v8, v0}, Lig/g;-><init>(Lig/i;Lkotlin/coroutines/Continuation;I)V

    .line 2100
    .line 2101
    .line 2102
    const/4 v0, 0x3

    .line 2103
    invoke-static {v1, v8, v8, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 2104
    .line 2105
    .line 2106
    return-object v2

    .line 2107
    :pswitch_19
    const/4 v8, 0x0

    .line 2108
    move-object/from16 v0, p1

    .line 2109
    .line 2110
    check-cast v0, Lne0/c;

    .line 2111
    .line 2112
    const-string v1, "$this$mapError"

    .line 2113
    .line 2114
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2115
    .line 2116
    .line 2117
    iget-object v1, v0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 2118
    .line 2119
    instance-of v2, v1, Lbm0/d;

    .line 2120
    .line 2121
    if-eqz v2, :cond_38

    .line 2122
    .line 2123
    move-object v4, v1

    .line 2124
    check-cast v4, Lbm0/d;

    .line 2125
    .line 2126
    goto :goto_47

    .line 2127
    :cond_38
    move-object v4, v8

    .line 2128
    :goto_47
    if-eqz v4, :cond_39

    .line 2129
    .line 2130
    iget v1, v4, Lbm0/d;->d:I

    .line 2131
    .line 2132
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2133
    .line 2134
    .line 2135
    move-result-object v7

    .line 2136
    goto :goto_48

    .line 2137
    :cond_39
    move-object v7, v8

    .line 2138
    :goto_48
    if-nez v7, :cond_3b

    .line 2139
    .line 2140
    :cond_3a
    move-object v11, v0

    .line 2141
    goto :goto_4a

    .line 2142
    :cond_3b
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 2143
    .line 2144
    .line 2145
    move-result v1

    .line 2146
    const/16 v3, 0x194

    .line 2147
    .line 2148
    if-ne v1, v3, :cond_3a

    .line 2149
    .line 2150
    new-instance v9, Lne0/c;

    .line 2151
    .line 2152
    new-instance v10, Lss0/y;

    .line 2153
    .line 2154
    invoke-direct {v10, v11}, Lss0/y;-><init>(Ljava/lang/String;)V

    .line 2155
    .line 2156
    .line 2157
    const/4 v13, 0x0

    .line 2158
    const/16 v14, 0x1c

    .line 2159
    .line 2160
    const/4 v12, 0x0

    .line 2161
    move-object v11, v0

    .line 2162
    invoke-direct/range {v9 .. v14}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 2163
    .line 2164
    .line 2165
    :goto_49
    move-object v0, v9

    .line 2166
    goto :goto_4b

    .line 2167
    :goto_4a
    if-eqz v2, :cond_3c

    .line 2168
    .line 2169
    new-instance v9, Lne0/c;

    .line 2170
    .line 2171
    new-instance v10, Lss0/c0;

    .line 2172
    .line 2173
    invoke-direct {v10}, Lss0/c0;-><init>()V

    .line 2174
    .line 2175
    .line 2176
    const/4 v13, 0x0

    .line 2177
    const/16 v14, 0x1c

    .line 2178
    .line 2179
    const/4 v12, 0x0

    .line 2180
    invoke-direct/range {v9 .. v14}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 2181
    .line 2182
    .line 2183
    goto :goto_49

    .line 2184
    :cond_3c
    move-object v0, v11

    .line 2185
    :goto_4b
    return-object v0

    .line 2186
    :pswitch_1a
    move-object/from16 v0, p1

    .line 2187
    .line 2188
    check-cast v0, Lua/a;

    .line 2189
    .line 2190
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2191
    .line 2192
    .line 2193
    const-string v1, "DELETE FROM vehicle where ? is vin"

    .line 2194
    .line 2195
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2196
    .line 2197
    .line 2198
    move-result-object v1

    .line 2199
    const/4 v2, 0x1

    .line 2200
    :try_start_12
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 2201
    .line 2202
    .line 2203
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_12

    .line 2204
    .line 2205
    .line 2206
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2207
    .line 2208
    .line 2209
    return-object v6

    .line 2210
    :catchall_12
    move-exception v0

    .line 2211
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2212
    .line 2213
    .line 2214
    throw v0

    .line 2215
    :pswitch_1b
    move-object/from16 v0, p1

    .line 2216
    .line 2217
    check-cast v0, Lua/a;

    .line 2218
    .line 2219
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2220
    .line 2221
    .line 2222
    const-string v1, "DELETE FROM capability_error WHERE vin = ?"

    .line 2223
    .line 2224
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2225
    .line 2226
    .line 2227
    move-result-object v1

    .line 2228
    const/4 v2, 0x1

    .line 2229
    :try_start_13
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 2230
    .line 2231
    .line 2232
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_13

    .line 2233
    .line 2234
    .line 2235
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2236
    .line 2237
    .line 2238
    return-object v6

    .line 2239
    :catchall_13
    move-exception v0

    .line 2240
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2241
    .line 2242
    .line 2243
    throw v0

    .line 2244
    :pswitch_1c
    move-object/from16 v0, p1

    .line 2245
    .line 2246
    check-cast v0, Lua/a;

    .line 2247
    .line 2248
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2249
    .line 2250
    .line 2251
    const-string v1, "DELETE FROM capability WHERE vin = ?"

    .line 2252
    .line 2253
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2254
    .line 2255
    .line 2256
    move-result-object v1

    .line 2257
    const/4 v2, 0x1

    .line 2258
    :try_start_14
    invoke-interface {v1, v2, v11}, Lua/c;->w(ILjava/lang/String;)V

    .line 2259
    .line 2260
    .line 2261
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_14

    .line 2262
    .line 2263
    .line 2264
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2265
    .line 2266
    .line 2267
    return-object v6

    .line 2268
    :catchall_14
    move-exception v0

    .line 2269
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2270
    .line 2271
    .line 2272
    throw v0

    .line 2273
    :pswitch_data_0
    .packed-switch 0x0
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
