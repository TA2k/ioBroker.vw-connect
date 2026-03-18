.class public abstract Lwo/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljo/d;

.field public static final b:Ljo/d;

.field public static final c:Ljo/d;

.field public static final d:Ljo/d;

.field public static final e:[Ljo/d;


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    new-instance v1, Ljo/d;

    .line 2
    .line 3
    const-wide/16 v2, 0x1

    .line 4
    .line 5
    const-string v0, "dck_management"

    .line 6
    .line 7
    invoke-direct {v1, v2, v3, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sput-object v1, Lwo/g;->a:Ljo/d;

    .line 11
    .line 12
    new-instance v0, Ljo/d;

    .line 13
    .line 14
    const-string v4, "dck_apis"

    .line 15
    .line 16
    invoke-direct {v0, v2, v3, v4}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lwo/g;->b:Ljo/d;

    .line 20
    .line 21
    new-instance v4, Ljo/d;

    .line 22
    .line 23
    const-wide/16 v5, 0x5

    .line 24
    .line 25
    const-string v7, "dck_rke_apis"

    .line 26
    .line 27
    invoke-direct {v4, v5, v6, v7}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    sput-object v4, Lwo/g;->c:Ljo/d;

    .line 31
    .line 32
    move-object v7, v4

    .line 33
    new-instance v4, Ljo/d;

    .line 34
    .line 35
    const-string v8, "dck_suspend_all_keys_with_callback_api"

    .line 36
    .line 37
    invoke-direct {v4, v2, v3, v8}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 38
    .line 39
    .line 40
    new-instance v8, Ljo/d;

    .line 41
    .line 42
    const-string v9, "dck_key_sharing_api"

    .line 43
    .line 44
    const-wide/16 v10, 0x9

    .line 45
    .line 46
    invoke-direct {v8, v10, v11, v9}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    new-instance v9, Ljo/d;

    .line 50
    .line 51
    const-string v10, "dck_get_digital_key_card_art_api"

    .line 52
    .line 53
    invoke-direct {v9, v2, v3, v10}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 54
    .line 55
    .line 56
    move-object v10, v7

    .line 57
    new-instance v7, Ljo/d;

    .line 58
    .line 59
    const-string v11, "dck_r3_apis"

    .line 60
    .line 61
    invoke-direct {v7, v5, v6, v11}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    sput-object v7, Lwo/g;->d:Ljo/d;

    .line 65
    .line 66
    move-object v5, v8

    .line 67
    new-instance v8, Ljo/d;

    .line 68
    .line 69
    const-wide/16 v11, 0x2

    .line 70
    .line 71
    const-string v6, "dck_wear_os_support"

    .line 72
    .line 73
    invoke-direct {v8, v11, v12, v6}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 74
    .line 75
    .line 76
    move-object v6, v9

    .line 77
    new-instance v9, Ljo/d;

    .line 78
    .line 79
    const-string v13, "dck_is_vehicle_oem_supported_api"

    .line 80
    .line 81
    invoke-direct {v9, v2, v3, v13}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 82
    .line 83
    .line 84
    move-object v13, v10

    .line 85
    new-instance v10, Ljo/d;

    .line 86
    .line 87
    const-string v14, "dck_get_all_digital_car_keys_from_native_app_api"

    .line 88
    .line 89
    invoke-direct {v10, v2, v3, v14}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    new-instance v14, Ljo/d;

    .line 93
    .line 94
    const-string v15, "dck_prepare_for_owner_pairing_api"

    .line 95
    .line 96
    invoke-direct {v14, v2, v3, v15}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v15, Ljo/d;

    .line 100
    .line 101
    const-string v11, "dck_is_key_provisioned_api"

    .line 102
    .line 103
    invoke-direct {v15, v2, v3, v11}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    move-object v11, v13

    .line 107
    new-instance v13, Ljo/d;

    .line 108
    .line 109
    const-string v12, "dck_feature_opt_in_api"

    .line 110
    .line 111
    const-wide/16 v2, 0x2

    .line 112
    .line 113
    invoke-direct {v13, v2, v3, v12}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    move-object v3, v11

    .line 117
    move-object v11, v14

    .line 118
    new-instance v14, Ljo/d;

    .line 119
    .line 120
    const-string v2, "dck_per_key_setting_api"

    .line 121
    .line 122
    move-object/from16 v16, v0

    .line 123
    .line 124
    move-object v12, v1

    .line 125
    const-wide/16 v0, 0x1

    .line 126
    .line 127
    invoke-direct {v14, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 128
    .line 129
    .line 130
    move-object v2, v12

    .line 131
    move-object v12, v15

    .line 132
    new-instance v15, Ljo/d;

    .line 133
    .line 134
    move-object/from16 v17, v2

    .line 135
    .line 136
    const-string v2, "dck_r4_sharing_apis"

    .line 137
    .line 138
    invoke-direct {v15, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance v2, Ljo/d;

    .line 142
    .line 143
    move-object/from16 v18, v3

    .line 144
    .line 145
    const-string v3, "dck_get_system_property_api"

    .line 146
    .line 147
    invoke-direct {v2, v0, v1, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 148
    .line 149
    .line 150
    new-instance v3, Ljo/d;

    .line 151
    .line 152
    move-object/from16 v19, v2

    .line 153
    .line 154
    const-string v2, "dck_set_wearable_default_key_api"

    .line 155
    .line 156
    invoke-direct {v3, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 157
    .line 158
    .line 159
    new-instance v2, Ljo/d;

    .line 160
    .line 161
    move-object/from16 v20, v3

    .line 162
    .line 163
    const-string v3, "dck_elevate_ble_connection_priority"

    .line 164
    .line 165
    invoke-direct {v2, v0, v1, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 166
    .line 167
    .line 168
    move-object/from16 v1, v17

    .line 169
    .line 170
    move-object/from16 v3, v18

    .line 171
    .line 172
    move-object/from16 v17, v20

    .line 173
    .line 174
    move-object/from16 v18, v2

    .line 175
    .line 176
    move-object/from16 v2, v16

    .line 177
    .line 178
    move-object/from16 v16, v19

    .line 179
    .line 180
    filled-new-array/range {v1 .. v18}, [Ljo/d;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    sput-object v0, Lwo/g;->e:[Ljo/d;

    .line 185
    .line 186
    return-void
.end method
