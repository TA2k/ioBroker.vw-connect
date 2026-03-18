.class public final synthetic Lc91/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lc91/q;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc91/q;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/q;->a:Lc91/q;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.telemetry.serialization.LogRecordDataSerializer.InternalSerializableLogRecordData"

    .line 11
    .line 12
    const/16 v3, 0xe

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "spanContext"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "severity"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "severityText"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "body"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "attributes"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "totalAttributeCount"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "instrumentationScopeInfoName"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "instrumentationScopeInfoVersion"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    const-string v0, "instrumentationScopeInfoSchemaUrl"

    .line 59
    .line 60
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 61
    .line 62
    .line 63
    const-string v0, "instrumentationScopeInfoAttributes"

    .line 64
    .line 65
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 66
    .line 67
    .line 68
    const-string v0, "timestampEpochNanos"

    .line 69
    .line 70
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 71
    .line 72
    .line 73
    const-string v0, "observedTimestampEpochNanos"

    .line 74
    .line 75
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 76
    .line 77
    .line 78
    const-string v0, "resourceAttributes"

    .line 79
    .line 80
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 81
    .line 82
    .line 83
    const-string v0, "resourceSchemaUrl"

    .line 84
    .line 85
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 86
    .line 87
    .line 88
    sput-object v1, Lc91/q;->descriptor:Lsz0/g;

    .line 89
    .line 90
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lc91/s;->o:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0xe

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aget-object v2, p0, v1

    .line 9
    .line 10
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    aput-object v2, v0, v1

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    aget-object v2, p0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    aput-object v2, v0, v1

    .line 30
    .line 31
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 32
    .line 33
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    const/4 v3, 0x2

    .line 38
    aput-object v2, v0, v3

    .line 39
    .line 40
    const/4 v2, 0x3

    .line 41
    aget-object v3, p0, v2

    .line 42
    .line 43
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    aput-object v3, v0, v2

    .line 48
    .line 49
    const/4 v2, 0x4

    .line 50
    aget-object v3, p0, v2

    .line 51
    .line 52
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    aput-object v3, v0, v2

    .line 57
    .line 58
    const/4 v2, 0x5

    .line 59
    sget-object v3, Luz0/k0;->a:Luz0/k0;

    .line 60
    .line 61
    aput-object v3, v0, v2

    .line 62
    .line 63
    const/4 v2, 0x6

    .line 64
    aput-object v1, v0, v2

    .line 65
    .line 66
    const/4 v2, 0x7

    .line 67
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    aput-object v3, v0, v2

    .line 72
    .line 73
    const/16 v2, 0x8

    .line 74
    .line 75
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    aput-object v3, v0, v2

    .line 80
    .line 81
    const/16 v2, 0x9

    .line 82
    .line 83
    aget-object v3, p0, v2

    .line 84
    .line 85
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    aput-object v3, v0, v2

    .line 90
    .line 91
    sget-object v2, Luz0/q0;->a:Luz0/q0;

    .line 92
    .line 93
    const/16 v3, 0xa

    .line 94
    .line 95
    aput-object v2, v0, v3

    .line 96
    .line 97
    const/16 v3, 0xb

    .line 98
    .line 99
    aput-object v2, v0, v3

    .line 100
    .line 101
    const/16 v2, 0xc

    .line 102
    .line 103
    aget-object p0, p0, v2

    .line 104
    .line 105
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    aput-object p0, v0, v2

    .line 110
    .line 111
    const/16 p0, 0xd

    .line 112
    .line 113
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    aput-object v1, v0, p0

    .line 118
    .line 119
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 26

    .line 1
    sget-object v0, Lc91/q;->descriptor:Lsz0/g;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lc91/s;->o:[Llx0/i;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    const-wide/16 v6, 0x0

    .line 13
    .line 14
    move-object v8, v5

    .line 15
    move-object v9, v8

    .line 16
    move-object v10, v9

    .line 17
    move-object v11, v10

    .line 18
    move-object v12, v11

    .line 19
    move-object v13, v12

    .line 20
    move-object v14, v13

    .line 21
    move-object/from16 v16, v14

    .line 22
    .line 23
    move-wide/from16 v20, v6

    .line 24
    .line 25
    move-wide/from16 v22, v20

    .line 26
    .line 27
    const/16 p0, 0x0

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v15, 0x1

    .line 31
    const/16 v17, 0x0

    .line 32
    .line 33
    move-object/from16 v6, v16

    .line 34
    .line 35
    move-object v7, v6

    .line 36
    :goto_0
    if-eqz v15, :cond_0

    .line 37
    .line 38
    const/16 p1, 0x1

    .line 39
    .line 40
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    packed-switch v3, :pswitch_data_0

    .line 45
    .line 46
    .line 47
    new-instance v0, Lqz0/k;

    .line 48
    .line 49
    invoke-direct {v0, v3}, Lqz0/k;-><init>(I)V

    .line 50
    .line 51
    .line 52
    throw v0

    .line 53
    :pswitch_0
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 54
    .line 55
    move-object/from16 v18, v2

    .line 56
    .line 57
    const/16 v2, 0xd

    .line 58
    .line 59
    invoke-interface {v1, v0, v2, v3, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    move-object v9, v2

    .line 64
    check-cast v9, Ljava/lang/String;

    .line 65
    .line 66
    or-int/lit16 v4, v4, 0x2000

    .line 67
    .line 68
    :goto_1
    move-object/from16 v2, v18

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :pswitch_1
    move-object/from16 v18, v2

    .line 72
    .line 73
    const/16 v2, 0xc

    .line 74
    .line 75
    aget-object v3, v18, v2

    .line 76
    .line 77
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    check-cast v3, Lqz0/a;

    .line 82
    .line 83
    invoke-interface {v1, v0, v2, v3, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    move-object v8, v2

    .line 88
    check-cast v8, Lio/opentelemetry/api/common/Attributes;

    .line 89
    .line 90
    or-int/lit16 v4, v4, 0x1000

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :pswitch_2
    move-object/from16 v18, v2

    .line 94
    .line 95
    const/16 v2, 0xb

    .line 96
    .line 97
    invoke-interface {v1, v0, v2}, Ltz0/a;->A(Lsz0/g;I)J

    .line 98
    .line 99
    .line 100
    move-result-wide v22

    .line 101
    or-int/lit16 v4, v4, 0x800

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :pswitch_3
    move-object/from16 v18, v2

    .line 105
    .line 106
    const/16 v2, 0xa

    .line 107
    .line 108
    invoke-interface {v1, v0, v2}, Ltz0/a;->A(Lsz0/g;I)J

    .line 109
    .line 110
    .line 111
    move-result-wide v20

    .line 112
    or-int/lit16 v4, v4, 0x400

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :pswitch_4
    move-object/from16 v18, v2

    .line 116
    .line 117
    const/16 v2, 0x9

    .line 118
    .line 119
    aget-object v3, v18, v2

    .line 120
    .line 121
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    check-cast v3, Lqz0/a;

    .line 126
    .line 127
    invoke-interface {v1, v0, v2, v3, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    move-object v7, v2

    .line 132
    check-cast v7, Lio/opentelemetry/api/common/Attributes;

    .line 133
    .line 134
    or-int/lit16 v4, v4, 0x200

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :pswitch_5
    move-object/from16 v18, v2

    .line 138
    .line 139
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 140
    .line 141
    const/16 v3, 0x8

    .line 142
    .line 143
    invoke-interface {v1, v0, v3, v2, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    move-object v6, v2

    .line 148
    check-cast v6, Ljava/lang/String;

    .line 149
    .line 150
    or-int/lit16 v4, v4, 0x100

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :pswitch_6
    move-object/from16 v18, v2

    .line 154
    .line 155
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 156
    .line 157
    const/4 v3, 0x7

    .line 158
    invoke-interface {v1, v0, v3, v2, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    move-object v5, v2

    .line 163
    check-cast v5, Ljava/lang/String;

    .line 164
    .line 165
    or-int/lit16 v4, v4, 0x80

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :pswitch_7
    move-object/from16 v18, v2

    .line 169
    .line 170
    const/4 v2, 0x6

    .line 171
    invoke-interface {v1, v0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v16

    .line 175
    or-int/lit8 v4, v4, 0x40

    .line 176
    .line 177
    goto :goto_1

    .line 178
    :pswitch_8
    move-object/from16 v18, v2

    .line 179
    .line 180
    const/4 v2, 0x5

    .line 181
    invoke-interface {v1, v0, v2}, Ltz0/a;->l(Lsz0/g;I)I

    .line 182
    .line 183
    .line 184
    move-result v17

    .line 185
    or-int/lit8 v4, v4, 0x20

    .line 186
    .line 187
    goto :goto_1

    .line 188
    :pswitch_9
    move-object/from16 v18, v2

    .line 189
    .line 190
    const/4 v2, 0x4

    .line 191
    aget-object v3, v18, v2

    .line 192
    .line 193
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    check-cast v3, Lqz0/a;

    .line 198
    .line 199
    invoke-interface {v1, v0, v2, v3, v14}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    move-object v14, v2

    .line 204
    check-cast v14, Lio/opentelemetry/api/common/Attributes;

    .line 205
    .line 206
    or-int/lit8 v4, v4, 0x10

    .line 207
    .line 208
    goto/16 :goto_1

    .line 209
    .line 210
    :pswitch_a
    move-object/from16 v18, v2

    .line 211
    .line 212
    const/4 v2, 0x3

    .line 213
    aget-object v3, v18, v2

    .line 214
    .line 215
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    check-cast v3, Lqz0/a;

    .line 220
    .line 221
    invoke-interface {v1, v0, v2, v3, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    move-object v13, v2

    .line 226
    check-cast v13, Lio/opentelemetry/sdk/logs/data/Body;

    .line 227
    .line 228
    or-int/lit8 v4, v4, 0x8

    .line 229
    .line 230
    goto/16 :goto_1

    .line 231
    .line 232
    :pswitch_b
    move-object/from16 v18, v2

    .line 233
    .line 234
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 235
    .line 236
    const/4 v3, 0x2

    .line 237
    invoke-interface {v1, v0, v3, v2, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    move-object v12, v2

    .line 242
    check-cast v12, Ljava/lang/String;

    .line 243
    .line 244
    or-int/lit8 v4, v4, 0x4

    .line 245
    .line 246
    goto/16 :goto_1

    .line 247
    .line 248
    :pswitch_c
    move-object/from16 v18, v2

    .line 249
    .line 250
    aget-object v2, v18, p1

    .line 251
    .line 252
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    check-cast v2, Lqz0/a;

    .line 257
    .line 258
    move/from16 v3, p1

    .line 259
    .line 260
    invoke-interface {v1, v0, v3, v2, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    move-object v11, v2

    .line 265
    check-cast v11, Lio/opentelemetry/api/logs/Severity;

    .line 266
    .line 267
    or-int/lit8 v4, v4, 0x2

    .line 268
    .line 269
    goto/16 :goto_1

    .line 270
    .line 271
    :pswitch_d
    move/from16 v3, p1

    .line 272
    .line 273
    move-object/from16 v18, v2

    .line 274
    .line 275
    aget-object v2, v18, p0

    .line 276
    .line 277
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    check-cast v2, Lqz0/a;

    .line 282
    .line 283
    move/from16 v3, p0

    .line 284
    .line 285
    invoke-interface {v1, v0, v3, v2, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v2

    .line 289
    move-object v10, v2

    .line 290
    check-cast v10, Lio/opentelemetry/api/trace/SpanContext;

    .line 291
    .line 292
    or-int/lit8 v4, v4, 0x1

    .line 293
    .line 294
    goto/16 :goto_1

    .line 295
    .line 296
    :pswitch_e
    move/from16 v3, p0

    .line 297
    .line 298
    move/from16 v15, p0

    .line 299
    .line 300
    goto/16 :goto_0

    .line 301
    .line 302
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 303
    .line 304
    .line 305
    move-object/from16 v24, v8

    .line 306
    .line 307
    new-instance v8, Lc91/s;

    .line 308
    .line 309
    move-object/from16 v18, v6

    .line 310
    .line 311
    move-object/from16 v19, v7

    .line 312
    .line 313
    move-object/from16 v25, v9

    .line 314
    .line 315
    move/from16 v15, v17

    .line 316
    .line 317
    move v9, v4

    .line 318
    move-object/from16 v17, v5

    .line 319
    .line 320
    invoke-direct/range {v8 .. v25}, Lc91/s;-><init>(ILio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/sdk/logs/data/Body;Lio/opentelemetry/api/common/Attributes;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JJLio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    return-object v8

    .line 324
    nop

    .line 325
    :pswitch_data_0
    .packed-switch -0x1
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

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lc91/q;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Lc91/s;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc91/q;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lc91/s;->o:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    iget-object v3, p2, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    aget-object v2, v0, v1

    .line 32
    .line 33
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Lqz0/a;

    .line 38
    .line 39
    iget-object v3, p2, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 45
    .line 46
    iget-object v2, p2, Lc91/s;->c:Ljava/lang/String;

    .line 47
    .line 48
    const/4 v3, 0x2

    .line 49
    invoke-interface {p1, p0, v3, v1, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/4 v2, 0x3

    .line 53
    aget-object v3, v0, v2

    .line 54
    .line 55
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Lqz0/a;

    .line 60
    .line 61
    iget-object v4, p2, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 62
    .line 63
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    const/4 v2, 0x4

    .line 67
    aget-object v3, v0, v2

    .line 68
    .line 69
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    check-cast v3, Lqz0/a;

    .line 74
    .line 75
    iget-object v4, p2, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 76
    .line 77
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    const/4 v2, 0x5

    .line 81
    iget v3, p2, Lc91/s;->f:I

    .line 82
    .line 83
    invoke-interface {p1, v2, v3, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 84
    .line 85
    .line 86
    const/4 v2, 0x6

    .line 87
    iget-object v3, p2, Lc91/s;->g:Ljava/lang/String;

    .line 88
    .line 89
    invoke-interface {p1, p0, v2, v3}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const/4 v2, 0x7

    .line 93
    iget-object v3, p2, Lc91/s;->h:Ljava/lang/String;

    .line 94
    .line 95
    invoke-interface {p1, p0, v2, v1, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    const/16 v2, 0x8

    .line 99
    .line 100
    iget-object v3, p2, Lc91/s;->i:Ljava/lang/String;

    .line 101
    .line 102
    invoke-interface {p1, p0, v2, v1, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    const/16 v2, 0x9

    .line 106
    .line 107
    aget-object v3, v0, v2

    .line 108
    .line 109
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    check-cast v3, Lqz0/a;

    .line 114
    .line 115
    iget-object v4, p2, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 116
    .line 117
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    const/16 v2, 0xa

    .line 121
    .line 122
    iget-wide v3, p2, Lc91/s;->k:J

    .line 123
    .line 124
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 125
    .line 126
    .line 127
    const/16 v2, 0xb

    .line 128
    .line 129
    iget-wide v3, p2, Lc91/s;->l:J

    .line 130
    .line 131
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 132
    .line 133
    .line 134
    const/16 v2, 0xc

    .line 135
    .line 136
    aget-object v0, v0, v2

    .line 137
    .line 138
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    check-cast v0, Lqz0/a;

    .line 143
    .line 144
    iget-object v3, p2, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 145
    .line 146
    invoke-interface {p1, p0, v2, v0, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    const/16 v0, 0xd

    .line 150
    .line 151
    iget-object p2, p2, Lc91/s;->n:Ljava/lang/String;

    .line 152
    .line 153
    invoke-interface {p1, p0, v0, v1, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 157
    .line 158
    .line 159
    return-void
.end method
