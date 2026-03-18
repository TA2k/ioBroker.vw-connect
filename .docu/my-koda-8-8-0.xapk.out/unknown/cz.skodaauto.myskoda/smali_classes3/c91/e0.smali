.class public final synthetic Lc91/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lc91/e0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc91/e0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/e0;->a:Lc91/e0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.telemetry.serialization.SpanDataSerializer.InternalSerializableSpanData"

    .line 11
    .line 12
    const/16 v3, 0x15

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "name"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "kind"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "spanContext"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "parentSpanContext"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "statusDescription"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "statusCode"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "startEpochNanos"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "attributes"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    const-string v0, "events"

    .line 59
    .line 60
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 61
    .line 62
    .line 63
    const-string v0, "links"

    .line 64
    .line 65
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 66
    .line 67
    .line 68
    const-string v0, "endEpochNanos"

    .line 69
    .line 70
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 71
    .line 72
    .line 73
    const-string v0, "hasEnded"

    .line 74
    .line 75
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 76
    .line 77
    .line 78
    const-string v0, "totalRecordedEvents"

    .line 79
    .line 80
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 81
    .line 82
    .line 83
    const-string v0, "totalRecordedLinks"

    .line 84
    .line 85
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 86
    .line 87
    .line 88
    const-string v0, "totalAttributeCount"

    .line 89
    .line 90
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 91
    .line 92
    .line 93
    const-string v0, "instrumentationScopeInfoName"

    .line 94
    .line 95
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 96
    .line 97
    .line 98
    const-string v0, "instrumentationScopeInfoVersion"

    .line 99
    .line 100
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 101
    .line 102
    .line 103
    const-string v0, "instrumentationScopeInfoSchemaUrl"

    .line 104
    .line 105
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 106
    .line 107
    .line 108
    const-string v0, "instrumentationScopeInfoAttributes"

    .line 109
    .line 110
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 111
    .line 112
    .line 113
    const-string v0, "resourceAttributes"

    .line 114
    .line 115
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 116
    .line 117
    .line 118
    const-string v0, "resourceSchemaUrl"

    .line 119
    .line 120
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 121
    .line 122
    .line 123
    sput-object v1, Lc91/e0;->descriptor:Lsz0/g;

    .line 124
    .line 125
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 5

    .line 1
    sget-object p0, Lc91/g0;->v:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0x15

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aput-object v1, v0, v2

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    aget-object v3, p0, v2

    .line 14
    .line 15
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    aput-object v3, v0, v2

    .line 20
    .line 21
    const/4 v2, 0x2

    .line 22
    aget-object v3, p0, v2

    .line 23
    .line 24
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    aput-object v3, v0, v2

    .line 29
    .line 30
    const/4 v2, 0x3

    .line 31
    aget-object v3, p0, v2

    .line 32
    .line 33
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    aput-object v3, v0, v2

    .line 38
    .line 39
    const/4 v2, 0x4

    .line 40
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    aput-object v3, v0, v2

    .line 45
    .line 46
    const/4 v2, 0x5

    .line 47
    aget-object v3, p0, v2

    .line 48
    .line 49
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    aput-object v3, v0, v2

    .line 54
    .line 55
    sget-object v2, Luz0/q0;->a:Luz0/q0;

    .line 56
    .line 57
    const/4 v3, 0x6

    .line 58
    aput-object v2, v0, v3

    .line 59
    .line 60
    const/4 v3, 0x7

    .line 61
    aget-object v4, p0, v3

    .line 62
    .line 63
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    aput-object v4, v0, v3

    .line 68
    .line 69
    const/16 v3, 0x8

    .line 70
    .line 71
    aget-object v4, p0, v3

    .line 72
    .line 73
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    aput-object v4, v0, v3

    .line 78
    .line 79
    const/16 v3, 0x9

    .line 80
    .line 81
    aget-object v4, p0, v3

    .line 82
    .line 83
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    aput-object v4, v0, v3

    .line 88
    .line 89
    const/16 v3, 0xa

    .line 90
    .line 91
    aput-object v2, v0, v3

    .line 92
    .line 93
    const/16 v2, 0xb

    .line 94
    .line 95
    sget-object v3, Luz0/g;->a:Luz0/g;

    .line 96
    .line 97
    aput-object v3, v0, v2

    .line 98
    .line 99
    sget-object v2, Luz0/k0;->a:Luz0/k0;

    .line 100
    .line 101
    const/16 v3, 0xc

    .line 102
    .line 103
    aput-object v2, v0, v3

    .line 104
    .line 105
    const/16 v3, 0xd

    .line 106
    .line 107
    aput-object v2, v0, v3

    .line 108
    .line 109
    const/16 v3, 0xe

    .line 110
    .line 111
    aput-object v2, v0, v3

    .line 112
    .line 113
    const/16 v2, 0xf

    .line 114
    .line 115
    aput-object v1, v0, v2

    .line 116
    .line 117
    const/16 v2, 0x10

    .line 118
    .line 119
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    aput-object v3, v0, v2

    .line 124
    .line 125
    const/16 v2, 0x11

    .line 126
    .line 127
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    aput-object v3, v0, v2

    .line 132
    .line 133
    const/16 v2, 0x12

    .line 134
    .line 135
    aget-object v3, p0, v2

    .line 136
    .line 137
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    aput-object v3, v0, v2

    .line 142
    .line 143
    const/16 v2, 0x13

    .line 144
    .line 145
    aget-object p0, p0, v2

    .line 146
    .line 147
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    aput-object p0, v0, v2

    .line 152
    .line 153
    const/16 p0, 0x14

    .line 154
    .line 155
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    aput-object v1, v0, p0

    .line 160
    .line 161
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 33

    .line 1
    sget-object v0, Lc91/e0;->descriptor:Lsz0/g;

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
    sget-object v2, Lc91/g0;->v:[Llx0/i;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    const-wide/16 v6, 0x0

    .line 13
    .line 14
    move-object/from16 v16, v2

    .line 15
    .line 16
    move-object v2, v5

    .line 17
    move-object v3, v2

    .line 18
    move-object v4, v3

    .line 19
    move-object v8, v4

    .line 20
    move-object v9, v8

    .line 21
    move-object v11, v9

    .line 22
    move-object v12, v11

    .line 23
    move-object v13, v12

    .line 24
    move-object v14, v13

    .line 25
    move-object v15, v14

    .line 26
    move-object/from16 v20, v15

    .line 27
    .line 28
    move-object/from16 v27, v20

    .line 29
    .line 30
    move-wide/from16 v17, v6

    .line 31
    .line 32
    move-wide/from16 v21, v17

    .line 33
    .line 34
    const/16 p1, 0x1

    .line 35
    .line 36
    const/4 v10, 0x0

    .line 37
    const/16 v19, 0x1

    .line 38
    .line 39
    const/16 v23, 0x0

    .line 40
    .line 41
    const/16 v24, 0x0

    .line 42
    .line 43
    const/16 v25, 0x0

    .line 44
    .line 45
    const/16 v26, 0x0

    .line 46
    .line 47
    move-object/from16 v6, v27

    .line 48
    .line 49
    move-object v7, v6

    .line 50
    :goto_0
    if-eqz v19, :cond_0

    .line 51
    .line 52
    move-object/from16 v28, v11

    .line 53
    .line 54
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 55
    .line 56
    .line 57
    move-result v11

    .line 58
    packed-switch v11, :pswitch_data_0

    .line 59
    .line 60
    .line 61
    new-instance v0, Lqz0/k;

    .line 62
    .line 63
    invoke-direct {v0, v11}, Lqz0/k;-><init>(I)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :pswitch_0
    sget-object v11, Luz0/q1;->a:Luz0/q1;

    .line 68
    .line 69
    move-object/from16 v29, v12

    .line 70
    .line 71
    const/16 v12, 0x14

    .line 72
    .line 73
    invoke-interface {v1, v0, v12, v11, v2}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/String;

    .line 78
    .line 79
    const/high16 v11, 0x100000

    .line 80
    .line 81
    :goto_1
    or-int/2addr v10, v11

    .line 82
    :goto_2
    move-object/from16 v11, v28

    .line 83
    .line 84
    :goto_3
    move-object/from16 v12, v29

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :pswitch_1
    move-object/from16 v29, v12

    .line 88
    .line 89
    const/16 v11, 0x13

    .line 90
    .line 91
    aget-object v12, v16, v11

    .line 92
    .line 93
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v12

    .line 97
    check-cast v12, Lqz0/a;

    .line 98
    .line 99
    invoke-interface {v1, v0, v11, v12, v3}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    check-cast v3, Lio/opentelemetry/api/common/Attributes;

    .line 104
    .line 105
    const/high16 v11, 0x80000

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :pswitch_2
    move-object/from16 v29, v12

    .line 109
    .line 110
    const/16 v11, 0x12

    .line 111
    .line 112
    aget-object v12, v16, v11

    .line 113
    .line 114
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v12

    .line 118
    check-cast v12, Lqz0/a;

    .line 119
    .line 120
    invoke-interface {v1, v0, v11, v12, v4}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    check-cast v4, Lio/opentelemetry/api/common/Attributes;

    .line 125
    .line 126
    const/high16 v11, 0x40000

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :pswitch_3
    move-object/from16 v29, v12

    .line 130
    .line 131
    sget-object v11, Luz0/q1;->a:Luz0/q1;

    .line 132
    .line 133
    const/16 v12, 0x11

    .line 134
    .line 135
    invoke-interface {v1, v0, v12, v11, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v9

    .line 139
    check-cast v9, Ljava/lang/String;

    .line 140
    .line 141
    const/high16 v11, 0x20000

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :pswitch_4
    move-object/from16 v29, v12

    .line 145
    .line 146
    sget-object v11, Luz0/q1;->a:Luz0/q1;

    .line 147
    .line 148
    const/16 v12, 0x10

    .line 149
    .line 150
    invoke-interface {v1, v0, v12, v11, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    check-cast v8, Ljava/lang/String;

    .line 155
    .line 156
    const/high16 v11, 0x10000

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :pswitch_5
    move-object/from16 v29, v12

    .line 160
    .line 161
    const/16 v11, 0xf

    .line 162
    .line 163
    invoke-interface {v1, v0, v11}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v27

    .line 167
    const v11, 0x8000

    .line 168
    .line 169
    .line 170
    or-int/2addr v10, v11

    .line 171
    :goto_4
    move-object/from16 v11, v28

    .line 172
    .line 173
    goto :goto_0

    .line 174
    :pswitch_6
    move-object/from16 v29, v12

    .line 175
    .line 176
    const/16 v11, 0xe

    .line 177
    .line 178
    invoke-interface {v1, v0, v11}, Ltz0/a;->l(Lsz0/g;I)I

    .line 179
    .line 180
    .line 181
    move-result v26

    .line 182
    or-int/lit16 v10, v10, 0x4000

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :pswitch_7
    move-object/from16 v29, v12

    .line 186
    .line 187
    const/16 v11, 0xd

    .line 188
    .line 189
    invoke-interface {v1, v0, v11}, Ltz0/a;->l(Lsz0/g;I)I

    .line 190
    .line 191
    .line 192
    move-result v25

    .line 193
    or-int/lit16 v10, v10, 0x2000

    .line 194
    .line 195
    goto :goto_4

    .line 196
    :pswitch_8
    move-object/from16 v29, v12

    .line 197
    .line 198
    const/16 v11, 0xc

    .line 199
    .line 200
    invoke-interface {v1, v0, v11}, Ltz0/a;->l(Lsz0/g;I)I

    .line 201
    .line 202
    .line 203
    move-result v24

    .line 204
    or-int/lit16 v10, v10, 0x1000

    .line 205
    .line 206
    goto :goto_4

    .line 207
    :pswitch_9
    move-object/from16 v29, v12

    .line 208
    .line 209
    const/16 v11, 0xb

    .line 210
    .line 211
    invoke-interface {v1, v0, v11}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 212
    .line 213
    .line 214
    move-result v23

    .line 215
    or-int/lit16 v10, v10, 0x800

    .line 216
    .line 217
    goto :goto_4

    .line 218
    :pswitch_a
    move-object/from16 v29, v12

    .line 219
    .line 220
    const/16 v11, 0xa

    .line 221
    .line 222
    invoke-interface {v1, v0, v11}, Ltz0/a;->A(Lsz0/g;I)J

    .line 223
    .line 224
    .line 225
    move-result-wide v21

    .line 226
    or-int/lit16 v10, v10, 0x400

    .line 227
    .line 228
    goto :goto_4

    .line 229
    :pswitch_b
    move-object/from16 v29, v12

    .line 230
    .line 231
    const/16 v11, 0x9

    .line 232
    .line 233
    aget-object v12, v16, v11

    .line 234
    .line 235
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v12

    .line 239
    check-cast v12, Lqz0/a;

    .line 240
    .line 241
    invoke-interface {v1, v0, v11, v12, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v7

    .line 245
    check-cast v7, Ljava/util/List;

    .line 246
    .line 247
    or-int/lit16 v10, v10, 0x200

    .line 248
    .line 249
    goto/16 :goto_2

    .line 250
    .line 251
    :pswitch_c
    move-object/from16 v29, v12

    .line 252
    .line 253
    const/16 v11, 0x8

    .line 254
    .line 255
    aget-object v12, v16, v11

    .line 256
    .line 257
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v12

    .line 261
    check-cast v12, Lqz0/a;

    .line 262
    .line 263
    invoke-interface {v1, v0, v11, v12, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v6

    .line 267
    check-cast v6, Ljava/util/List;

    .line 268
    .line 269
    or-int/lit16 v10, v10, 0x100

    .line 270
    .line 271
    goto/16 :goto_2

    .line 272
    .line 273
    :pswitch_d
    move-object/from16 v29, v12

    .line 274
    .line 275
    const/4 v11, 0x7

    .line 276
    aget-object v12, v16, v11

    .line 277
    .line 278
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v12

    .line 282
    check-cast v12, Lqz0/a;

    .line 283
    .line 284
    invoke-interface {v1, v0, v11, v12, v5}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    check-cast v5, Lio/opentelemetry/api/common/Attributes;

    .line 289
    .line 290
    or-int/lit16 v10, v10, 0x80

    .line 291
    .line 292
    goto/16 :goto_2

    .line 293
    .line 294
    :pswitch_e
    move-object/from16 v29, v12

    .line 295
    .line 296
    const/4 v11, 0x6

    .line 297
    invoke-interface {v1, v0, v11}, Ltz0/a;->A(Lsz0/g;I)J

    .line 298
    .line 299
    .line 300
    move-result-wide v17

    .line 301
    or-int/lit8 v10, v10, 0x40

    .line 302
    .line 303
    goto/16 :goto_4

    .line 304
    .line 305
    :pswitch_f
    move-object/from16 v29, v12

    .line 306
    .line 307
    const/4 v11, 0x5

    .line 308
    aget-object v12, v16, v11

    .line 309
    .line 310
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v12

    .line 314
    check-cast v12, Lqz0/a;

    .line 315
    .line 316
    invoke-interface {v1, v0, v11, v12, v15}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v11

    .line 320
    move-object v15, v11

    .line 321
    check-cast v15, Lio/opentelemetry/api/trace/StatusCode;

    .line 322
    .line 323
    or-int/lit8 v10, v10, 0x20

    .line 324
    .line 325
    goto/16 :goto_2

    .line 326
    .line 327
    :pswitch_10
    move-object/from16 v29, v12

    .line 328
    .line 329
    sget-object v11, Luz0/q1;->a:Luz0/q1;

    .line 330
    .line 331
    const/4 v12, 0x4

    .line 332
    invoke-interface {v1, v0, v12, v11, v14}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v11

    .line 336
    move-object v14, v11

    .line 337
    check-cast v14, Ljava/lang/String;

    .line 338
    .line 339
    or-int/lit8 v10, v10, 0x10

    .line 340
    .line 341
    goto/16 :goto_2

    .line 342
    .line 343
    :pswitch_11
    move-object/from16 v29, v12

    .line 344
    .line 345
    const/4 v11, 0x3

    .line 346
    aget-object v12, v16, v11

    .line 347
    .line 348
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v12

    .line 352
    check-cast v12, Lqz0/a;

    .line 353
    .line 354
    invoke-interface {v1, v0, v11, v12, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v11

    .line 358
    move-object v13, v11

    .line 359
    check-cast v13, Lio/opentelemetry/api/trace/SpanContext;

    .line 360
    .line 361
    or-int/lit8 v10, v10, 0x8

    .line 362
    .line 363
    goto/16 :goto_2

    .line 364
    .line 365
    :pswitch_12
    move-object/from16 v29, v12

    .line 366
    .line 367
    const/4 v11, 0x2

    .line 368
    aget-object v12, v16, v11

    .line 369
    .line 370
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v12

    .line 374
    check-cast v12, Lqz0/a;

    .line 375
    .line 376
    move-object/from16 v32, v2

    .line 377
    .line 378
    move-object/from16 v2, v29

    .line 379
    .line 380
    invoke-interface {v1, v0, v11, v12, v2}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v2

    .line 384
    move-object v12, v2

    .line 385
    check-cast v12, Lio/opentelemetry/api/trace/SpanContext;

    .line 386
    .line 387
    or-int/lit8 v10, v10, 0x4

    .line 388
    .line 389
    move-object/from16 v11, v28

    .line 390
    .line 391
    :goto_5
    move-object/from16 v2, v32

    .line 392
    .line 393
    goto/16 :goto_0

    .line 394
    .line 395
    :pswitch_13
    move-object/from16 v32, v2

    .line 396
    .line 397
    move-object v2, v12

    .line 398
    aget-object v11, v16, p1

    .line 399
    .line 400
    invoke-interface {v11}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v11

    .line 404
    check-cast v11, Lqz0/a;

    .line 405
    .line 406
    move-object/from16 v29, v2

    .line 407
    .line 408
    move-object/from16 v12, v28

    .line 409
    .line 410
    move/from16 v2, p1

    .line 411
    .line 412
    invoke-interface {v1, v0, v2, v11, v12}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v11

    .line 416
    check-cast v11, Lio/opentelemetry/api/trace/SpanKind;

    .line 417
    .line 418
    or-int/lit8 v10, v10, 0x2

    .line 419
    .line 420
    :goto_6
    move-object/from16 v12, v29

    .line 421
    .line 422
    goto :goto_5

    .line 423
    :pswitch_14
    move-object/from16 v32, v2

    .line 424
    .line 425
    move-object/from16 v29, v12

    .line 426
    .line 427
    move-object/from16 v12, v28

    .line 428
    .line 429
    const/4 v11, 0x0

    .line 430
    move/from16 v2, p1

    .line 431
    .line 432
    invoke-interface {v1, v0, v11}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 433
    .line 434
    .line 435
    move-result-object v20

    .line 436
    or-int/lit8 v10, v10, 0x1

    .line 437
    .line 438
    move-object v11, v12

    .line 439
    goto :goto_6

    .line 440
    :pswitch_15
    move-object/from16 v32, v2

    .line 441
    .line 442
    move-object/from16 v29, v12

    .line 443
    .line 444
    move-object/from16 v12, v28

    .line 445
    .line 446
    const/4 v11, 0x0

    .line 447
    move/from16 v19, v11

    .line 448
    .line 449
    move-object v11, v12

    .line 450
    goto/16 :goto_3

    .line 451
    .line 452
    :cond_0
    move-object/from16 v32, v2

    .line 453
    .line 454
    move-object/from16 v29, v12

    .line 455
    .line 456
    move-object v12, v11

    .line 457
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 458
    .line 459
    .line 460
    move-object/from16 v28, v8

    .line 461
    .line 462
    new-instance v8, Lc91/g0;

    .line 463
    .line 464
    move-object/from16 v31, v3

    .line 465
    .line 466
    move-object/from16 v30, v4

    .line 467
    .line 468
    move-object/from16 v19, v6

    .line 469
    .line 470
    move-wide/from16 v16, v17

    .line 471
    .line 472
    move-object/from16 v12, v29

    .line 473
    .line 474
    move-object/from16 v18, v5

    .line 475
    .line 476
    move-object/from16 v29, v9

    .line 477
    .line 478
    move v9, v10

    .line 479
    move-object/from16 v10, v20

    .line 480
    .line 481
    move-object/from16 v20, v7

    .line 482
    .line 483
    invoke-direct/range {v8 .. v32}, Lc91/g0;-><init>(ILjava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/api/trace/StatusCode;JLio/opentelemetry/api/common/Attributes;Ljava/util/List;Ljava/util/List;JZIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    return-object v8

    .line 487
    :pswitch_data_0
    .packed-switch -0x1
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

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lc91/e0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Lc91/g0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc91/e0;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lc91/g0;->v:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iget-object v2, p2, Lc91/g0;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x1

    .line 23
    aget-object v2, v0, v1

    .line 24
    .line 25
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lqz0/a;

    .line 30
    .line 31
    iget-object v3, p2, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 32
    .line 33
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    aget-object v2, v0, v1

    .line 38
    .line 39
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lqz0/a;

    .line 44
    .line 45
    iget-object v3, p2, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 46
    .line 47
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    const/4 v1, 0x3

    .line 51
    aget-object v2, v0, v1

    .line 52
    .line 53
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    check-cast v2, Lqz0/a;

    .line 58
    .line 59
    iget-object v3, p2, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 60
    .line 61
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 65
    .line 66
    iget-object v2, p2, Lc91/g0;->e:Ljava/lang/String;

    .line 67
    .line 68
    const/4 v3, 0x4

    .line 69
    invoke-interface {p1, p0, v3, v1, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    const/4 v2, 0x5

    .line 73
    aget-object v3, v0, v2

    .line 74
    .line 75
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    check-cast v3, Lqz0/a;

    .line 80
    .line 81
    iget-object v4, p2, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 82
    .line 83
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    const/4 v2, 0x6

    .line 87
    iget-wide v3, p2, Lc91/g0;->g:J

    .line 88
    .line 89
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 90
    .line 91
    .line 92
    const/4 v2, 0x7

    .line 93
    aget-object v3, v0, v2

    .line 94
    .line 95
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Lqz0/a;

    .line 100
    .line 101
    iget-object v4, p2, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 102
    .line 103
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    const/16 v2, 0x8

    .line 107
    .line 108
    aget-object v3, v0, v2

    .line 109
    .line 110
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    check-cast v3, Lqz0/a;

    .line 115
    .line 116
    iget-object v4, p2, Lc91/g0;->i:Ljava/util/List;

    .line 117
    .line 118
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    const/16 v2, 0x9

    .line 122
    .line 123
    aget-object v3, v0, v2

    .line 124
    .line 125
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    check-cast v3, Lqz0/a;

    .line 130
    .line 131
    iget-object v4, p2, Lc91/g0;->j:Ljava/util/List;

    .line 132
    .line 133
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    const/16 v2, 0xa

    .line 137
    .line 138
    iget-wide v3, p2, Lc91/g0;->k:J

    .line 139
    .line 140
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 141
    .line 142
    .line 143
    const/16 v2, 0xb

    .line 144
    .line 145
    iget-boolean v3, p2, Lc91/g0;->l:Z

    .line 146
    .line 147
    invoke-interface {p1, p0, v2, v3}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 148
    .line 149
    .line 150
    const/16 v2, 0xc

    .line 151
    .line 152
    iget v3, p2, Lc91/g0;->m:I

    .line 153
    .line 154
    invoke-interface {p1, v2, v3, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 155
    .line 156
    .line 157
    const/16 v2, 0xd

    .line 158
    .line 159
    iget v3, p2, Lc91/g0;->n:I

    .line 160
    .line 161
    invoke-interface {p1, v2, v3, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 162
    .line 163
    .line 164
    const/16 v2, 0xe

    .line 165
    .line 166
    iget v3, p2, Lc91/g0;->o:I

    .line 167
    .line 168
    invoke-interface {p1, v2, v3, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 169
    .line 170
    .line 171
    const/16 v2, 0xf

    .line 172
    .line 173
    iget-object v3, p2, Lc91/g0;->p:Ljava/lang/String;

    .line 174
    .line 175
    invoke-interface {p1, p0, v2, v3}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 176
    .line 177
    .line 178
    const/16 v2, 0x10

    .line 179
    .line 180
    iget-object v3, p2, Lc91/g0;->q:Ljava/lang/String;

    .line 181
    .line 182
    invoke-interface {p1, p0, v2, v1, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    const/16 v2, 0x11

    .line 186
    .line 187
    iget-object v3, p2, Lc91/g0;->r:Ljava/lang/String;

    .line 188
    .line 189
    invoke-interface {p1, p0, v2, v1, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    const/16 v2, 0x12

    .line 193
    .line 194
    aget-object v3, v0, v2

    .line 195
    .line 196
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    check-cast v3, Lqz0/a;

    .line 201
    .line 202
    iget-object v4, p2, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    .line 203
    .line 204
    invoke-interface {p1, p0, v2, v3, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    const/16 v2, 0x13

    .line 208
    .line 209
    aget-object v0, v0, v2

    .line 210
    .line 211
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    check-cast v0, Lqz0/a;

    .line 216
    .line 217
    iget-object v3, p2, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 218
    .line 219
    invoke-interface {p1, p0, v2, v0, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    const/16 v0, 0x14

    .line 223
    .line 224
    iget-object p2, p2, Lc91/g0;->u:Ljava/lang/String;

    .line 225
    .line 226
    invoke-interface {p1, p0, v0, v1, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 230
    .line 231
    .line 232
    return-void
.end method
