.class public final synthetic Lem0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(IILem0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lem0/b;->d:I

    .line 5
    .line 6
    iput p2, p0, Lem0/b;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lem0/b;->d:I

    .line 4
    .line 5
    iget v0, v0, Lem0/b;->e:I

    .line 6
    .line 7
    move-object/from16 v2, p1

    .line 8
    .line 9
    check-cast v2, Lua/a;

    .line 10
    .line 11
    const-string v3, "_connection"

    .line 12
    .line 13
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v3, "SELECT * from network_log WHERE response_code BETWEEN ? AND ?"

    .line 17
    .line 18
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const/4 v3, 0x1

    .line 23
    int-to-long v4, v1

    .line 24
    :try_start_0
    invoke-interface {v2, v3, v4, v5}, Lua/c;->bindLong(IJ)V

    .line 25
    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    int-to-long v3, v0

    .line 29
    invoke-interface {v2, v1, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 30
    .line 31
    .line 32
    const-string v0, "id"

    .line 33
    .line 34
    invoke-static {v2, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    const-string v1, "service_label"

    .line 39
    .line 40
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const-string v3, "exception"

    .line 45
    .line 46
    invoke-static {v2, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    const-string v4, "response_body"

    .line 51
    .line 52
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    const-string v5, "response_code"

    .line 57
    .line 58
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    const-string v6, "response_headers"

    .line 63
    .line 64
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    const-string v7, "response_message"

    .line 69
    .line 70
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 71
    .line 72
    .line 73
    move-result v7

    .line 74
    const-string v8, "response_time"

    .line 75
    .line 76
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    const-string v9, "response_url"

    .line 81
    .line 82
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    const-string v10, "request_body"

    .line 87
    .line 88
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 89
    .line 90
    .line 91
    move-result v10

    .line 92
    const-string v11, "request_headers"

    .line 93
    .line 94
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 95
    .line 96
    .line 97
    move-result v11

    .line 98
    const-string v12, "request_method"

    .line 99
    .line 100
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 101
    .line 102
    .line 103
    move-result v12

    .line 104
    const-string v13, "request_protocol"

    .line 105
    .line 106
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 107
    .line 108
    .line 109
    move-result v13

    .line 110
    const-string v14, "request_state"

    .line 111
    .line 112
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 113
    .line 114
    .line 115
    move-result v14

    .line 116
    const-string v15, "request_url"

    .line 117
    .line 118
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    move-result v15

    .line 122
    move/from16 p0, v15

    .line 123
    .line 124
    const-string v15, "log_type"

    .line 125
    .line 126
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 127
    .line 128
    .line 129
    move-result v15

    .line 130
    move/from16 p1, v15

    .line 131
    .line 132
    const-string v15, "timestamp"

    .line 133
    .line 134
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 135
    .line 136
    .line 137
    move-result v15

    .line 138
    move/from16 v16, v15

    .line 139
    .line 140
    new-instance v15, Ljava/util/ArrayList;

    .line 141
    .line 142
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 143
    .line 144
    .line 145
    :goto_0
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 146
    .line 147
    .line 148
    move-result v17

    .line 149
    if-eqz v17, :cond_0

    .line 150
    .line 151
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 152
    .line 153
    .line 154
    move-result-wide v19

    .line 155
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v21

    .line 159
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v22

    .line 163
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v23

    .line 167
    move/from16 v17, v0

    .line 168
    .line 169
    move/from16 v39, v1

    .line 170
    .line 171
    invoke-interface {v2, v5}, Lua/c;->getLong(I)J

    .line 172
    .line 173
    .line 174
    move-result-wide v0

    .line 175
    long-to-int v0, v0

    .line 176
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v25

    .line 180
    invoke-interface {v2, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v26

    .line 184
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 185
    .line 186
    .line 187
    move-result-wide v27

    .line 188
    invoke-interface {v2, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v29

    .line 192
    invoke-interface {v2, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v30

    .line 196
    invoke-interface {v2, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v31

    .line 200
    invoke-interface {v2, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v32

    .line 204
    invoke-interface {v2, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v33

    .line 208
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v34

    .line 212
    move/from16 v1, p0

    .line 213
    .line 214
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v35

    .line 218
    move/from16 v24, v0

    .line 219
    .line 220
    move/from16 v0, p1

    .line 221
    .line 222
    invoke-interface {v2, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v18

    .line 226
    invoke-static/range {v18 .. v18}, Lem0/f;->a(Ljava/lang/String;)Lhm0/c;

    .line 227
    .line 228
    .line 229
    move-result-object v36

    .line 230
    move/from16 p1, v0

    .line 231
    .line 232
    move/from16 v0, v16

    .line 233
    .line 234
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 235
    .line 236
    .line 237
    move-result-wide v37

    .line 238
    new-instance v18, Lem0/g;

    .line 239
    .line 240
    invoke-direct/range {v18 .. v38}, Lem0/g;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/c;J)V

    .line 241
    .line 242
    .line 243
    move/from16 v16, v0

    .line 244
    .line 245
    move-object/from16 v0, v18

    .line 246
    .line 247
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 248
    .line 249
    .line 250
    move/from16 p0, v1

    .line 251
    .line 252
    move/from16 v0, v17

    .line 253
    .line 254
    move/from16 v1, v39

    .line 255
    .line 256
    goto :goto_0

    .line 257
    :catchall_0
    move-exception v0

    .line 258
    goto :goto_1

    .line 259
    :cond_0
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 260
    .line 261
    .line 262
    return-object v15

    .line 263
    :goto_1
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 264
    .line 265
    .line 266
    throw v0
.end method
