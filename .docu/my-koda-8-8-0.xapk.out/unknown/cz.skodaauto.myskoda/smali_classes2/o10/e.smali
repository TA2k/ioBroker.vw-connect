.class public final Lo10/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo10/e;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/16 v0, 0x1b

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Las0/h;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lo10/e;->b:Las0/h;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(Lua/a;Landroidx/collection/u;)V
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    invoke-virtual {v1}, Landroidx/collection/u;->h()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {v1}, Landroidx/collection/u;->h()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const/16 v3, 0x3e7

    .line 17
    .line 18
    if-le v2, v3, :cond_1

    .line 19
    .line 20
    new-instance v2, Lo10/d;

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    move-object/from16 v4, p0

    .line 24
    .line 25
    invoke-direct {v2, v4, v0, v3}, Lo10/d;-><init>(Lo10/e;Lua/a;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1, v2}, Ljp/ye;->c(Landroidx/collection/u;Lay0/k;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    const-string v2, "SELECT `id`,`timer_id`,`charging_time_id`,`enabled`,`start_time`,`end_time` FROM `departure_charging_time` WHERE `timer_id` IN ("

    .line 33
    .line 34
    invoke-static {v2}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v1}, Landroidx/collection/u;->h()I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    invoke-static {v3, v2}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 43
    .line 44
    .line 45
    const-string v3, ")"

    .line 46
    .line 47
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    const-string v3, "toString(...)"

    .line 55
    .line 56
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {v0, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {v1}, Landroidx/collection/u;->h()I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    const/4 v3, 0x0

    .line 68
    const/4 v4, 0x1

    .line 69
    move v5, v3

    .line 70
    move v6, v4

    .line 71
    :goto_0
    if-ge v5, v0, :cond_2

    .line 72
    .line 73
    invoke-virtual {v1, v5}, Landroidx/collection/u;->d(I)J

    .line 74
    .line 75
    .line 76
    move-result-wide v7

    .line 77
    invoke-interface {v2, v6, v7, v8}, Lua/c;->bindLong(IJ)V

    .line 78
    .line 79
    .line 80
    add-int/2addr v6, v4

    .line 81
    add-int/lit8 v5, v5, 0x1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_2
    :try_start_0
    const-string v0, "timer_id"

    .line 85
    .line 86
    invoke-static {v2, v0}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 87
    .line 88
    .line 89
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 90
    const/4 v5, -0x1

    .line 91
    if-ne v0, v5, :cond_3

    .line 92
    .line 93
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    if-eqz v5, :cond_9

    .line 102
    .line 103
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 104
    .line 105
    .line 106
    move-result-wide v5

    .line 107
    invoke-virtual {v1, v5, v6}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    check-cast v5, Ljava/util/List;

    .line 112
    .line 113
    if-eqz v5, :cond_3

    .line 114
    .line 115
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 116
    .line 117
    .line 118
    move-result-wide v7

    .line 119
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 120
    .line 121
    .line 122
    move-result-wide v9

    .line 123
    const/4 v6, 0x2

    .line 124
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 125
    .line 126
    .line 127
    move-result-wide v11

    .line 128
    const/4 v6, 0x3

    .line 129
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 130
    .line 131
    .line 132
    move-result-wide v13

    .line 133
    long-to-int v6, v13

    .line 134
    if-eqz v6, :cond_4

    .line 135
    .line 136
    move v13, v4

    .line 137
    goto :goto_2

    .line 138
    :cond_4
    move v13, v3

    .line 139
    :goto_2
    const/4 v6, 0x4

    .line 140
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 141
    .line 142
    .line 143
    move-result v14

    .line 144
    const/4 v15, 0x0

    .line 145
    if-eqz v14, :cond_5

    .line 146
    .line 147
    move-object v6, v15

    .line 148
    goto :goto_3

    .line 149
    :cond_5
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    :goto_3
    invoke-static {v6}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 154
    .line 155
    .line 156
    move-result-object v14
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 157
    const-string v6, "Expected NON-NULL \'java.time.LocalTime\', but it was NULL."

    .line 158
    .line 159
    if-eqz v14, :cond_8

    .line 160
    .line 161
    const/4 v3, 0x5

    .line 162
    :try_start_2
    invoke-interface {v2, v3}, Lua/c;->isNull(I)Z

    .line 163
    .line 164
    .line 165
    move-result v16

    .line 166
    if-eqz v16, :cond_6

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_6
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v15

    .line 173
    :goto_4
    invoke-static {v15}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 174
    .line 175
    .line 176
    move-result-object v15

    .line 177
    if-eqz v15, :cond_7

    .line 178
    .line 179
    new-instance v6, Lo10/b;

    .line 180
    .line 181
    invoke-direct/range {v6 .. v15}, Lo10/b;-><init>(JJJZLjava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 182
    .line 183
    .line 184
    invoke-interface {v5, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    const/4 v3, 0x0

    .line 188
    goto :goto_1

    .line 189
    :catchall_0
    move-exception v0

    .line 190
    goto :goto_5

    .line 191
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    throw v0

    .line 197
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 198
    .line 199
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 203
    :cond_9
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 204
    .line 205
    .line 206
    return-void

    .line 207
    :goto_5
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 208
    .line 209
    .line 210
    throw v0
.end method

.method public final b(Lua/a;Landroidx/collection/f;)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-virtual {v2}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-interface {v3}, Ljava/util/Set;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    if-eqz v4, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-virtual {v2}, Landroidx/collection/a1;->size()I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    const/16 v5, 0x3e7

    .line 23
    .line 24
    if-le v4, v5, :cond_1

    .line 25
    .line 26
    new-instance v3, Lo10/d;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct {v3, v0, v1, v4}, Lo10/d;-><init>(Lo10/e;Lua/a;I)V

    .line 30
    .line 31
    .line 32
    invoke-static {v2, v3}, Ljp/ye;->b(Landroidx/collection/f;Lay0/k;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    const-string v4, "SELECT `id`,`vin`,`index`,`is_enabled`,`is_charging_enabled`,`is_air_conditioning_enabled`,`target_charged_state`,`timer_id`,`timer_enabled`,`timer_time`,`timer_type`,`timer_days` FROM `departure_timer` WHERE `vin` IN ("

    .line 37
    .line 38
    invoke-static {v4}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-interface {v3}, Ljava/util/Set;->size()I

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    invoke-static {v5, v4}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 47
    .line 48
    .line 49
    const-string v5, ")"

    .line 50
    .line 51
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    const-string v5, "toString(...)"

    .line 59
    .line 60
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-interface {v1, v4}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    const/4 v5, 0x1

    .line 72
    move v6, v5

    .line 73
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-eqz v7, :cond_2

    .line 78
    .line 79
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    check-cast v7, Ljava/lang/String;

    .line 84
    .line 85
    invoke-interface {v4, v6, v7}, Lua/c;->w(ILjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    add-int/2addr v6, v5

    .line 89
    goto :goto_0

    .line 90
    :cond_2
    :try_start_0
    const-string v3, "vin"

    .line 91
    .line 92
    invoke-static {v4, v3}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 93
    .line 94
    .line 95
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 96
    const/4 v6, -0x1

    .line 97
    if-ne v3, v6, :cond_3

    .line 98
    .line 99
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :cond_3
    :try_start_1
    new-instance v6, Landroidx/collection/u;

    .line 104
    .line 105
    const/4 v7, 0x0

    .line 106
    invoke-direct {v6, v7}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_4
    :goto_1
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    const/4 v9, 0x0

    .line 114
    if-eqz v8, :cond_6

    .line 115
    .line 116
    invoke-interface {v4, v9}, Lua/c;->getLong(I)J

    .line 117
    .line 118
    .line 119
    move-result-wide v10

    .line 120
    invoke-virtual {v6, v10, v11}, Landroidx/collection/u;->c(J)I

    .line 121
    .line 122
    .line 123
    move-result v8

    .line 124
    if-ltz v8, :cond_5

    .line 125
    .line 126
    move v9, v5

    .line 127
    :cond_5
    if-nez v9, :cond_4

    .line 128
    .line 129
    new-instance v8, Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v6, v10, v11, v8}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :catchall_0
    move-exception v0

    .line 139
    goto/16 :goto_9

    .line 140
    .line 141
    :cond_6
    invoke-interface {v4}, Lua/c;->reset()V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0, v1, v6}, Lo10/e;->a(Lua/a;Landroidx/collection/u;)V

    .line 145
    .line 146
    .line 147
    :cond_7
    :goto_2
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    if-eqz v0, :cond_10

    .line 152
    .line 153
    invoke-interface {v4, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-virtual {v2, v0}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    check-cast v0, Ljava/util/List;

    .line 162
    .line 163
    if-eqz v0, :cond_7

    .line 164
    .line 165
    invoke-interface {v4, v9}, Lua/c;->getLong(I)J

    .line 166
    .line 167
    .line 168
    move-result-wide v11

    .line 169
    invoke-interface {v4, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v13

    .line 173
    const/4 v1, 0x2

    .line 174
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 175
    .line 176
    .line 177
    move-result-wide v14

    .line 178
    long-to-int v14, v14

    .line 179
    const/4 v1, 0x3

    .line 180
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 181
    .line 182
    .line 183
    move-result-wide v7

    .line 184
    long-to-int v1, v7

    .line 185
    if-eqz v1, :cond_8

    .line 186
    .line 187
    move v15, v5

    .line 188
    goto :goto_3

    .line 189
    :cond_8
    move v15, v9

    .line 190
    :goto_3
    const/4 v1, 0x4

    .line 191
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 192
    .line 193
    .line 194
    move-result-wide v7

    .line 195
    long-to-int v1, v7

    .line 196
    if-eqz v1, :cond_9

    .line 197
    .line 198
    move/from16 v16, v5

    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_9
    move/from16 v16, v9

    .line 202
    .line 203
    :goto_4
    const/4 v1, 0x5

    .line 204
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 205
    .line 206
    .line 207
    move-result-wide v7

    .line 208
    long-to-int v1, v7

    .line 209
    if-eqz v1, :cond_a

    .line 210
    .line 211
    move/from16 v17, v5

    .line 212
    .line 213
    goto :goto_5

    .line 214
    :cond_a
    move/from16 v17, v9

    .line 215
    .line 216
    :goto_5
    const/4 v1, 0x6

    .line 217
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 218
    .line 219
    .line 220
    move-result v7

    .line 221
    if-eqz v7, :cond_b

    .line 222
    .line 223
    const/16 v18, 0x0

    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_b
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 227
    .line 228
    .line 229
    move-result-wide v7

    .line 230
    long-to-int v1, v7

    .line 231
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    move-object/from16 v18, v1

    .line 236
    .line 237
    :goto_6
    const/4 v1, 0x7

    .line 238
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 239
    .line 240
    .line 241
    move-result-wide v19

    .line 242
    const/16 v1, 0x8

    .line 243
    .line 244
    invoke-interface {v4, v1}, Lua/c;->getLong(I)J

    .line 245
    .line 246
    .line 247
    move-result-wide v7

    .line 248
    long-to-int v1, v7

    .line 249
    if-eqz v1, :cond_c

    .line 250
    .line 251
    move/from16 v21, v5

    .line 252
    .line 253
    goto :goto_7

    .line 254
    :cond_c
    move/from16 v21, v9

    .line 255
    .line 256
    :goto_7
    const/16 v1, 0x9

    .line 257
    .line 258
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 259
    .line 260
    .line 261
    move-result v7

    .line 262
    if-eqz v7, :cond_d

    .line 263
    .line 264
    const/4 v1, 0x0

    .line 265
    goto :goto_8

    .line 266
    :cond_d
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v1

    .line 270
    :goto_8
    invoke-static {v1}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 271
    .line 272
    .line 273
    move-result-object v22

    .line 274
    if-eqz v22, :cond_f

    .line 275
    .line 276
    const/16 v1, 0xa

    .line 277
    .line 278
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v23

    .line 282
    const/16 v1, 0xb

    .line 283
    .line 284
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v24

    .line 288
    new-instance v10, Lo10/i;

    .line 289
    .line 290
    invoke-direct/range {v10 .. v24}, Lo10/i;-><init>(JLjava/lang/String;IZZZLjava/lang/Integer;JZLjava/time/LocalTime;Ljava/lang/String;Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    invoke-interface {v4, v9}, Lua/c;->getLong(I)J

    .line 294
    .line 295
    .line 296
    move-result-wide v7

    .line 297
    invoke-virtual {v6, v7, v8}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    if-eqz v1, :cond_e

    .line 302
    .line 303
    check-cast v1, Ljava/util/List;

    .line 304
    .line 305
    new-instance v7, Lo10/j;

    .line 306
    .line 307
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 308
    .line 309
    .line 310
    iput-object v10, v7, Lo10/j;->a:Lo10/i;

    .line 311
    .line 312
    iput-object v1, v7, Lo10/j;->b:Ljava/util/List;

    .line 313
    .line 314
    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 315
    .line 316
    .line 317
    const/4 v7, 0x0

    .line 318
    goto/16 :goto_2

    .line 319
    .line 320
    :cond_e
    const-string v0, "Required value was null."

    .line 321
    .line 322
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 323
    .line 324
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw v1

    .line 328
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 329
    .line 330
    const-string v1, "Expected NON-NULL \'java.time.LocalTime\', but it was NULL."

    .line 331
    .line 332
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 336
    :cond_10
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 337
    .line 338
    .line 339
    return-void

    .line 340
    :goto_9
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 341
    .line 342
    .line 343
    throw v0
.end method
