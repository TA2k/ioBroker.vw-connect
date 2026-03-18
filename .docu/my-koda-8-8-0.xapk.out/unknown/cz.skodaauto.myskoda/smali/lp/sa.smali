.class public abstract Llp/sa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/t2;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v7, p6

    .line 2
    .line 3
    check-cast v7, Ll2/t;

    .line 4
    .line 5
    const v0, 0x162afa27

    .line 6
    .line 7
    .line 8
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v9, p0

    .line 12
    .line 13
    invoke-virtual {v7, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p7, v0

    .line 23
    .line 24
    and-int/lit8 v1, p7, 0x30

    .line 25
    .line 26
    move-object/from16 v10, p1

    .line 27
    .line 28
    if-nez v1, :cond_2

    .line 29
    .line 30
    invoke-virtual {v7, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    const/16 v1, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v1, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v1

    .line 42
    :cond_2
    move/from16 v11, p2

    .line 43
    .line 44
    invoke-virtual {v7, v11}, Ll2/t;->d(F)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    const/16 v1, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_3
    const/16 v1, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v1

    .line 56
    move/from16 v12, p3

    .line 57
    .line 58
    invoke-virtual {v7, v12}, Ll2/t;->d(F)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_4

    .line 63
    .line 64
    const/16 v1, 0x800

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    const/16 v1, 0x400

    .line 68
    .line 69
    :goto_3
    or-int/2addr v0, v1

    .line 70
    const/high16 v1, 0x30000

    .line 71
    .line 72
    and-int v2, p7, v1

    .line 73
    .line 74
    move-object/from16 v14, p5

    .line 75
    .line 76
    if-nez v2, :cond_6

    .line 77
    .line 78
    invoke-virtual {v7, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_5

    .line 83
    .line 84
    const/high16 v2, 0x20000

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_5
    const/high16 v2, 0x10000

    .line 88
    .line 89
    :goto_4
    or-int/2addr v0, v2

    .line 90
    :cond_6
    const v2, 0x12493

    .line 91
    .line 92
    .line 93
    and-int/2addr v2, v0

    .line 94
    const v3, 0x12492

    .line 95
    .line 96
    .line 97
    const/4 v13, 0x0

    .line 98
    if-eq v2, v3, :cond_7

    .line 99
    .line 100
    const/4 v2, 0x1

    .line 101
    goto :goto_5

    .line 102
    :cond_7
    move v2, v13

    .line 103
    :goto_5
    and-int/lit8 v3, v0, 0x1

    .line 104
    .line 105
    invoke-virtual {v7, v3, v2}, Ll2/t;->O(IZ)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_a

    .line 110
    .line 111
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v2, v3, :cond_8

    .line 118
    .line 119
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 120
    .line 121
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_8
    move-object v5, v2

    .line 129
    check-cast v5, Ll2/b1;

    .line 130
    .line 131
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    check-cast v2, Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    if-eqz v2, :cond_9

    .line 142
    .line 143
    const v0, -0x4caf9252

    .line 144
    .line 145
    .line 146
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    const/4 v0, 0x0

    .line 150
    const/4 v1, 0x6

    .line 151
    invoke-static {v5, v0, v7, v1}, Llp/ra;->a(Ll2/b1;Lay0/a;Ll2/o;I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    goto :goto_6

    .line 158
    :cond_9
    const v2, -0x4cae3a89

    .line 159
    .line 160
    .line 161
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    and-int/lit8 v2, v0, 0xe

    .line 165
    .line 166
    or-int/2addr v1, v2

    .line 167
    and-int/lit8 v2, v0, 0x70

    .line 168
    .line 169
    or-int/2addr v1, v2

    .line 170
    and-int/lit16 v2, v0, 0x380

    .line 171
    .line 172
    or-int/2addr v1, v2

    .line 173
    and-int/lit16 v2, v0, 0x1c00

    .line 174
    .line 175
    or-int/2addr v1, v2

    .line 176
    or-int/lit16 v1, v1, 0x6000

    .line 177
    .line 178
    shl-int/lit8 v0, v0, 0x3

    .line 179
    .line 180
    const/high16 v2, 0x380000

    .line 181
    .line 182
    and-int/2addr v0, v2

    .line 183
    or-int v8, v1, v0

    .line 184
    .line 185
    move-object/from16 v4, p4

    .line 186
    .line 187
    move-object v0, v9

    .line 188
    move-object v1, v10

    .line 189
    move v2, v11

    .line 190
    move v3, v12

    .line 191
    move-object v6, v14

    .line 192
    invoke-static/range {v0 .. v8}, Llp/sa;->b(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/b1;Ll2/t2;Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    goto :goto_6

    .line 199
    :cond_a
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 200
    .line 201
    .line 202
    :goto_6
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    if-eqz v0, :cond_b

    .line 207
    .line 208
    new-instance v8, Lio0/e;

    .line 209
    .line 210
    move-object/from16 v9, p0

    .line 211
    .line 212
    move-object/from16 v10, p1

    .line 213
    .line 214
    move/from16 v11, p2

    .line 215
    .line 216
    move/from16 v12, p3

    .line 217
    .line 218
    move-object/from16 v13, p4

    .line 219
    .line 220
    move-object/from16 v14, p5

    .line 221
    .line 222
    move/from16 v15, p7

    .line 223
    .line 224
    invoke-direct/range {v8 .. v15}, Lio0/e;-><init>(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/t2;I)V

    .line 225
    .line 226
    .line 227
    iput-object v8, v0, Ll2/u1;->d:Lay0/n;

    .line 228
    .line 229
    :cond_b
    return-void
.end method

.method public static final b(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/b1;Ll2/t2;Ll2/o;I)V
    .locals 29

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v9, p3

    .line 6
    .line 7
    move-object/from16 v10, p6

    .line 8
    .line 9
    const-string v0, "url"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "isPlaying"

    .line 15
    .line 16
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v7, p7

    .line 20
    .line 21
    check-cast v7, Ll2/t;

    .line 22
    .line 23
    const v0, -0x7ffe6eec

    .line 24
    .line 25
    .line 26
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v0, 0x2

    .line 38
    :goto_0
    or-int v0, p8, v0

    .line 39
    .line 40
    and-int/lit8 v3, p8, 0x30

    .line 41
    .line 42
    if-nez v3, :cond_2

    .line 43
    .line 44
    invoke-virtual {v7, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_1

    .line 49
    .line 50
    const/16 v3, 0x20

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    const/16 v3, 0x10

    .line 54
    .line 55
    :goto_1
    or-int/2addr v0, v3

    .line 56
    :cond_2
    move/from16 v13, p2

    .line 57
    .line 58
    invoke-virtual {v7, v13}, Ll2/t;->d(F)Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    if-eqz v3, :cond_3

    .line 63
    .line 64
    const/16 v3, 0x100

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_3
    const/16 v3, 0x80

    .line 68
    .line 69
    :goto_2
    or-int/2addr v0, v3

    .line 70
    invoke-virtual {v7, v9}, Ll2/t;->d(F)Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-eqz v3, :cond_4

    .line 75
    .line 76
    const/16 v3, 0x800

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    const/16 v3, 0x400

    .line 80
    .line 81
    :goto_3
    or-int/2addr v0, v3

    .line 82
    const/high16 v3, 0x180000

    .line 83
    .line 84
    and-int v3, p8, v3

    .line 85
    .line 86
    if-nez v3, :cond_6

    .line 87
    .line 88
    invoke-virtual {v7, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-eqz v3, :cond_5

    .line 93
    .line 94
    const/high16 v3, 0x100000

    .line 95
    .line 96
    goto :goto_4

    .line 97
    :cond_5
    const/high16 v3, 0x80000

    .line 98
    .line 99
    :goto_4
    or-int/2addr v0, v3

    .line 100
    :cond_6
    const v3, 0x92493

    .line 101
    .line 102
    .line 103
    and-int/2addr v3, v0

    .line 104
    const v4, 0x92492

    .line 105
    .line 106
    .line 107
    const/4 v5, 0x0

    .line 108
    const/4 v6, 0x1

    .line 109
    if-eq v3, v4, :cond_7

    .line 110
    .line 111
    move v3, v6

    .line 112
    goto :goto_5

    .line 113
    :cond_7
    move v3, v5

    .line 114
    :goto_5
    and-int/lit8 v4, v0, 0x1

    .line 115
    .line 116
    invoke-virtual {v7, v4, v3}, Ll2/t;->O(IZ)Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-eqz v3, :cond_1e

    .line 121
    .line 122
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 123
    .line 124
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    check-cast v3, Landroid/content/Context;

    .line 129
    .line 130
    invoke-virtual {v3}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 139
    .line 140
    if-ne v4, v8, :cond_8

    .line 141
    .line 142
    new-instance v4, La8/q;

    .line 143
    .line 144
    invoke-direct {v4, v3}, La8/q;-><init>(Landroid/content/Context;)V

    .line 145
    .line 146
    .line 147
    iget-boolean v11, v4, La8/q;->u:Z

    .line 148
    .line 149
    xor-int/2addr v11, v6

    .line 150
    invoke-static {v11}, Lw7/a;->j(Z)V

    .line 151
    .line 152
    .line 153
    iput-boolean v6, v4, La8/q;->u:Z

    .line 154
    .line 155
    new-instance v11, La8/i0;

    .line 156
    .line 157
    invoke-direct {v11, v4}, La8/i0;-><init>(La8/q;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v7, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    move-object v4, v11

    .line 164
    :cond_8
    move-object v11, v4

    .line 165
    check-cast v11, Landroidx/media3/exoplayer/ExoPlayer;

    .line 166
    .line 167
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v4

    .line 174
    if-ne v4, v8, :cond_9

    .line 175
    .line 176
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 177
    .line 178
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    :cond_9
    move-object/from16 v21, v4

    .line 186
    .line 187
    check-cast v21, Ll2/b1;

    .line 188
    .line 189
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    if-ne v4, v8, :cond_a

    .line 194
    .line 195
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 196
    .line 197
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    :cond_a
    check-cast v4, Ll2/b1;

    .line 205
    .line 206
    const-string v6, "audio"

    .line 207
    .line 208
    invoke-virtual {v3, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    instance-of v6, v3, Landroid/media/AudioManager;

    .line 213
    .line 214
    if-eqz v6, :cond_b

    .line 215
    .line 216
    check-cast v3, Landroid/media/AudioManager;

    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_b
    const/4 v3, 0x0

    .line 220
    :goto_6
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 221
    .line 222
    invoke-static {v6, v9}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v22

    .line 226
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v6

    .line 230
    if-ne v6, v8, :cond_c

    .line 231
    .line 232
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    :cond_c
    move-object/from16 v23, v6

    .line 237
    .line 238
    check-cast v23, Li1/l;

    .line 239
    .line 240
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    if-ne v6, v8, :cond_d

    .line 245
    .line 246
    new-instance v6, Lio0/f;

    .line 247
    .line 248
    const/4 v14, 0x0

    .line 249
    invoke-direct {v6, v4, v14}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v7, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    :cond_d
    move-object/from16 v27, v6

    .line 256
    .line 257
    check-cast v27, Lay0/a;

    .line 258
    .line 259
    const/16 v28, 0x1c

    .line 260
    .line 261
    const/16 v24, 0x0

    .line 262
    .line 263
    const/16 v25, 0x0

    .line 264
    .line 265
    const/16 v26, 0x0

    .line 266
    .line 267
    invoke-static/range {v22 .. v28}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 268
    .line 269
    .line 270
    move-result-object v6

    .line 271
    sget-object v14, Lx2/c;->d:Lx2/j;

    .line 272
    .line 273
    invoke-static {v14, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 274
    .line 275
    .line 276
    move-result-object v14

    .line 277
    iget-wide v12, v7, Ll2/t;->T:J

    .line 278
    .line 279
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 280
    .line 281
    .line 282
    move-result v12

    .line 283
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 284
    .line 285
    .line 286
    move-result-object v13

    .line 287
    invoke-static {v7, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    sget-object v20, Lv3/k;->m1:Lv3/j;

    .line 292
    .line 293
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 294
    .line 295
    .line 296
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 297
    .line 298
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 299
    .line 300
    .line 301
    iget-boolean v15, v7, Ll2/t;->S:Z

    .line 302
    .line 303
    if-eqz v15, :cond_e

    .line 304
    .line 305
    invoke-virtual {v7, v5}, Ll2/t;->l(Lay0/a;)V

    .line 306
    .line 307
    .line 308
    goto :goto_7

    .line 309
    :cond_e
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 310
    .line 311
    .line 312
    :goto_7
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 313
    .line 314
    invoke-static {v5, v14, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 315
    .line 316
    .line 317
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 318
    .line 319
    invoke-static {v5, v13, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 320
    .line 321
    .line 322
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 323
    .line 324
    iget-boolean v13, v7, Ll2/t;->S:Z

    .line 325
    .line 326
    if-nez v13, :cond_f

    .line 327
    .line 328
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v13

    .line 332
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 333
    .line 334
    .line 335
    move-result-object v14

    .line 336
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 337
    .line 338
    .line 339
    move-result v13

    .line 340
    if-nez v13, :cond_10

    .line 341
    .line 342
    :cond_f
    invoke-static {v12, v7, v12, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 343
    .line 344
    .line 345
    :cond_10
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 346
    .line 347
    invoke-static {v5, v6, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 348
    .line 349
    .line 350
    sget-object v5, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 351
    .line 352
    invoke-virtual {v7, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    move-result v6

    .line 356
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v12

    .line 360
    if-nez v6, :cond_11

    .line 361
    .line 362
    if-ne v12, v8, :cond_12

    .line 363
    .line 364
    :cond_11
    new-instance v12, Lio0/a;

    .line 365
    .line 366
    const/4 v6, 0x1

    .line 367
    invoke-direct {v12, v11, v6}, Lio0/a;-><init>(Landroidx/media3/exoplayer/ExoPlayer;I)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {v7, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 371
    .line 372
    .line 373
    :cond_12
    check-cast v12, Lay0/k;

    .line 374
    .line 375
    move-object v6, v3

    .line 376
    const/16 v3, 0x30

    .line 377
    .line 378
    move-object v13, v4

    .line 379
    const/4 v4, 0x4

    .line 380
    move-object v14, v6

    .line 381
    const/4 v6, 0x0

    .line 382
    move-object/from16 v16, v8

    .line 383
    .line 384
    move-object v8, v5

    .line 385
    move-object v5, v12

    .line 386
    move-object/from16 v12, v16

    .line 387
    .line 388
    const/16 v16, 0x1

    .line 389
    .line 390
    const/16 v23, 0x0

    .line 391
    .line 392
    invoke-static/range {v3 .. v8}, Landroidx/compose/ui/viewinterop/a;->a(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 393
    .line 394
    .line 395
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v3

    .line 399
    check-cast v3, Ljava/lang/Boolean;

    .line 400
    .line 401
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 402
    .line 403
    .line 404
    move-result v3

    .line 405
    const/4 v4, 0x3

    .line 406
    const/4 v5, 0x0

    .line 407
    invoke-static {v5, v4}, Lb1/o0;->c(Lc1/a0;I)Lb1/t0;

    .line 408
    .line 409
    .line 410
    move-result-object v13

    .line 411
    invoke-static {v5, v4}, Lb1/o0;->d(Lc1/a0;I)Lb1/u0;

    .line 412
    .line 413
    .line 414
    move-result-object v4

    .line 415
    new-instance v5, Li50/j;

    .line 416
    .line 417
    const/4 v6, 0x7

    .line 418
    invoke-direct {v5, v6, v2, v11}, Li50/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 419
    .line 420
    .line 421
    const v6, 0x372eeb76

    .line 422
    .line 423
    .line 424
    invoke-static {v6, v7, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 425
    .line 426
    .line 427
    move-result-object v5

    .line 428
    const/16 v6, 0x100

    .line 429
    .line 430
    const v18, 0x30d80

    .line 431
    .line 432
    .line 433
    const/16 v19, 0x12

    .line 434
    .line 435
    move-object v8, v12

    .line 436
    const/4 v12, 0x0

    .line 437
    const/4 v15, 0x0

    .line 438
    move-object/from16 v16, v5

    .line 439
    .line 440
    move-object/from16 v17, v7

    .line 441
    .line 442
    move-object v5, v8

    .line 443
    move-object v6, v14

    .line 444
    const/4 v7, 0x4

    .line 445
    const/16 v8, 0x20

    .line 446
    .line 447
    move-object v14, v4

    .line 448
    move-object v4, v11

    .line 449
    move v11, v3

    .line 450
    const/high16 v3, 0x100000

    .line 451
    .line 452
    invoke-static/range {v11 .. v19}, Landroidx/compose/animation/b;->d(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 453
    .line 454
    .line 455
    move-object/from16 v11, v17

    .line 456
    .line 457
    const/high16 v12, 0x380000

    .line 458
    .line 459
    and-int/2addr v12, v0

    .line 460
    if-ne v12, v3, :cond_13

    .line 461
    .line 462
    const/4 v3, 0x1

    .line 463
    goto :goto_8

    .line 464
    :cond_13
    move/from16 v3, v23

    .line 465
    .line 466
    :goto_8
    and-int/lit8 v12, v0, 0x70

    .line 467
    .line 468
    if-ne v12, v8, :cond_14

    .line 469
    .line 470
    const/4 v13, 0x1

    .line 471
    goto :goto_9

    .line 472
    :cond_14
    move/from16 v13, v23

    .line 473
    .line 474
    :goto_9
    or-int/2addr v3, v13

    .line 475
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    move-result v13

    .line 479
    or-int/2addr v3, v13

    .line 480
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v13

    .line 484
    if-nez v3, :cond_15

    .line 485
    .line 486
    if-ne v13, v5, :cond_16

    .line 487
    .line 488
    :cond_15
    new-instance v13, Li2/t;

    .line 489
    .line 490
    invoke-direct {v13, v2, v10, v4}, Li2/t;-><init>(Lio0/c;Ll2/t2;Landroidx/media3/exoplayer/ExoPlayer;)V

    .line 491
    .line 492
    .line 493
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 494
    .line 495
    .line 496
    :cond_16
    move-object v14, v13

    .line 497
    check-cast v14, Lay0/a;

    .line 498
    .line 499
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 500
    .line 501
    .line 502
    move-result v3

    .line 503
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v13

    .line 507
    if-nez v3, :cond_17

    .line 508
    .line 509
    if-ne v13, v5, :cond_18

    .line 510
    .line 511
    :cond_17
    new-instance v13, Lio0/d;

    .line 512
    .line 513
    const/4 v3, 0x1

    .line 514
    invoke-direct {v13, v4, v3}, Lio0/d;-><init>(Landroidx/media3/exoplayer/ExoPlayer;I)V

    .line 515
    .line 516
    .line 517
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    :cond_18
    move-object v15, v13

    .line 521
    check-cast v15, Lay0/a;

    .line 522
    .line 523
    const/16 v19, 0x0

    .line 524
    .line 525
    const/16 v20, 0xe7

    .line 526
    .line 527
    move-object/from16 v17, v11

    .line 528
    .line 529
    const/4 v11, 0x0

    .line 530
    move v3, v12

    .line 531
    const/4 v12, 0x0

    .line 532
    const/4 v13, 0x0

    .line 533
    const/16 v16, 0x0

    .line 534
    .line 535
    move-object/from16 v18, v17

    .line 536
    .line 537
    const/16 v17, 0x0

    .line 538
    .line 539
    invoke-static/range {v11 .. v20}, Lxf0/i0;->z(Landroidx/lifecycle/x;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 540
    .line 541
    .line 542
    move-object/from16 v11, v18

    .line 543
    .line 544
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 545
    .line 546
    .line 547
    move-result v12

    .line 548
    and-int/lit8 v13, v0, 0xe

    .line 549
    .line 550
    if-ne v13, v7, :cond_19

    .line 551
    .line 552
    const/4 v7, 0x1

    .line 553
    goto :goto_a

    .line 554
    :cond_19
    move/from16 v7, v23

    .line 555
    .line 556
    :goto_a
    or-int/2addr v7, v12

    .line 557
    if-ne v3, v8, :cond_1a

    .line 558
    .line 559
    const/4 v3, 0x1

    .line 560
    goto :goto_b

    .line 561
    :cond_1a
    move/from16 v3, v23

    .line 562
    .line 563
    :goto_b
    or-int/2addr v3, v7

    .line 564
    and-int/lit16 v0, v0, 0x380

    .line 565
    .line 566
    const/16 v7, 0x100

    .line 567
    .line 568
    if-ne v0, v7, :cond_1b

    .line 569
    .line 570
    const/16 v23, 0x1

    .line 571
    .line 572
    :cond_1b
    or-int v0, v3, v23

    .line 573
    .line 574
    invoke-virtual {v11, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 575
    .line 576
    .line 577
    move-result v3

    .line 578
    or-int/2addr v0, v3

    .line 579
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v3

    .line 583
    if-nez v0, :cond_1c

    .line 584
    .line 585
    if-ne v3, v5, :cond_1d

    .line 586
    .line 587
    :cond_1c
    new-instance v0, Lc1/i1;

    .line 588
    .line 589
    move-object/from16 v5, p4

    .line 590
    .line 591
    move-object/from16 v8, p5

    .line 592
    .line 593
    move-object v3, v1

    .line 594
    move-object v1, v4

    .line 595
    move-object v4, v6

    .line 596
    move-object/from16 v7, v21

    .line 597
    .line 598
    move/from16 v6, p2

    .line 599
    .line 600
    invoke-direct/range {v0 .. v8}, Lc1/i1;-><init>(Landroidx/media3/exoplayer/ExoPlayer;Lio0/c;Ljava/lang/String;Landroid/media/AudioManager;Ll2/f1;FLl2/b1;Ll2/b1;)V

    .line 601
    .line 602
    .line 603
    move-object v1, v3

    .line 604
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 605
    .line 606
    .line 607
    move-object v3, v0

    .line 608
    :cond_1d
    check-cast v3, Lay0/k;

    .line 609
    .line 610
    invoke-static {v1, v3, v11}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 611
    .line 612
    .line 613
    const/4 v0, 0x1

    .line 614
    invoke-virtual {v11, v0}, Ll2/t;->q(Z)V

    .line 615
    .line 616
    .line 617
    goto :goto_c

    .line 618
    :cond_1e
    move-object v11, v7

    .line 619
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 620
    .line 621
    .line 622
    :goto_c
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 623
    .line 624
    .line 625
    move-result-object v11

    .line 626
    if-eqz v11, :cond_1f

    .line 627
    .line 628
    new-instance v0, Lio0/g;

    .line 629
    .line 630
    move-object/from16 v2, p1

    .line 631
    .line 632
    move/from16 v3, p2

    .line 633
    .line 634
    move-object/from16 v5, p4

    .line 635
    .line 636
    move-object/from16 v6, p5

    .line 637
    .line 638
    move/from16 v8, p8

    .line 639
    .line 640
    move v4, v9

    .line 641
    move-object v7, v10

    .line 642
    invoke-direct/range {v0 .. v8}, Lio0/g;-><init>(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/b1;Ll2/t2;I)V

    .line 643
    .line 644
    .line 645
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 646
    .line 647
    :cond_1f
    return-void
.end method

.method public static final c(Ljava/lang/String;Ll2/t2;Lio0/c;Ll2/o;I)V
    .locals 9

    .line 1
    const-string v1, "url"

    .line 2
    .line 3
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v1, "isPlaying"

    .line 7
    .line 8
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v6, p3

    .line 12
    check-cast v6, Ll2/t;

    .line 13
    .line 14
    const v1, -0x62bac6e5

    .line 15
    .line 16
    .line 17
    invoke-virtual {v6, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v1, 0x2

    .line 29
    :goto_0
    or-int/2addr v1, p4

    .line 30
    invoke-virtual {v6, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    const/16 v2, 0x100

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v2, 0x80

    .line 40
    .line 41
    :goto_1
    or-int/2addr v1, v2

    .line 42
    and-int/lit16 v2, v1, 0x93

    .line 43
    .line 44
    const/16 v3, 0x92

    .line 45
    .line 46
    if-eq v2, v3, :cond_2

    .line 47
    .line 48
    const/4 v2, 0x1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/4 v2, 0x0

    .line 51
    :goto_2
    and-int/lit8 v3, v1, 0x1

    .line 52
    .line 53
    invoke-virtual {v6, v3, v2}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_5

    .line 58
    .line 59
    sget-object v2, Lw3/h1;->t:Ll2/u2;

    .line 60
    .line 61
    invoke-virtual {v6, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Lw3/j2;

    .line 66
    .line 67
    check-cast v2, Lw3/r1;

    .line 68
    .line 69
    invoke-virtual {v2}, Lw3/r1;->a()J

    .line 70
    .line 71
    .line 72
    move-result-wide v2

    .line 73
    const/16 v7, 0x20

    .line 74
    .line 75
    shr-long/2addr v2, v7

    .line 76
    long-to-int v2, v2

    .line 77
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-static {v2}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 86
    .line 87
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    check-cast v3, Lj91/c;

    .line 92
    .line 93
    iget v3, v3, Lj91/c;->f:F

    .line 94
    .line 95
    sub-float/2addr v2, v3

    .line 96
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 101
    .line 102
    if-ne v3, v7, :cond_3

    .line 103
    .line 104
    new-instance v3, Ll2/f1;

    .line 105
    .line 106
    invoke-direct {v3, v2}, Ll2/f1;-><init>(F)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_3
    check-cast v3, Ll2/f1;

    .line 113
    .line 114
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    cmpg-float v7, v7, v2

    .line 119
    .line 120
    if-nez v7, :cond_4

    .line 121
    .line 122
    move v7, v2

    .line 123
    goto :goto_3

    .line 124
    :cond_4
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    :goto_3
    and-int/lit8 v8, v1, 0xe

    .line 129
    .line 130
    or-int/lit16 v8, v8, 0x6000

    .line 131
    .line 132
    shr-int/lit8 v1, v1, 0x3

    .line 133
    .line 134
    and-int/lit8 v1, v1, 0x70

    .line 135
    .line 136
    or-int/2addr v1, v8

    .line 137
    const/high16 v8, 0x30000

    .line 138
    .line 139
    or-int/2addr v1, v8

    .line 140
    move-object v0, p0

    .line 141
    move-object v5, p1

    .line 142
    move-object v4, v3

    .line 143
    move v3, v7

    .line 144
    move v7, v1

    .line 145
    move-object v1, p2

    .line 146
    invoke-static/range {v0 .. v7}, Llp/sa;->a(Ljava/lang/String;Lio0/c;FFLl2/f1;Ll2/t2;Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_5
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 151
    .line 152
    .line 153
    :goto_4
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    if-eqz v6, :cond_6

    .line 158
    .line 159
    new-instance v0, Li91/k3;

    .line 160
    .line 161
    const/4 v2, 0x2

    .line 162
    move-object v3, p0

    .line 163
    move-object v4, p1

    .line 164
    move-object v5, p2

    .line 165
    move v1, p4

    .line 166
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 170
    .line 171
    :cond_6
    return-void
.end method
