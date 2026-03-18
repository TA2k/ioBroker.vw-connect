.class public abstract Ljp/qf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Llh/g;Lay0/k;Ll2/o;I)V
    .locals 12

    .line 1
    move/from16 v1, p4

    .line 2
    .line 3
    move-object v0, p3

    .line 4
    check-cast v0, Ll2/t;

    .line 5
    .line 6
    const v2, 0x29e93b08

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 10
    .line 11
    .line 12
    and-int/lit8 v2, v1, 0x6

    .line 13
    .line 14
    if-nez v2, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    const/4 v2, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v2, 0x2

    .line 25
    :goto_0
    or-int/2addr v2, v1

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move v2, v1

    .line 28
    :goto_1
    and-int/lit8 v5, v1, 0x30

    .line 29
    .line 30
    const/16 v6, 0x20

    .line 31
    .line 32
    if-nez v5, :cond_3

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    move v5, v6

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v5, 0x10

    .line 43
    .line 44
    :goto_2
    or-int/2addr v2, v5

    .line 45
    :cond_3
    and-int/lit16 v5, v1, 0x180

    .line 46
    .line 47
    const/16 v7, 0x100

    .line 48
    .line 49
    if-nez v5, :cond_5

    .line 50
    .line 51
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v8

    .line 55
    if-eqz v8, :cond_4

    .line 56
    .line 57
    move v8, v7

    .line 58
    goto :goto_3

    .line 59
    :cond_4
    const/16 v8, 0x80

    .line 60
    .line 61
    :goto_3
    or-int/2addr v2, v8

    .line 62
    :cond_5
    and-int/lit16 v8, v2, 0x93

    .line 63
    .line 64
    const/16 v9, 0x92

    .line 65
    .line 66
    const/4 v10, 0x0

    .line 67
    const/4 v11, 0x1

    .line 68
    if-eq v8, v9, :cond_6

    .line 69
    .line 70
    move v8, v11

    .line 71
    goto :goto_4

    .line 72
    :cond_6
    move v8, v10

    .line 73
    :goto_4
    and-int/lit8 v9, v2, 0x1

    .line 74
    .line 75
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 76
    .line 77
    .line 78
    move-result v8

    .line 79
    if-eqz v8, :cond_b

    .line 80
    .line 81
    invoke-static {p0, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    and-int/lit8 v9, v2, 0x70

    .line 86
    .line 87
    if-ne v9, v6, :cond_7

    .line 88
    .line 89
    move v6, v11

    .line 90
    goto :goto_5

    .line 91
    :cond_7
    move v6, v10

    .line 92
    :goto_5
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    or-int/2addr v6, v9

    .line 97
    and-int/lit16 v2, v2, 0x380

    .line 98
    .line 99
    if-ne v2, v7, :cond_8

    .line 100
    .line 101
    move v10, v11

    .line 102
    :cond_8
    or-int v2, v6, v10

    .line 103
    .line 104
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    if-nez v2, :cond_a

    .line 109
    .line 110
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 111
    .line 112
    if-ne v6, v2, :cond_9

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_9
    move-object v4, v6

    .line 116
    goto :goto_7

    .line 117
    :cond_a
    :goto_6
    new-instance v4, Lqh/a;

    .line 118
    .line 119
    const/4 v9, 0x0

    .line 120
    const/4 v5, 0x0

    .line 121
    move-object v6, p1

    .line 122
    move-object v7, p2

    .line 123
    invoke-direct/range {v4 .. v9}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    :goto_7
    check-cast v4, Lay0/n;

    .line 130
    .line 131
    invoke-static {v4, p1, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 132
    .line 133
    .line 134
    goto :goto_8

    .line 135
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    if-eqz v7, :cond_c

    .line 143
    .line 144
    new-instance v0, Lph/a;

    .line 145
    .line 146
    const/4 v2, 0x1

    .line 147
    move-object v3, p0

    .line 148
    move-object v4, p1

    .line 149
    move-object v5, p2

    .line 150
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 154
    .line 155
    :cond_c
    return-void
.end method

.method public static final b(Ldi/b;Lay0/a;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "goToAutomaticUpdate"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p2

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v3, -0x7862059c

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x4

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    move v3, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v3, 0x2

    .line 32
    :goto_0
    or-int/2addr v3, v2

    .line 33
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    const/16 v5, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v5, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v3, v5

    .line 45
    and-int/lit8 v5, v3, 0x13

    .line 46
    .line 47
    const/16 v6, 0x12

    .line 48
    .line 49
    const/4 v7, 0x1

    .line 50
    const/4 v10, 0x0

    .line 51
    if-eq v5, v6, :cond_2

    .line 52
    .line 53
    move v5, v7

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v5, v10

    .line 56
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 57
    .line 58
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_d

    .line 63
    .line 64
    and-int/lit8 v5, v3, 0xe

    .line 65
    .line 66
    if-ne v5, v4, :cond_3

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v7, v10

    .line 70
    :goto_3
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-nez v7, :cond_4

    .line 77
    .line 78
    if-ne v4, v11, :cond_5

    .line 79
    .line 80
    :cond_4
    new-instance v4, Llh/a;

    .line 81
    .line 82
    const/4 v5, 0x1

    .line 83
    invoke-direct {v4, v0, v5}, Llh/a;-><init>(Ldi/b;I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_5
    check-cast v4, Lay0/k;

    .line 90
    .line 91
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 92
    .line 93
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    check-cast v5, Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    if-eqz v5, :cond_6

    .line 104
    .line 105
    const v5, -0x105bcaaa

    .line 106
    .line 107
    .line 108
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 112
    .line 113
    .line 114
    const/4 v5, 0x0

    .line 115
    goto :goto_4

    .line 116
    :cond_6
    const v5, 0x31054eee

    .line 117
    .line 118
    .line 119
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 120
    .line 121
    .line 122
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 123
    .line 124
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    check-cast v5, Lhi/a;

    .line 129
    .line 130
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 131
    .line 132
    .line 133
    :goto_4
    new-instance v7, Lnd/e;

    .line 134
    .line 135
    const/16 v6, 0xc

    .line 136
    .line 137
    invoke-direct {v7, v5, v4, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 138
    .line 139
    .line 140
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    if-eqz v5, :cond_c

    .line 145
    .line 146
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 147
    .line 148
    if-eqz v4, :cond_7

    .line 149
    .line 150
    move-object v4, v5

    .line 151
    check-cast v4, Landroidx/lifecycle/k;

    .line 152
    .line 153
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    :goto_5
    move-object v8, v4

    .line 158
    goto :goto_6

    .line 159
    :cond_7
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :goto_6
    const-class v4, Llh/h;

    .line 163
    .line 164
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 165
    .line 166
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    const/4 v6, 0x0

    .line 171
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    move-object v14, v4

    .line 176
    check-cast v14, Llh/h;

    .line 177
    .line 178
    iget-object v4, v14, Llh/h;->f:Lyy0/l1;

    .line 179
    .line 180
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    check-cast v5, Llh/g;

    .line 189
    .line 190
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v7

    .line 198
    if-nez v6, :cond_8

    .line 199
    .line 200
    if-ne v7, v11, :cond_9

    .line 201
    .line 202
    :cond_8
    new-instance v12, Lo90/f;

    .line 203
    .line 204
    const/16 v18, 0x0

    .line 205
    .line 206
    const/16 v19, 0xb

    .line 207
    .line 208
    const/4 v13, 0x1

    .line 209
    const-class v15, Llh/h;

    .line 210
    .line 211
    const-string v16, "onUiEvent"

    .line 212
    .line 213
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/name/WallboxChangeNameUiEvent;)V"

    .line 214
    .line 215
    invoke-direct/range {v12 .. v19}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    move-object v7, v12

    .line 222
    :cond_9
    check-cast v7, Lhy0/g;

    .line 223
    .line 224
    check-cast v7, Lay0/k;

    .line 225
    .line 226
    shr-int/lit8 v3, v3, 0x3

    .line 227
    .line 228
    and-int/lit8 v3, v3, 0xe

    .line 229
    .line 230
    invoke-static {v1, v5, v7, v9, v3}, Ljp/qf;->a(Lay0/a;Llh/g;Lay0/k;Ll2/o;I)V

    .line 231
    .line 232
    .line 233
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v4

    .line 241
    check-cast v4, Llh/g;

    .line 242
    .line 243
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v5

    .line 247
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v6

    .line 251
    if-nez v5, :cond_a

    .line 252
    .line 253
    if-ne v6, v11, :cond_b

    .line 254
    .line 255
    :cond_a
    new-instance v12, Lo90/f;

    .line 256
    .line 257
    const/16 v18, 0x0

    .line 258
    .line 259
    const/16 v19, 0xc

    .line 260
    .line 261
    const/4 v13, 0x1

    .line 262
    const-class v15, Llh/h;

    .line 263
    .line 264
    const-string v16, "onUiEvent"

    .line 265
    .line 266
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/name/WallboxChangeNameUiEvent;)V"

    .line 267
    .line 268
    invoke-direct/range {v12 .. v19}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    move-object v6, v12

    .line 275
    :cond_b
    check-cast v6, Lhy0/g;

    .line 276
    .line 277
    check-cast v6, Lay0/k;

    .line 278
    .line 279
    invoke-interface {v3, v4, v6, v9, v10}, Leh/n;->P(Llh/g;Lay0/k;Ll2/o;I)V

    .line 280
    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 284
    .line 285
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 286
    .line 287
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    throw v0

    .line 291
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 292
    .line 293
    .line 294
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 295
    .line 296
    .line 297
    move-result-object v3

    .line 298
    if-eqz v3, :cond_e

    .line 299
    .line 300
    new-instance v4, Lo50/b;

    .line 301
    .line 302
    const/4 v5, 0x7

    .line 303
    invoke-direct {v4, v0, v1, v2, v5}, Lo50/b;-><init>(Ljava/lang/Object;Lay0/a;II)V

    .line 304
    .line 305
    .line 306
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 307
    .line 308
    :cond_e
    return-void
.end method

.method public static c(I)I
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, v0, :cond_9

    .line 3
    .line 4
    const/4 v1, 0x2

    .line 5
    if-eq p0, v1, :cond_8

    .line 6
    .line 7
    const/4 v0, 0x4

    .line 8
    if-eq p0, v0, :cond_7

    .line 9
    .line 10
    const/16 v1, 0x8

    .line 11
    .line 12
    if-eq p0, v1, :cond_6

    .line 13
    .line 14
    const/16 v2, 0x10

    .line 15
    .line 16
    if-eq p0, v2, :cond_5

    .line 17
    .line 18
    const/16 v0, 0x20

    .line 19
    .line 20
    if-eq p0, v0, :cond_4

    .line 21
    .line 22
    const/16 v0, 0x40

    .line 23
    .line 24
    if-eq p0, v0, :cond_3

    .line 25
    .line 26
    const/16 v0, 0x80

    .line 27
    .line 28
    if-eq p0, v0, :cond_2

    .line 29
    .line 30
    const/16 v0, 0x100

    .line 31
    .line 32
    if-eq p0, v0, :cond_1

    .line 33
    .line 34
    const/16 v0, 0x200

    .line 35
    .line 36
    if-ne p0, v0, :cond_0

    .line 37
    .line 38
    const/16 p0, 0x9

    .line 39
    .line 40
    return p0

    .line 41
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    const-string v1, "type needs to be >= FIRST and <= LAST, type="

    .line 44
    .line 45
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v0

    .line 53
    :cond_1
    return v1

    .line 54
    :cond_2
    const/4 p0, 0x7

    .line 55
    return p0

    .line 56
    :cond_3
    const/4 p0, 0x6

    .line 57
    return p0

    .line 58
    :cond_4
    const/4 p0, 0x5

    .line 59
    return p0

    .line 60
    :cond_5
    return v0

    .line 61
    :cond_6
    const/4 p0, 0x3

    .line 62
    return p0

    .line 63
    :cond_7
    return v1

    .line 64
    :cond_8
    return v0

    .line 65
    :cond_9
    const/4 p0, 0x0

    .line 66
    return p0
.end method
