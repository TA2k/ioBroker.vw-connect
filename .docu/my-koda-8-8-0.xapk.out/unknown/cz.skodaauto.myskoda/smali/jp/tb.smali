.class public abstract Ljp/tb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ZLay0/a;Ll2/o;II)V
    .locals 10

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x158b58d6

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x1

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    or-int/lit8 v2, p3, 0x6

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    and-int/lit8 v2, p3, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_2

    .line 20
    .line 21
    invoke-virtual {p2, p0}, Ll2/t;->h(Z)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    move v2, v1

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 v2, 0x2

    .line 30
    :goto_0
    or-int/2addr v2, p3

    .line 31
    goto :goto_1

    .line 32
    :cond_2
    move v2, p3

    .line 33
    :goto_1
    and-int/lit8 v3, p3, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_4

    .line 36
    .line 37
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_3

    .line 42
    .line 43
    const/16 v3, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    const/16 v3, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr v2, v3

    .line 49
    :cond_4
    and-int/lit8 v3, v2, 0x13

    .line 50
    .line 51
    const/16 v4, 0x12

    .line 52
    .line 53
    if-ne v3, v4, :cond_6

    .line 54
    .line 55
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-nez v3, :cond_5

    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    :goto_3
    move v5, p0

    .line 66
    goto/16 :goto_6

    .line 67
    .line 68
    :cond_6
    :goto_4
    const/4 v3, 0x1

    .line 69
    if-eqz v0, :cond_7

    .line 70
    .line 71
    move p0, v3

    .line 72
    :cond_7
    invoke-static {p1, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 81
    .line 82
    if-ne v4, v5, :cond_8

    .line 83
    .line 84
    new-instance v4, Lc/f;

    .line 85
    .line 86
    invoke-direct {v4, v0, p0}, Lc/f;-><init>(Ll2/b1;Z)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    :cond_8
    check-cast v4, Lc/f;

    .line 93
    .line 94
    invoke-virtual {p2, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    and-int/lit8 v2, v2, 0xe

    .line 99
    .line 100
    if-ne v2, v1, :cond_9

    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_9
    const/4 v3, 0x0

    .line 104
    :goto_5
    or-int/2addr v0, v3

    .line 105
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    if-nez v0, :cond_a

    .line 110
    .line 111
    if-ne v1, v5, :cond_b

    .line 112
    .line 113
    :cond_a
    new-instance v1, Lc/d;

    .line 114
    .line 115
    const/4 v0, 0x0

    .line 116
    invoke-direct {v1, v4, p0, v0}, Lc/d;-><init>(Ljava/lang/Object;ZI)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_b
    check-cast v1, Lay0/a;

    .line 123
    .line 124
    invoke-static {v1, p2}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    invoke-static {p2}, Lc/j;->a(Ll2/o;)Lb/j0;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-eqz v0, :cond_f

    .line 132
    .line 133
    invoke-interface {v0}, Lb/j0;->getOnBackPressedDispatcher()Lb/h0;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Ll2/s1;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    check-cast v1, Landroidx/lifecycle/x;

    .line 146
    .line 147
    invoke-virtual {p2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v2

    .line 151
    invoke-virtual {p2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v3

    .line 155
    or-int/2addr v2, v3

    .line 156
    invoke-virtual {p2, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    or-int/2addr v2, v3

    .line 161
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    if-nez v2, :cond_c

    .line 166
    .line 167
    if-ne v3, v5, :cond_d

    .line 168
    .line 169
    :cond_c
    new-instance v3, Laa/o;

    .line 170
    .line 171
    const/4 v2, 0x3

    .line 172
    invoke-direct {v3, v0, v1, v4, v2}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_d
    check-cast v3, Lay0/k;

    .line 179
    .line 180
    invoke-static {v1, v0, v3, p2}, Ll2/l0;->b(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 181
    .line 182
    .line 183
    goto :goto_3

    .line 184
    :goto_6
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    if-eqz p0, :cond_e

    .line 189
    .line 190
    new-instance v4, Lc/e;

    .line 191
    .line 192
    const/4 v9, 0x0

    .line 193
    move-object v6, p1

    .line 194
    move v7, p3

    .line 195
    move v8, p4

    .line 196
    invoke-direct/range {v4 .. v9}, Lc/e;-><init>(ZLay0/a;III)V

    .line 197
    .line 198
    .line 199
    iput-object v4, p0, Ll2/u1;->d:Lay0/n;

    .line 200
    .line 201
    :cond_e
    return-void

    .line 202
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    const-string p1, "No OnBackPressedDispatcherOwner was provided via LocalOnBackPressedDispatcherOwner"

    .line 205
    .line 206
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    throw p0
.end method

.method public static final b(Lac/a0;Lxh/e;Lac/e;Log/i;Ljava/util/List;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v5, p4

    .line 4
    .line 5
    move/from16 v7, p6

    .line 6
    .line 7
    const-string v0, "userLegalCountry"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "availableShippingCountries"

    .line 13
    .line 14
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v8, p5

    .line 18
    .line 19
    check-cast v8, Ll2/t;

    .line 20
    .line 21
    const v0, -0x53364c7f

    .line 22
    .line 23
    .line 24
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v2, 0x4

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    move v0, v2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr v0, v7

    .line 38
    move-object/from16 v3, p1

    .line 39
    .line 40
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    const/16 v6, 0x20

    .line 45
    .line 46
    if-eqz v4, :cond_1

    .line 47
    .line 48
    move v4, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    const/16 v4, 0x10

    .line 51
    .line 52
    :goto_1
    or-int/2addr v0, v4

    .line 53
    and-int/lit16 v4, v7, 0x180

    .line 54
    .line 55
    const/16 v9, 0x100

    .line 56
    .line 57
    if-nez v4, :cond_3

    .line 58
    .line 59
    move-object/from16 v4, p2

    .line 60
    .line 61
    invoke-virtual {v8, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v10

    .line 65
    if-eqz v10, :cond_2

    .line 66
    .line 67
    move v10, v9

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    const/16 v10, 0x80

    .line 70
    .line 71
    :goto_2
    or-int/2addr v0, v10

    .line 72
    goto :goto_3

    .line 73
    :cond_3
    move-object/from16 v4, p2

    .line 74
    .line 75
    :goto_3
    and-int/lit16 v10, v7, 0xc00

    .line 76
    .line 77
    const/16 v11, 0x800

    .line 78
    .line 79
    if-nez v10, :cond_6

    .line 80
    .line 81
    if-nez p3, :cond_4

    .line 82
    .line 83
    const/4 v10, -0x1

    .line 84
    goto :goto_4

    .line 85
    :cond_4
    invoke-virtual/range {p3 .. p3}, Ljava/lang/Enum;->ordinal()I

    .line 86
    .line 87
    .line 88
    move-result v10

    .line 89
    :goto_4
    invoke-virtual {v8, v10}, Ll2/t;->e(I)Z

    .line 90
    .line 91
    .line 92
    move-result v10

    .line 93
    if-eqz v10, :cond_5

    .line 94
    .line 95
    move v10, v11

    .line 96
    goto :goto_5

    .line 97
    :cond_5
    const/16 v10, 0x400

    .line 98
    .line 99
    :goto_5
    or-int/2addr v0, v10

    .line 100
    :cond_6
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v10

    .line 104
    if-eqz v10, :cond_7

    .line 105
    .line 106
    const/16 v10, 0x4000

    .line 107
    .line 108
    goto :goto_6

    .line 109
    :cond_7
    const/16 v10, 0x2000

    .line 110
    .line 111
    :goto_6
    or-int/2addr v0, v10

    .line 112
    and-int/lit16 v10, v0, 0x2493

    .line 113
    .line 114
    const/16 v12, 0x2492

    .line 115
    .line 116
    const/4 v13, 0x1

    .line 117
    const/4 v14, 0x0

    .line 118
    if-eq v10, v12, :cond_8

    .line 119
    .line 120
    move v10, v13

    .line 121
    goto :goto_7

    .line 122
    :cond_8
    move v10, v14

    .line 123
    :goto_7
    and-int/lit8 v12, v0, 0x1

    .line 124
    .line 125
    invoke-virtual {v8, v12, v10}, Ll2/t;->O(IZ)Z

    .line 126
    .line 127
    .line 128
    move-result v10

    .line 129
    if-eqz v10, :cond_15

    .line 130
    .line 131
    and-int/lit8 v10, v0, 0xe

    .line 132
    .line 133
    if-eq v10, v2, :cond_a

    .line 134
    .line 135
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    if-eqz v2, :cond_9

    .line 140
    .line 141
    goto :goto_8

    .line 142
    :cond_9
    move v2, v14

    .line 143
    goto :goto_9

    .line 144
    :cond_a
    :goto_8
    move v2, v13

    .line 145
    :goto_9
    and-int/lit8 v10, v0, 0x70

    .line 146
    .line 147
    if-ne v10, v6, :cond_b

    .line 148
    .line 149
    move v6, v13

    .line 150
    goto :goto_a

    .line 151
    :cond_b
    move v6, v14

    .line 152
    :goto_a
    or-int/2addr v2, v6

    .line 153
    and-int/lit16 v6, v0, 0x380

    .line 154
    .line 155
    if-eq v6, v9, :cond_c

    .line 156
    .line 157
    move v6, v14

    .line 158
    goto :goto_b

    .line 159
    :cond_c
    move v6, v13

    .line 160
    :goto_b
    or-int/2addr v2, v6

    .line 161
    and-int/lit16 v0, v0, 0x1c00

    .line 162
    .line 163
    if-ne v0, v11, :cond_d

    .line 164
    .line 165
    goto :goto_c

    .line 166
    :cond_d
    move v13, v14

    .line 167
    :goto_c
    or-int v0, v2, v13

    .line 168
    .line 169
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    or-int/2addr v0, v2

    .line 174
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 179
    .line 180
    if-nez v0, :cond_e

    .line 181
    .line 182
    if-ne v2, v9, :cond_f

    .line 183
    .line 184
    :cond_e
    new-instance v0, Lc/b;

    .line 185
    .line 186
    const/4 v6, 0x6

    .line 187
    move-object v2, v3

    .line 188
    move-object v3, v4

    .line 189
    move-object/from16 v4, p3

    .line 190
    .line 191
    invoke-direct/range {v0 .. v6}, Lc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    move-object v2, v0

    .line 198
    :cond_f
    check-cast v2, Lay0/k;

    .line 199
    .line 200
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 201
    .line 202
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    check-cast v0, Ljava/lang/Boolean;

    .line 207
    .line 208
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    if-eqz v0, :cond_10

    .line 213
    .line 214
    const v0, -0x105bcaaa

    .line 215
    .line 216
    .line 217
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v8, v14}, Ll2/t;->q(Z)V

    .line 221
    .line 222
    .line 223
    const/4 v0, 0x0

    .line 224
    goto :goto_d

    .line 225
    :cond_10
    const v0, 0x31054eee

    .line 226
    .line 227
    .line 228
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 229
    .line 230
    .line 231
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 232
    .line 233
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    check-cast v0, Lhi/a;

    .line 238
    .line 239
    invoke-virtual {v8, v14}, Ll2/t;->q(Z)V

    .line 240
    .line 241
    .line 242
    :goto_d
    new-instance v4, Lnd/e;

    .line 243
    .line 244
    const/4 v1, 0x5

    .line 245
    invoke-direct {v4, v0, v2, v1}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 246
    .line 247
    .line 248
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    if-eqz v2, :cond_14

    .line 253
    .line 254
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 255
    .line 256
    if-eqz v0, :cond_11

    .line 257
    .line 258
    move-object v0, v2

    .line 259
    check-cast v0, Landroidx/lifecycle/k;

    .line 260
    .line 261
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    :goto_e
    move-object v5, v0

    .line 266
    goto :goto_f

    .line 267
    :cond_11
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 268
    .line 269
    goto :goto_e

    .line 270
    :goto_f
    const-class v0, Log/h;

    .line 271
    .line 272
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 273
    .line 274
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    const/4 v3, 0x0

    .line 279
    move-object v6, v8

    .line 280
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    move-object v12, v0

    .line 285
    check-cast v12, Log/h;

    .line 286
    .line 287
    invoke-static {v6}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    iget-object v1, v12, Log/h;->h:Lyy0/l1;

    .line 292
    .line 293
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 294
    .line 295
    .line 296
    move-result-object v1

    .line 297
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    check-cast v1, Log/f;

    .line 302
    .line 303
    invoke-virtual {v6, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    move-result v2

    .line 307
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v3

    .line 311
    if-nez v2, :cond_12

    .line 312
    .line 313
    if-ne v3, v9, :cond_13

    .line 314
    .line 315
    :cond_12
    new-instance v10, Lo90/f;

    .line 316
    .line 317
    const/16 v16, 0x0

    .line 318
    .line 319
    const/16 v17, 0x4

    .line 320
    .line 321
    const/4 v11, 0x1

    .line 322
    const-class v13, Log/h;

    .line 323
    .line 324
    const-string v14, "onUiEvent"

    .line 325
    .line 326
    const-string v15, "onUiEvent$kitten_subscription_release(Lcariad/charging/multicharge/kitten/subscription/presentation/carddeliveryaddress/CardDeliveryAddressUiEvent;)V"

    .line 327
    .line 328
    invoke-direct/range {v10 .. v17}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v6, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    move-object v3, v10

    .line 335
    :cond_13
    check-cast v3, Lhy0/g;

    .line 336
    .line 337
    check-cast v3, Lay0/k;

    .line 338
    .line 339
    sget-object v2, Lac/x;->v:Lac/x;

    .line 340
    .line 341
    const/16 v2, 0x8

    .line 342
    .line 343
    invoke-interface {v0, v1, v3, v6, v2}, Lmg/k;->C0(Log/f;Lay0/k;Ll2/o;I)V

    .line 344
    .line 345
    .line 346
    goto :goto_10

    .line 347
    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 348
    .line 349
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 350
    .line 351
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    throw v0

    .line 355
    :cond_15
    move-object v6, v8

    .line 356
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 357
    .line 358
    .line 359
    :goto_10
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 360
    .line 361
    .line 362
    move-result-object v8

    .line 363
    if-eqz v8, :cond_16

    .line 364
    .line 365
    new-instance v0, La71/c0;

    .line 366
    .line 367
    const/16 v7, 0x14

    .line 368
    .line 369
    move-object/from16 v1, p0

    .line 370
    .line 371
    move-object/from16 v2, p1

    .line 372
    .line 373
    move-object/from16 v3, p2

    .line 374
    .line 375
    move-object/from16 v4, p3

    .line 376
    .line 377
    move-object/from16 v5, p4

    .line 378
    .line 379
    move/from16 v6, p6

    .line 380
    .line 381
    invoke-direct/range {v0 .. v7}, La71/c0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 382
    .line 383
    .line 384
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 385
    .line 386
    :cond_16
    return-void
.end method
