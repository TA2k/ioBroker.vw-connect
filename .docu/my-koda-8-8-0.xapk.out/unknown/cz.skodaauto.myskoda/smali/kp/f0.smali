.class public abstract Lkp/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;Lay0/a;Lrh/s;Ll2/o;I)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x42cbafda

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 42
    .line 43
    if-nez v1, :cond_5

    .line 44
    .line 45
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    const/16 v1, 0x100

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_4
    const/16 v1, 0x80

    .line 55
    .line 56
    :goto_3
    or-int/2addr v0, v1

    .line 57
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 58
    .line 59
    const/16 v2, 0x92

    .line 60
    .line 61
    const/4 v3, 0x1

    .line 62
    if-eq v1, v2, :cond_6

    .line 63
    .line 64
    move v1, v3

    .line 65
    goto :goto_4

    .line 66
    :cond_6
    const/4 v1, 0x0

    .line 67
    :goto_4
    and-int/2addr v0, v3

    .line 68
    invoke-virtual {p3, v0, v1}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_9

    .line 73
    .line 74
    invoke-static {p0, p3}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    invoke-static {p1, p3}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 83
    .line 84
    invoke-virtual {p3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Landroid/content/Context;

    .line 89
    .line 90
    const-class v1, Landroid/os/Vibrator;

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    move-object v3, v0

    .line 97
    check-cast v3, Landroid/os/Vibrator;

    .line 98
    .line 99
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    invoke-virtual {p3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    or-int/2addr v0, v1

    .line 108
    invoke-virtual {p3, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    or-int/2addr v0, v1

    .line 113
    invoke-virtual {p3, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    or-int/2addr v0, v1

    .line 118
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    if-nez v0, :cond_8

    .line 123
    .line 124
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 125
    .line 126
    if-ne v1, v0, :cond_7

    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_7
    move-object v2, p2

    .line 130
    goto :goto_6

    .line 131
    :cond_8
    :goto_5
    new-instance v1, Lff/a;

    .line 132
    .line 133
    const/4 v6, 0x0

    .line 134
    const/16 v7, 0x8

    .line 135
    .line 136
    move-object v2, p2

    .line 137
    invoke-direct/range {v1 .. v7}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :goto_6
    check-cast v1, Lay0/n;

    .line 144
    .line 145
    invoke-static {v1, v2, p3}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    goto :goto_7

    .line 149
    :cond_9
    move-object v2, p2

    .line 150
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 151
    .line 152
    .line 153
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    if-eqz p2, :cond_a

    .line 158
    .line 159
    new-instance p3, Lph/a;

    .line 160
    .line 161
    invoke-direct {p3, p0, p1, v2, p4}, Lph/a;-><init>(Lay0/k;Lay0/a;Lrh/s;I)V

    .line 162
    .line 163
    .line 164
    iput-object p3, p2, Ll2/u1;->d:Lay0/n;

    .line 165
    .line 166
    :cond_a
    return-void
.end method

.method public static final b(ZLay0/k;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    const-string v0, "goToNextStep"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "goToPreviousStep"

    .line 13
    .line 14
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p3

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v0, -0x7f94ee66

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v1}, Ll2/t;->h(Z)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v4, 0x4

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    move v0, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int v0, p4, v0

    .line 38
    .line 39
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_1

    .line 44
    .line 45
    const/16 v5, 0x20

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v0, v5

    .line 51
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_2

    .line 56
    .line 57
    const/16 v5, 0x100

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/16 v5, 0x80

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, v5

    .line 63
    and-int/lit16 v5, v0, 0x93

    .line 64
    .line 65
    const/16 v6, 0x92

    .line 66
    .line 67
    const/4 v10, 0x1

    .line 68
    const/4 v11, 0x0

    .line 69
    if-eq v5, v6, :cond_3

    .line 70
    .line 71
    move v5, v10

    .line 72
    goto :goto_3

    .line 73
    :cond_3
    move v5, v11

    .line 74
    :goto_3
    and-int/lit8 v6, v0, 0x1

    .line 75
    .line 76
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_e

    .line 81
    .line 82
    and-int/lit8 v5, v0, 0xe

    .line 83
    .line 84
    if-ne v5, v4, :cond_4

    .line 85
    .line 86
    move v4, v10

    .line 87
    goto :goto_4

    .line 88
    :cond_4
    move v4, v11

    .line 89
    :goto_4
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 94
    .line 95
    if-nez v4, :cond_5

    .line 96
    .line 97
    if-ne v5, v12, :cond_6

    .line 98
    .line 99
    :cond_5
    new-instance v5, Le81/b;

    .line 100
    .line 101
    const/16 v4, 0x19

    .line 102
    .line 103
    invoke-direct {v5, v4, v1}, Le81/b;-><init>(IZ)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v9, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_6
    check-cast v5, Lay0/k;

    .line 110
    .line 111
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 112
    .line 113
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    check-cast v4, Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_7

    .line 124
    .line 125
    const v4, -0x105bcaaa

    .line 126
    .line 127
    .line 128
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 132
    .line 133
    .line 134
    const/4 v4, 0x0

    .line 135
    goto :goto_5

    .line 136
    :cond_7
    const v4, 0x31054eee

    .line 137
    .line 138
    .line 139
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 140
    .line 141
    .line 142
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 143
    .line 144
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    check-cast v4, Lhi/a;

    .line 149
    .line 150
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 151
    .line 152
    .line 153
    :goto_5
    new-instance v7, Lnd/e;

    .line 154
    .line 155
    const/16 v6, 0x10

    .line 156
    .line 157
    invoke-direct {v7, v4, v5, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 158
    .line 159
    .line 160
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 161
    .line 162
    .line 163
    move-result-object v5

    .line 164
    if-eqz v5, :cond_d

    .line 165
    .line 166
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 167
    .line 168
    if-eqz v4, :cond_8

    .line 169
    .line 170
    move-object v4, v5

    .line 171
    check-cast v4, Landroidx/lifecycle/k;

    .line 172
    .line 173
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 174
    .line 175
    .line 176
    move-result-object v4

    .line 177
    :goto_6
    move-object v8, v4

    .line 178
    goto :goto_7

    .line 179
    :cond_8
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 180
    .line 181
    goto :goto_6

    .line 182
    :goto_7
    const-class v4, Lrh/u;

    .line 183
    .line 184
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 185
    .line 186
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    const/4 v6, 0x0

    .line 191
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 192
    .line 193
    .line 194
    move-result-object v4

    .line 195
    move-object v15, v4

    .line 196
    check-cast v15, Lrh/u;

    .line 197
    .line 198
    iget-object v4, v15, Lrh/u;->i:Lyy0/l1;

    .line 199
    .line 200
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v5

    .line 208
    check-cast v5, Lrh/s;

    .line 209
    .line 210
    shr-int/lit8 v0, v0, 0x3

    .line 211
    .line 212
    and-int/lit8 v0, v0, 0x7e

    .line 213
    .line 214
    invoke-static {v2, v3, v5, v9, v0}, Lkp/f0;->a(Lay0/k;Lay0/a;Lrh/s;Ll2/o;I)V

    .line 215
    .line 216
    .line 217
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    check-cast v4, Lrh/s;

    .line 226
    .line 227
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v6

    .line 235
    if-nez v5, :cond_9

    .line 236
    .line 237
    if-ne v6, v12, :cond_a

    .line 238
    .line 239
    :cond_9
    new-instance v13, Lo90/f;

    .line 240
    .line 241
    const/16 v19, 0x0

    .line 242
    .line 243
    const/16 v20, 0x17

    .line 244
    .line 245
    const/4 v14, 0x1

    .line 246
    const-class v16, Lrh/u;

    .line 247
    .line 248
    const-string v17, "onUiEvent"

    .line 249
    .line 250
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/pairing/WallboxPairingUiEvent;)V"

    .line 251
    .line 252
    invoke-direct/range {v13 .. v20}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    move-object v6, v13

    .line 259
    :cond_a
    check-cast v6, Lhy0/g;

    .line 260
    .line 261
    check-cast v6, Lay0/k;

    .line 262
    .line 263
    invoke-interface {v0, v4, v6, v9, v11}, Leh/n;->b0(Lrh/s;Lay0/k;Ll2/o;I)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    if-nez v0, :cond_b

    .line 275
    .line 276
    if-ne v4, v12, :cond_c

    .line 277
    .line 278
    :cond_b
    new-instance v4, Lrh/i;

    .line 279
    .line 280
    const/4 v0, 0x0

    .line 281
    invoke-direct {v4, v15, v0}, Lrh/i;-><init>(Lrh/u;I)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    :cond_c
    check-cast v4, Lay0/a;

    .line 288
    .line 289
    invoke-static {v11, v4, v9, v11, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 290
    .line 291
    .line 292
    goto :goto_8

    .line 293
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 294
    .line 295
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 296
    .line 297
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    throw v0

    .line 301
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 302
    .line 303
    .line 304
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 305
    .line 306
    .line 307
    move-result-object v6

    .line 308
    if-eqz v6, :cond_f

    .line 309
    .line 310
    new-instance v0, La71/l0;

    .line 311
    .line 312
    const/16 v5, 0x9

    .line 313
    .line 314
    move/from16 v4, p4

    .line 315
    .line 316
    invoke-direct/range {v0 .. v5}, La71/l0;-><init>(ZLjava/lang/Object;Ljava/lang/Object;II)V

    .line 317
    .line 318
    .line 319
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 320
    .line 321
    :cond_f
    return-void
.end method

.method public static final c(JLay0/k;Ll2/o;II)Le71/b;
    .locals 1

    .line 1
    and-int/lit8 p4, p5, 0x2

    .line 2
    .line 3
    sget-object p5, Ll2/n;->a:Ll2/x0;

    .line 4
    .line 5
    if-eqz p4, :cond_1

    .line 6
    .line 7
    move-object p2, p3

    .line 8
    check-cast p2, Ll2/t;

    .line 9
    .line 10
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p4

    .line 14
    if-ne p4, p5, :cond_0

    .line 15
    .line 16
    new-instance p4, Ldj/a;

    .line 17
    .line 18
    const/16 v0, 0x17

    .line 19
    .line 20
    invoke-direct {p4, v0}, Ldj/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p2, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    move-object p2, p4

    .line 27
    check-cast p2, Lay0/k;

    .line 28
    .line 29
    :cond_1
    move-object p4, p3

    .line 30
    check-cast p4, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {p4, p0, p1}, Ll2/t;->f(J)Z

    .line 33
    .line 34
    .line 35
    move-result p4

    .line 36
    check-cast p3, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-nez p4, :cond_2

    .line 43
    .line 44
    if-ne v0, p5, :cond_3

    .line 45
    .line 46
    :cond_2
    new-instance v0, Le71/b;

    .line 47
    .line 48
    invoke-direct {v0, p0, p1, p2}, Le71/b;-><init>(JLay0/k;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :cond_3
    check-cast v0, Le71/b;

    .line 55
    .line 56
    return-object v0
.end method
