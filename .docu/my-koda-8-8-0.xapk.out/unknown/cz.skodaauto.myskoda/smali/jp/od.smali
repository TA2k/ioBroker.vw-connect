.class public abstract Ljp/od;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/a;Lph/g;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v5, p2

    .line 4
    .line 5
    move/from16 v1, p4

    .line 6
    .line 7
    move-object/from16 v0, p3

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v2, -0x2dee79ec

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v1, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v2, 0x2

    .line 30
    :goto_0
    or-int/2addr v2, v1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v2, v1

    .line 33
    :goto_1
    and-int/lit8 v4, v1, 0x30

    .line 34
    .line 35
    const/16 v6, 0x20

    .line 36
    .line 37
    if-nez v4, :cond_3

    .line 38
    .line 39
    move-object/from16 v4, p1

    .line 40
    .line 41
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    if-eqz v7, :cond_2

    .line 46
    .line 47
    move v7, v6

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v7, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v2, v7

    .line 52
    goto :goto_3

    .line 53
    :cond_3
    move-object/from16 v4, p1

    .line 54
    .line 55
    :goto_3
    and-int/lit16 v7, v1, 0x180

    .line 56
    .line 57
    const/16 v8, 0x100

    .line 58
    .line 59
    if-nez v7, :cond_5

    .line 60
    .line 61
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    if-eqz v7, :cond_4

    .line 66
    .line 67
    move v7, v8

    .line 68
    goto :goto_4

    .line 69
    :cond_4
    const/16 v7, 0x80

    .line 70
    .line 71
    :goto_4
    or-int/2addr v2, v7

    .line 72
    :cond_5
    and-int/lit16 v7, v2, 0x93

    .line 73
    .line 74
    const/16 v9, 0x92

    .line 75
    .line 76
    const/4 v10, 0x0

    .line 77
    const/4 v11, 0x1

    .line 78
    if-eq v7, v9, :cond_6

    .line 79
    .line 80
    move v7, v11

    .line 81
    goto :goto_5

    .line 82
    :cond_6
    move v7, v10

    .line 83
    :goto_5
    and-int/lit8 v9, v2, 0x1

    .line 84
    .line 85
    invoke-virtual {v0, v9, v7}, Ll2/t;->O(IZ)Z

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    if-eqz v7, :cond_b

    .line 90
    .line 91
    invoke-static {v3, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    sget-object v9, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 96
    .line 97
    invoke-virtual {v0, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    check-cast v9, Landroid/content/Context;

    .line 102
    .line 103
    invoke-static {v0}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 104
    .line 105
    .line 106
    move-result-object v12

    .line 107
    invoke-interface {v12, v0}, Lzb/j;->u(Ll2/o;)J

    .line 108
    .line 109
    .line 110
    move-result-wide v12

    .line 111
    const-string v14, "context"

    .line 112
    .line 113
    invoke-static {v9, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    new-instance v14, Lh2/d6;

    .line 117
    .line 118
    const/4 v15, 0x3

    .line 119
    invoke-direct {v14, v9, v12, v13, v15}, Lh2/d6;-><init>(Ljava/lang/Object;JI)V

    .line 120
    .line 121
    .line 122
    and-int/lit16 v9, v2, 0x380

    .line 123
    .line 124
    if-ne v9, v8, :cond_7

    .line 125
    .line 126
    move v8, v11

    .line 127
    goto :goto_6

    .line 128
    :cond_7
    move v8, v10

    .line 129
    :goto_6
    invoke-virtual {v0, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    or-int/2addr v8, v9

    .line 134
    and-int/lit8 v2, v2, 0x70

    .line 135
    .line 136
    if-ne v2, v6, :cond_8

    .line 137
    .line 138
    move v10, v11

    .line 139
    :cond_8
    or-int v2, v8, v10

    .line 140
    .line 141
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v6

    .line 145
    or-int/2addr v2, v6

    .line 146
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    if-nez v2, :cond_9

    .line 151
    .line 152
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 153
    .line 154
    if-ne v6, v2, :cond_a

    .line 155
    .line 156
    :cond_9
    new-instance v4, Lff/a;

    .line 157
    .line 158
    const/4 v9, 0x0

    .line 159
    move-object v8, v7

    .line 160
    move-object v6, v14

    .line 161
    move-object/from16 v7, p1

    .line 162
    .line 163
    invoke-direct/range {v4 .. v9}, Lff/a;-><init>(Lph/g;Lh2/d6;Lay0/a;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    move-object v6, v4

    .line 170
    :cond_a
    check-cast v6, Lay0/n;

    .line 171
    .line 172
    invoke-static {v6, v5, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 173
    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 177
    .line 178
    .line 179
    :goto_7
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 180
    .line 181
    .line 182
    move-result-object v6

    .line 183
    if-eqz v6, :cond_c

    .line 184
    .line 185
    new-instance v0, Lph/a;

    .line 186
    .line 187
    const/4 v2, 0x0

    .line 188
    move-object/from16 v4, p1

    .line 189
    .line 190
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 194
    .line 195
    :cond_c
    return-void
.end method

.method public static final b(Ljava/lang/String;Lay0/a;Ll2/o;I)V
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
    const-string v3, "chargingStationId"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "goToNextStep"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p2

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v3, 0x5bcd622b

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const/4 v4, 0x4

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v2

    .line 38
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    if-eqz v5, :cond_1

    .line 43
    .line 44
    const/16 v5, 0x20

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/16 v5, 0x10

    .line 48
    .line 49
    :goto_1
    or-int/2addr v3, v5

    .line 50
    and-int/lit8 v5, v3, 0x13

    .line 51
    .line 52
    const/16 v6, 0x12

    .line 53
    .line 54
    const/4 v7, 0x1

    .line 55
    const/4 v10, 0x0

    .line 56
    if-eq v5, v6, :cond_2

    .line 57
    .line 58
    move v5, v7

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    move v5, v10

    .line 61
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 62
    .line 63
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-eqz v5, :cond_d

    .line 68
    .line 69
    and-int/lit8 v5, v3, 0xe

    .line 70
    .line 71
    if-ne v5, v4, :cond_3

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_3
    move v7, v10

    .line 75
    :goto_3
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 80
    .line 81
    if-nez v7, :cond_4

    .line 82
    .line 83
    if-ne v4, v11, :cond_5

    .line 84
    .line 85
    :cond_4
    new-instance v4, Lod0/d;

    .line 86
    .line 87
    const/4 v5, 0x5

    .line 88
    invoke-direct {v4, v0, v5}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_5
    check-cast v4, Lay0/k;

    .line 95
    .line 96
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 97
    .line 98
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    check-cast v5, Ljava/lang/Boolean;

    .line 103
    .line 104
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 105
    .line 106
    .line 107
    move-result v5

    .line 108
    if-eqz v5, :cond_6

    .line 109
    .line 110
    const v5, -0x105bcaaa

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    const/4 v5, 0x0

    .line 120
    goto :goto_4

    .line 121
    :cond_6
    const v5, 0x31054eee

    .line 122
    .line 123
    .line 124
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 128
    .line 129
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v5

    .line 133
    check-cast v5, Lhi/a;

    .line 134
    .line 135
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 136
    .line 137
    .line 138
    :goto_4
    new-instance v7, Lnd/e;

    .line 139
    .line 140
    const/16 v6, 0xa

    .line 141
    .line 142
    invoke-direct {v7, v5, v4, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 146
    .line 147
    .line 148
    move-result-object v5

    .line 149
    if-eqz v5, :cond_c

    .line 150
    .line 151
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 152
    .line 153
    if-eqz v4, :cond_7

    .line 154
    .line 155
    move-object v4, v5

    .line 156
    check-cast v4, Landroidx/lifecycle/k;

    .line 157
    .line 158
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 159
    .line 160
    .line 161
    move-result-object v4

    .line 162
    :goto_5
    move-object v8, v4

    .line 163
    goto :goto_6

    .line 164
    :cond_7
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :goto_6
    const-class v4, Lph/i;

    .line 168
    .line 169
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 170
    .line 171
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    const/4 v6, 0x0

    .line 176
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    move-object v14, v4

    .line 181
    check-cast v14, Lph/i;

    .line 182
    .line 183
    iget-object v4, v14, Lph/i;->f:Lyy0/l1;

    .line 184
    .line 185
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    check-cast v5, Lph/g;

    .line 194
    .line 195
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v6

    .line 199
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v7

    .line 203
    if-nez v6, :cond_8

    .line 204
    .line 205
    if-ne v7, v11, :cond_9

    .line 206
    .line 207
    :cond_8
    new-instance v7, Lmc/e;

    .line 208
    .line 209
    const/16 v6, 0x14

    .line 210
    .line 211
    invoke-direct {v7, v14, v6}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v9, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    :cond_9
    check-cast v7, Lay0/a;

    .line 218
    .line 219
    shr-int/lit8 v3, v3, 0x3

    .line 220
    .line 221
    and-int/lit8 v3, v3, 0xe

    .line 222
    .line 223
    invoke-static {v1, v7, v5, v9, v3}, Ljp/od;->a(Lay0/a;Lay0/a;Lph/g;Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v4

    .line 234
    check-cast v4, Lph/g;

    .line 235
    .line 236
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    if-nez v5, :cond_a

    .line 245
    .line 246
    if-ne v6, v11, :cond_b

    .line 247
    .line 248
    :cond_a
    new-instance v12, Lo90/f;

    .line 249
    .line 250
    const/16 v18, 0x0

    .line 251
    .line 252
    const/16 v19, 0x9

    .line 253
    .line 254
    const/4 v13, 0x1

    .line 255
    const-class v15, Lph/i;

    .line 256
    .line 257
    const-string v16, "onUiEvent"

    .line 258
    .line 259
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/automaticupdates/WallboxOnboardingAutomaticUpdateUiEvent;)V"

    .line 260
    .line 261
    invoke-direct/range {v12 .. v19}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    move-object v6, v12

    .line 268
    :cond_b
    check-cast v6, Lhy0/g;

    .line 269
    .line 270
    check-cast v6, Lay0/k;

    .line 271
    .line 272
    invoke-interface {v3, v4, v6, v9, v10}, Leh/n;->F(Lph/g;Lay0/k;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    goto :goto_7

    .line 276
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 277
    .line 278
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 279
    .line 280
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw v0

    .line 284
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 288
    .line 289
    .line 290
    move-result-object v3

    .line 291
    if-eqz v3, :cond_e

    .line 292
    .line 293
    new-instance v4, Lf41/c;

    .line 294
    .line 295
    const/4 v5, 0x4

    .line 296
    invoke-direct {v4, v0, v1, v2, v5}, Lf41/c;-><init>(Ljava/lang/String;Lay0/a;II)V

    .line 297
    .line 298
    .line 299
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 300
    .line 301
    :cond_e
    return-void
.end method

.method public static final c(Lbl0/e;)Lgy0/e;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbl0/e;->a:Lbl0/g;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    int-to-float v0, v0

    .line 13
    iget-object p0, p0, Lbl0/e;->b:Lbl0/g;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    int-to-float p0, p0

    .line 20
    new-instance v1, Lgy0/e;

    .line 21
    .line 22
    invoke-direct {v1, v0, p0}, Lgy0/e;-><init>(FF)V

    .line 23
    .line 24
    .line 25
    return-object v1
.end method
