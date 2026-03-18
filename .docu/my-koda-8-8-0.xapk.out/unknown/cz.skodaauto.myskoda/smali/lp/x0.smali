.class public abstract Llp/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lxh/e;Lzb/s0;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v9, p3

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, -0x30ed3258

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v4, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    const/16 v6, 0x20

    .line 34
    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    move v5, v6

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v5, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v5

    .line 42
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    const/16 v7, 0x100

    .line 47
    .line 48
    if-eqz v5, :cond_2

    .line 49
    .line 50
    move v5, v7

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v5, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v5

    .line 55
    and-int/lit16 v5, v0, 0x93

    .line 56
    .line 57
    const/16 v8, 0x92

    .line 58
    .line 59
    const/4 v10, 0x1

    .line 60
    const/4 v11, 0x0

    .line 61
    if-eq v5, v8, :cond_3

    .line 62
    .line 63
    move v5, v10

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    move v5, v11

    .line 66
    :goto_3
    and-int/lit8 v8, v0, 0x1

    .line 67
    .line 68
    invoke-virtual {v9, v8, v5}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-eqz v5, :cond_e

    .line 73
    .line 74
    and-int/lit8 v5, v0, 0xe

    .line 75
    .line 76
    if-ne v5, v4, :cond_4

    .line 77
    .line 78
    move v4, v10

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v4, v11

    .line 81
    :goto_4
    and-int/lit8 v5, v0, 0x70

    .line 82
    .line 83
    if-ne v5, v6, :cond_5

    .line 84
    .line 85
    move v5, v10

    .line 86
    goto :goto_5

    .line 87
    :cond_5
    move v5, v11

    .line 88
    :goto_5
    or-int/2addr v4, v5

    .line 89
    and-int/lit16 v0, v0, 0x380

    .line 90
    .line 91
    if-ne v0, v7, :cond_6

    .line 92
    .line 93
    goto :goto_6

    .line 94
    :cond_6
    move v10, v11

    .line 95
    :goto_6
    or-int v0, v4, v10

    .line 96
    .line 97
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-nez v0, :cond_7

    .line 104
    .line 105
    if-ne v4, v10, :cond_8

    .line 106
    .line 107
    :cond_7
    new-instance v4, Lhh/a;

    .line 108
    .line 109
    const/4 v0, 0x0

    .line 110
    invoke-direct {v4, v1, v2, v3, v0}, Lhh/a;-><init>(Ljava/lang/String;Lxh/e;Lzb/s0;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_8
    check-cast v4, Lay0/k;

    .line 117
    .line 118
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_9

    .line 131
    .line 132
    const v0, -0x105bcaaa

    .line 133
    .line 134
    .line 135
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x0

    .line 142
    goto :goto_7

    .line 143
    :cond_9
    const v0, 0x31054eee

    .line 144
    .line 145
    .line 146
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 150
    .line 151
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    check-cast v0, Lhi/a;

    .line 156
    .line 157
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 158
    .line 159
    .line 160
    :goto_7
    new-instance v7, Laf/a;

    .line 161
    .line 162
    const/16 v5, 0x11

    .line 163
    .line 164
    invoke-direct {v7, v0, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 165
    .line 166
    .line 167
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    if-eqz v5, :cond_d

    .line 172
    .line 173
    instance-of v0, v5, Landroidx/lifecycle/k;

    .line 174
    .line 175
    if-eqz v0, :cond_a

    .line 176
    .line 177
    move-object v0, v5

    .line 178
    check-cast v0, Landroidx/lifecycle/k;

    .line 179
    .line 180
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    :goto_8
    move-object v8, v0

    .line 185
    goto :goto_9

    .line 186
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 187
    .line 188
    goto :goto_8

    .line 189
    :goto_9
    const-class v0, Lhh/h;

    .line 190
    .line 191
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 192
    .line 193
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    const/4 v6, 0x0

    .line 198
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    move-object v13, v0

    .line 203
    check-cast v13, Lhh/h;

    .line 204
    .line 205
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    iget-object v4, v13, Lhh/h;->m:Lyy0/l1;

    .line 210
    .line 211
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    check-cast v4, Llc/q;

    .line 220
    .line 221
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v6

    .line 229
    if-nez v5, :cond_b

    .line 230
    .line 231
    if-ne v6, v10, :cond_c

    .line 232
    .line 233
    :cond_b
    new-instance v11, Lhh/d;

    .line 234
    .line 235
    const/16 v17, 0x0

    .line 236
    .line 237
    const/16 v18, 0x0

    .line 238
    .line 239
    const/4 v12, 0x1

    .line 240
    const-class v14, Lhh/h;

    .line 241
    .line 242
    const-string v15, "onUiEvent"

    .line 243
    .line 244
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/detail/WallboxDetailUiEvent;)V"

    .line 245
    .line 246
    invoke-direct/range {v11 .. v18}, Lhh/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    move-object v6, v11

    .line 253
    :cond_c
    check-cast v6, Lhy0/g;

    .line 254
    .line 255
    check-cast v6, Lay0/k;

    .line 256
    .line 257
    const/16 v5, 0x8

    .line 258
    .line 259
    invoke-interface {v0, v4, v6, v9, v5}, Leh/n;->m0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 260
    .line 261
    .line 262
    goto :goto_a

    .line 263
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 266
    .line 267
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    throw v0

    .line 271
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 272
    .line 273
    .line 274
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    if-eqz v6, :cond_f

    .line 279
    .line 280
    new-instance v0, Lhh/b;

    .line 281
    .line 282
    const/4 v5, 0x0

    .line 283
    move/from16 v4, p4

    .line 284
    .line 285
    invoke-direct/range {v0 .. v5}, Lhh/b;-><init>(Ljava/lang/String;Lxh/e;Lzb/s0;II)V

    .line 286
    .line 287
    .line 288
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 289
    .line 290
    :cond_f
    return-void
.end method

.method public static b(Ljava/util/ArrayList;)Landroid/hardware/camera2/CameraDevice$StateCallback;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance p0, Lu/k0;

    .line 8
    .line 9
    invoke-direct {p0}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x1

    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    new-instance v0, Lu/j0;

    .line 29
    .line 30
    invoke-direct {v0, p0}, Lu/j0;-><init>(Ljava/util/ArrayList;)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method
