.class public abstract Llp/oe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lzg/f1;Lay0/k;Ll2/o;I)V
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
    const-string v3, "event"

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
    const v3, -0xca25907

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    const/4 v3, -0x1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    :goto_0
    invoke-virtual {v9, v3}, Ll2/t;->e(I)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    const/4 v4, 0x4

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    move v3, v4

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/4 v3, 0x2

    .line 40
    :goto_1
    or-int/2addr v3, v2

    .line 41
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    const/16 v6, 0x20

    .line 46
    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    move v5, v6

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v5, 0x10

    .line 52
    .line 53
    :goto_2
    or-int/2addr v3, v5

    .line 54
    and-int/lit8 v5, v3, 0x13

    .line 55
    .line 56
    const/16 v7, 0x12

    .line 57
    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v8, 0x1

    .line 60
    if-eq v5, v7, :cond_3

    .line 61
    .line 62
    move v5, v8

    .line 63
    goto :goto_3

    .line 64
    :cond_3
    move v5, v10

    .line 65
    :goto_3
    and-int/lit8 v7, v3, 0x1

    .line 66
    .line 67
    invoke-virtual {v9, v7, v5}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-eqz v5, :cond_d

    .line 72
    .line 73
    and-int/lit8 v5, v3, 0xe

    .line 74
    .line 75
    if-ne v5, v4, :cond_4

    .line 76
    .line 77
    move v4, v8

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    move v4, v10

    .line 80
    :goto_4
    and-int/lit8 v3, v3, 0x70

    .line 81
    .line 82
    if-ne v3, v6, :cond_5

    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_5
    move v8, v10

    .line 86
    :goto_5
    or-int v3, v4, v8

    .line 87
    .line 88
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 93
    .line 94
    if-nez v3, :cond_6

    .line 95
    .line 96
    if-ne v4, v11, :cond_7

    .line 97
    .line 98
    :cond_6
    new-instance v4, Lxh/e;

    .line 99
    .line 100
    const/4 v3, 0x0

    .line 101
    invoke-direct {v4, v3, v0, v1}, Lxh/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :cond_7
    check-cast v4, Lay0/k;

    .line 108
    .line 109
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 110
    .line 111
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    check-cast v3, Ljava/lang/Boolean;

    .line 116
    .line 117
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_8

    .line 122
    .line 123
    const v3, -0x105bcaaa

    .line 124
    .line 125
    .line 126
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 130
    .line 131
    .line 132
    const/4 v3, 0x0

    .line 133
    goto :goto_6

    .line 134
    :cond_8
    const v3, 0x31054eee

    .line 135
    .line 136
    .line 137
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 138
    .line 139
    .line 140
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 141
    .line 142
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    check-cast v3, Lhi/a;

    .line 147
    .line 148
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    :goto_6
    new-instance v7, Lvh/i;

    .line 152
    .line 153
    const/4 v5, 0x5

    .line 154
    invoke-direct {v7, v5, v3, v4}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    if-eqz v5, :cond_c

    .line 162
    .line 163
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 164
    .line 165
    if-eqz v3, :cond_9

    .line 166
    .line 167
    move-object v3, v5

    .line 168
    check-cast v3, Landroidx/lifecycle/k;

    .line 169
    .line 170
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    :goto_7
    move-object v8, v3

    .line 175
    goto :goto_8

    .line 176
    :cond_9
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 177
    .line 178
    goto :goto_7

    .line 179
    :goto_8
    const-class v3, Lxh/f;

    .line 180
    .line 181
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 182
    .line 183
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    const/4 v6, 0x0

    .line 188
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    move-object v14, v3

    .line 193
    check-cast v14, Lxh/f;

    .line 194
    .line 195
    iget-object v3, v14, Lxh/f;->e:Lyy0/l1;

    .line 196
    .line 197
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 198
    .line 199
    .line 200
    move-result-object v3

    .line 201
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    check-cast v3, Lxh/d;

    .line 210
    .line 211
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v5

    .line 215
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v6

    .line 219
    if-nez v5, :cond_a

    .line 220
    .line 221
    if-ne v6, v11, :cond_b

    .line 222
    .line 223
    :cond_a
    new-instance v12, Lwc/a;

    .line 224
    .line 225
    const/16 v18, 0x0

    .line 226
    .line 227
    const/16 v19, 0x10

    .line 228
    .line 229
    const/4 v13, 0x1

    .line 230
    const-class v15, Lxh/f;

    .line 231
    .line 232
    const-string v16, "onUiEvent"

    .line 233
    .line 234
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/azimuth/SetAzimuthScreenUiEvent;)V"

    .line 235
    .line 236
    invoke-direct/range {v12 .. v19}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    move-object v6, v12

    .line 243
    :cond_b
    check-cast v6, Lhy0/g;

    .line 244
    .line 245
    check-cast v6, Lay0/k;

    .line 246
    .line 247
    invoke-interface {v4, v3, v6, v9, v10}, Leh/n;->k0(Lxh/d;Lay0/k;Ll2/o;I)V

    .line 248
    .line 249
    .line 250
    goto :goto_9

    .line 251
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 252
    .line 253
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 254
    .line 255
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    throw v0

    .line 259
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 260
    .line 261
    .line 262
    :goto_9
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    if-eqz v3, :cond_e

    .line 267
    .line 268
    new-instance v4, Lx40/n;

    .line 269
    .line 270
    const/4 v5, 0x7

    .line 271
    invoke-direct {v4, v2, v5, v0, v1}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 275
    .line 276
    :cond_e
    return-void
.end method

.method public static final b(Ld3/c;FF)Z
    .locals 2

    .line 1
    iget v0, p0, Ld3/c;->a:F

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->c:F

    .line 4
    .line 5
    cmpg-float v1, p1, v1

    .line 6
    .line 7
    if-gtz v1, :cond_0

    .line 8
    .line 9
    cmpg-float p1, v0, p1

    .line 10
    .line 11
    if-gtz p1, :cond_0

    .line 12
    .line 13
    iget p1, p0, Ld3/c;->b:F

    .line 14
    .line 15
    iget p0, p0, Ld3/c;->d:F

    .line 16
    .line 17
    cmpg-float p0, p2, p0

    .line 18
    .line 19
    if-gtz p0, :cond_0

    .line 20
    .line 21
    cmpg-float p0, p1, p2

    .line 22
    .line 23
    if-gtz p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method
