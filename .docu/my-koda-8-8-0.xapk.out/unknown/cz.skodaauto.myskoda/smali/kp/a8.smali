.class public abstract Lkp/a8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lai/a;Lyj/b;Ll2/o;I)V
    .locals 22

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
    move-object/from16 v8, p2

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v3, -0x2f3e1174

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v3, 0x2

    .line 26
    :goto_0
    or-int/2addr v3, v2

    .line 27
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/16 v9, 0x20

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    move v4, v9

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v4, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v3, v4

    .line 40
    and-int/lit8 v4, v3, 0x13

    .line 41
    .line 42
    const/16 v5, 0x12

    .line 43
    .line 44
    const/4 v10, 0x1

    .line 45
    const/4 v11, 0x0

    .line 46
    if-eq v4, v5, :cond_2

    .line 47
    .line 48
    move v4, v10

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v4, v11

    .line 51
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 52
    .line 53
    invoke-virtual {v8, v5, v4}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_e

    .line 58
    .line 59
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    and-int/lit8 v12, v3, 0x70

    .line 64
    .line 65
    if-ne v12, v9, :cond_3

    .line 66
    .line 67
    move v3, v10

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v3, v11

    .line 70
    :goto_3
    or-int/2addr v3, v4

    .line 71
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 76
    .line 77
    if-nez v3, :cond_4

    .line 78
    .line 79
    if-ne v4, v13, :cond_5

    .line 80
    .line 81
    :cond_4
    new-instance v4, Let/g;

    .line 82
    .line 83
    const/4 v3, 0x3

    .line 84
    invoke-direct {v4, v3, v0, v1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_5
    check-cast v4, Lay0/k;

    .line 91
    .line 92
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 93
    .line 94
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    check-cast v3, Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    if-eqz v3, :cond_6

    .line 105
    .line 106
    const v3, -0x105bcaaa

    .line 107
    .line 108
    .line 109
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 113
    .line 114
    .line 115
    const/4 v3, 0x0

    .line 116
    goto :goto_4

    .line 117
    :cond_6
    const v3, 0x31054eee

    .line 118
    .line 119
    .line 120
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 121
    .line 122
    .line 123
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 124
    .line 125
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    check-cast v3, Lhi/a;

    .line 130
    .line 131
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 132
    .line 133
    .line 134
    :goto_4
    new-instance v6, Laf/a;

    .line 135
    .line 136
    const/16 v5, 0xd

    .line 137
    .line 138
    invoke-direct {v6, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 139
    .line 140
    .line 141
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    if-eqz v4, :cond_d

    .line 146
    .line 147
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 148
    .line 149
    if-eqz v3, :cond_7

    .line 150
    .line 151
    move-object v3, v4

    .line 152
    check-cast v3, Landroidx/lifecycle/k;

    .line 153
    .line 154
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    :goto_5
    move-object v7, v3

    .line 159
    goto :goto_6

    .line 160
    :cond_7
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :goto_6
    const-class v3, Lfi/c;

    .line 164
    .line 165
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 166
    .line 167
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    const/4 v5, 0x0

    .line 172
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    check-cast v3, Lfi/c;

    .line 177
    .line 178
    if-ne v12, v9, :cond_8

    .line 179
    .line 180
    move v4, v10

    .line 181
    goto :goto_7

    .line 182
    :cond_8
    move v4, v11

    .line 183
    :goto_7
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    if-nez v4, :cond_9

    .line 188
    .line 189
    if-ne v5, v13, :cond_a

    .line 190
    .line 191
    :cond_9
    new-instance v5, Lfi/a;

    .line 192
    .line 193
    const/4 v4, 0x0

    .line 194
    invoke-direct {v5, v1, v4}, Lfi/a;-><init>(Lyj/b;I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    :cond_a
    check-cast v5, Lay0/a;

    .line 201
    .line 202
    invoke-static {v11, v5, v8, v11, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 203
    .line 204
    .line 205
    invoke-static {v8}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    iget-object v5, v3, Lfi/c;->d:Lyy0/l1;

    .line 210
    .line 211
    invoke-static {v5, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 212
    .line 213
    .line 214
    move-result-object v5

    .line 215
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v5

    .line 219
    check-cast v5, Llc/q;

    .line 220
    .line 221
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v7

    .line 229
    if-nez v6, :cond_b

    .line 230
    .line 231
    if-ne v7, v13, :cond_c

    .line 232
    .line 233
    :cond_b
    new-instance v14, Lei/a;

    .line 234
    .line 235
    const/16 v20, 0x0

    .line 236
    .line 237
    const/16 v21, 0x10

    .line 238
    .line 239
    const/4 v15, 0x1

    .line 240
    const-class v17, Lfi/c;

    .line 241
    .line 242
    const-string v18, "onUiEvent"

    .line 243
    .line 244
    const-string v19, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/solarsystemdetails/SolarSystemDetailsUiEvent;)V"

    .line 245
    .line 246
    move-object/from16 v16, v3

    .line 247
    .line 248
    invoke-direct/range {v14 .. v21}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v8, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    move-object v7, v14

    .line 255
    :cond_c
    check-cast v7, Lhy0/g;

    .line 256
    .line 257
    check-cast v7, Lay0/k;

    .line 258
    .line 259
    const/16 v3, 0x8

    .line 260
    .line 261
    invoke-interface {v4, v5, v7, v8, v3}, Leh/n;->z(Llc/q;Lay0/k;Ll2/o;I)V

    .line 262
    .line 263
    .line 264
    goto :goto_8

    .line 265
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 266
    .line 267
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 268
    .line 269
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    throw v0

    .line 273
    :cond_e
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 274
    .line 275
    .line 276
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 277
    .line 278
    .line 279
    move-result-object v3

    .line 280
    if-eqz v3, :cond_f

    .line 281
    .line 282
    new-instance v4, Ld90/m;

    .line 283
    .line 284
    const/16 v5, 0xf

    .line 285
    .line 286
    invoke-direct {v4, v2, v5, v0, v1}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 290
    .line 291
    :cond_f
    return-void
.end method


# virtual methods
.method public abstract b(Le21/a;)V
.end method
