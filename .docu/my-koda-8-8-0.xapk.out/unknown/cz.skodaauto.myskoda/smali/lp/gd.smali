.class public abstract Llp/gd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxh/e;ZLjava/lang/String;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

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
    const v0, -0x12031367

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    invoke-virtual {v9, v2}, Ll2/t;->h(Z)Z

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
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    new-instance v4, Laa/l;

    .line 108
    .line 109
    const/4 v0, 0x5

    .line 110
    invoke-direct {v4, v1, v2, v3, v0}, Laa/l;-><init>(Ljava/lang/Object;ZLjava/lang/Object;I)V

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
    new-instance v7, Lvh/i;

    .line 161
    .line 162
    const/4 v5, 0x1

    .line 163
    invoke-direct {v7, v5, v0, v4}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    if-eqz v5, :cond_d

    .line 171
    .line 172
    instance-of v0, v5, Landroidx/lifecycle/k;

    .line 173
    .line 174
    if-eqz v0, :cond_a

    .line 175
    .line 176
    move-object v0, v5

    .line 177
    check-cast v0, Landroidx/lifecycle/k;

    .line 178
    .line 179
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    :goto_8
    move-object v8, v0

    .line 184
    goto :goto_9

    .line 185
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 186
    .line 187
    goto :goto_8

    .line 188
    :goto_9
    const-class v0, Lwc/g;

    .line 189
    .line 190
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 191
    .line 192
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    const/4 v6, 0x0

    .line 197
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    move-object v14, v0

    .line 202
    check-cast v14, Lwc/g;

    .line 203
    .line 204
    invoke-static {v9}, Llp/kb;->c(Ll2/o;)Lvc/b;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    iget-object v4, v14, Lwc/g;->g:Lyy0/l1;

    .line 209
    .line 210
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    check-cast v4, Lwc/f;

    .line 219
    .line 220
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v6

    .line 228
    if-nez v5, :cond_b

    .line 229
    .line 230
    if-ne v6, v10, :cond_c

    .line 231
    .line 232
    :cond_b
    new-instance v12, Lwc/a;

    .line 233
    .line 234
    const/16 v18, 0x0

    .line 235
    .line 236
    const/16 v19, 0x0

    .line 237
    .line 238
    const/4 v13, 0x1

    .line 239
    const-class v15, Lwc/g;

    .line 240
    .line 241
    const-string v16, "onUiEvent"

    .line 242
    .line 243
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/chargingcard/presentation/add/AddChargingCardUiEvent;)V"

    .line 244
    .line 245
    invoke-direct/range {v12 .. v19}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    move-object v6, v12

    .line 252
    :cond_c
    check-cast v6, Lhy0/g;

    .line 253
    .line 254
    check-cast v6, Lay0/k;

    .line 255
    .line 256
    invoke-interface {v0, v11, v6, v9, v4}, Lvc/b;->h0(ILay0/k;Ll2/o;Lwc/f;)V

    .line 257
    .line 258
    .line 259
    goto :goto_a

    .line 260
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 261
    .line 262
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 263
    .line 264
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    throw v0

    .line 268
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 269
    .line 270
    .line 271
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 272
    .line 273
    .line 274
    move-result-object v6

    .line 275
    if-eqz v6, :cond_f

    .line 276
    .line 277
    new-instance v0, La71/l0;

    .line 278
    .line 279
    const/16 v5, 0xc

    .line 280
    .line 281
    move/from16 v4, p4

    .line 282
    .line 283
    invoke-direct/range {v0 .. v5}, La71/l0;-><init>(Ljava/lang/Object;ZLjava/lang/Object;II)V

    .line 284
    .line 285
    .line 286
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 287
    .line 288
    :cond_f
    return-void
.end method

.method public static final b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;)Z
    .locals 2

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->getEntries()Lsx0/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->NON_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 10
    .line 11
    invoke-static {v0, v1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {v0, p1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 22
    .line 23
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 24
    .line 25
    filled-new-array {p1, v0}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {p1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    check-cast p1, Ljava/lang/Iterable;

    .line 34
    .line 35
    invoke-static {p1, p2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_1

    .line 40
    .line 41
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->getEntries()Lsx0/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->NO_ERROR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 50
    .line 51
    invoke-static {p1, p2}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {p1, p0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    const/4 p0, 0x0

    .line 63
    return p0

    .line 64
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 65
    return p0
.end method
