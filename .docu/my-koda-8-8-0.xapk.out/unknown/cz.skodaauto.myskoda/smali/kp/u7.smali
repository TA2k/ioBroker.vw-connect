.class public abstract Lkp/u7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Ljava/lang/Boolean;


# direct methods
.method public static final a(Lzb/s0;Lrd/a;Ll2/o;I)V
    .locals 19

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
    const v3, -0x6ebec056

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
    const/4 v4, 0x4

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    move v3, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v3, 0x2

    .line 27
    :goto_0
    or-int/2addr v3, v2

    .line 28
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v5, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v3, v5

    .line 40
    and-int/lit8 v5, v3, 0x13

    .line 41
    .line 42
    const/16 v6, 0x12

    .line 43
    .line 44
    const/4 v7, 0x1

    .line 45
    const/4 v9, 0x0

    .line 46
    if-eq v5, v6, :cond_2

    .line 47
    .line 48
    move v5, v7

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v5, v9

    .line 51
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 52
    .line 53
    invoke-virtual {v8, v6, v5}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-eqz v5, :cond_b

    .line 58
    .line 59
    and-int/lit8 v3, v3, 0xe

    .line 60
    .line 61
    if-ne v3, v4, :cond_3

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    move v7, v9

    .line 65
    :goto_3
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    or-int/2addr v3, v7

    .line 70
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-nez v3, :cond_4

    .line 77
    .line 78
    if-ne v4, v10, :cond_5

    .line 79
    .line 80
    :cond_4
    new-instance v4, Lod0/n;

    .line 81
    .line 82
    const/16 v3, 0x14

    .line 83
    .line 84
    invoke-direct {v4, v3, v0, v1}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

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
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

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
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 132
    .line 133
    .line 134
    :goto_4
    new-instance v6, Lnd/e;

    .line 135
    .line 136
    const/16 v5, 0x11

    .line 137
    .line 138
    invoke-direct {v6, v3, v4, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 139
    .line 140
    .line 141
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    if-eqz v4, :cond_a

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
    const-class v3, Lsd/e;

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
    move-object v13, v3

    .line 177
    check-cast v13, Lsd/e;

    .line 178
    .line 179
    sget-object v3, Lzb/x;->b:Ll2/u2;

    .line 180
    .line 181
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    const-string v4, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.chargingstatistics.presentation.ChargingStatisticsUi"

    .line 186
    .line 187
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    check-cast v3, Lrd/c;

    .line 191
    .line 192
    iget-object v4, v13, Lsd/e;->h:Lyy0/c2;

    .line 193
    .line 194
    invoke-static {v4, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    check-cast v4, Lsd/d;

    .line 203
    .line 204
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    if-nez v5, :cond_8

    .line 213
    .line 214
    if-ne v6, v10, :cond_9

    .line 215
    .line 216
    :cond_8
    new-instance v11, Ls60/h;

    .line 217
    .line 218
    const/16 v17, 0x0

    .line 219
    .line 220
    const/16 v18, 0xe

    .line 221
    .line 222
    const/4 v12, 0x1

    .line 223
    const-class v14, Lsd/e;

    .line 224
    .line 225
    const-string v15, "onUiEvent"

    .line 226
    .line 227
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/chargingstatistics/presentation/details/ChargingStatisticsDetailsUiEvent;)V"

    .line 228
    .line 229
    invoke-direct/range {v11 .. v18}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    move-object v6, v11

    .line 236
    :cond_9
    check-cast v6, Lhy0/g;

    .line 237
    .line 238
    check-cast v6, Lay0/k;

    .line 239
    .line 240
    invoke-interface {v3, v4, v6, v8, v9}, Lrd/c;->g0(Lsd/d;Lay0/k;Ll2/o;I)V

    .line 241
    .line 242
    .line 243
    goto :goto_7

    .line 244
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 245
    .line 246
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 247
    .line 248
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw v0

    .line 252
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 253
    .line 254
    .line 255
    :goto_7
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    if-eqz v3, :cond_c

    .line 260
    .line 261
    new-instance v4, Lo50/b;

    .line 262
    .line 263
    const/16 v5, 0x16

    .line 264
    .line 265
    invoke-direct {v4, v2, v5, v0, v1}, Lo50/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 269
    .line 270
    :cond_c
    return-void
.end method
