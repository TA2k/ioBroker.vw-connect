.class public abstract Lkp/x7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lxh/e;Ll2/o;I)V
    .locals 18

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
    const v3, -0x6dbddeba

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    const/16 v6, 0x20

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    move v5, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v3, v5

    .line 41
    and-int/lit8 v5, v3, 0x13

    .line 42
    .line 43
    const/16 v7, 0x12

    .line 44
    .line 45
    const/4 v9, 0x1

    .line 46
    const/4 v10, 0x0

    .line 47
    if-eq v5, v7, :cond_2

    .line 48
    .line 49
    move v5, v9

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    move v5, v10

    .line 52
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 53
    .line 54
    invoke-virtual {v8, v7, v5}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_c

    .line 59
    .line 60
    and-int/lit8 v5, v3, 0xe

    .line 61
    .line 62
    if-ne v5, v4, :cond_3

    .line 63
    .line 64
    move v4, v9

    .line 65
    goto :goto_3

    .line 66
    :cond_3
    move v4, v10

    .line 67
    :goto_3
    and-int/lit8 v3, v3, 0x70

    .line 68
    .line 69
    if-ne v3, v6, :cond_4

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_4
    move v9, v10

    .line 73
    :goto_4
    or-int v3, v4, v9

    .line 74
    .line 75
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 80
    .line 81
    if-nez v3, :cond_5

    .line 82
    .line 83
    if-ne v4, v9, :cond_6

    .line 84
    .line 85
    :cond_5
    new-instance v4, Lsg/j;

    .line 86
    .line 87
    invoke-direct {v4, v0, v1}, Lsg/j;-><init>(Ljava/lang/String;Lxh/e;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_6
    check-cast v4, Lay0/k;

    .line 94
    .line 95
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 96
    .line 97
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    check-cast v3, Ljava/lang/Boolean;

    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-eqz v3, :cond_7

    .line 108
    .line 109
    const v3, -0x105bcaaa

    .line 110
    .line 111
    .line 112
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 116
    .line 117
    .line 118
    const/4 v3, 0x0

    .line 119
    goto :goto_5

    .line 120
    :cond_7
    const v3, 0x31054eee

    .line 121
    .line 122
    .line 123
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 124
    .line 125
    .line 126
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 127
    .line 128
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    check-cast v3, Lhi/a;

    .line 133
    .line 134
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    :goto_5
    new-instance v6, Lnd/e;

    .line 138
    .line 139
    const/16 v5, 0x14

    .line 140
    .line 141
    invoke-direct {v6, v3, v4, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 142
    .line 143
    .line 144
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    if-eqz v4, :cond_b

    .line 149
    .line 150
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 151
    .line 152
    if-eqz v3, :cond_8

    .line 153
    .line 154
    move-object v3, v4

    .line 155
    check-cast v3, Landroidx/lifecycle/k;

    .line 156
    .line 157
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    :goto_6
    move-object v7, v3

    .line 162
    goto :goto_7

    .line 163
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 164
    .line 165
    goto :goto_6

    .line 166
    :goto_7
    const-class v3, Lsg/p;

    .line 167
    .line 168
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 169
    .line 170
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    const/4 v5, 0x0

    .line 175
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    move-object v12, v3

    .line 180
    check-cast v12, Lsg/p;

    .line 181
    .line 182
    invoke-static {v8}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    iget-object v4, v12, Lsg/p;->h:Lyy0/c2;

    .line 187
    .line 188
    invoke-static {v4, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    check-cast v4, Llc/q;

    .line 197
    .line 198
    invoke-virtual {v8, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v5

    .line 202
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v6

    .line 206
    if-nez v5, :cond_9

    .line 207
    .line 208
    if-ne v6, v9, :cond_a

    .line 209
    .line 210
    :cond_9
    new-instance v10, Ls60/h;

    .line 211
    .line 212
    const/16 v16, 0x0

    .line 213
    .line 214
    const/16 v17, 0x11

    .line 215
    .line 216
    const/4 v11, 0x1

    .line 217
    const-class v13, Lsg/p;

    .line 218
    .line 219
    const-string v14, "onUiEvent"

    .line 220
    .line 221
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/tariff/selection/TariffSelectionUiEvent;)V"

    .line 222
    .line 223
    invoke-direct/range {v10 .. v17}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v8, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    move-object v6, v10

    .line 230
    :cond_a
    check-cast v6, Lhy0/g;

    .line 231
    .line 232
    check-cast v6, Lay0/k;

    .line 233
    .line 234
    const/16 v5, 0x8

    .line 235
    .line 236
    invoke-interface {v3, v4, v6, v8, v5}, Lmg/k;->i0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    goto :goto_8

    .line 240
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 243
    .line 244
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw v0

    .line 248
    :cond_c
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 249
    .line 250
    .line 251
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 252
    .line 253
    .line 254
    move-result-object v3

    .line 255
    if-eqz v3, :cond_d

    .line 256
    .line 257
    new-instance v4, Lsg/k;

    .line 258
    .line 259
    const/4 v5, 0x0

    .line 260
    invoke-direct {v4, v0, v1, v2, v5}, Lsg/k;-><init>(Ljava/lang/String;Lxh/e;II)V

    .line 261
    .line 262
    .line 263
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 264
    .line 265
    :cond_d
    return-void
.end method

.method public static final b(Landroid/content/pm/PackageManager;Landroid/content/Intent;I)Ljava/util/List;
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x21

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    int-to-long v0, p2

    .line 8
    invoke-static {v0, v1}, Lb/s;->c(J)Landroid/content/pm/PackageManager$ResolveInfoFlags;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    invoke-static {p0, p1, p2}, Lb/s;->s(Landroid/content/pm/PackageManager;Landroid/content/Intent;Landroid/content/pm/PackageManager$ResolveInfoFlags;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    invoke-virtual {p0, p1, p2}, Landroid/content/pm/PackageManager;->queryIntentActivities(Landroid/content/Intent;I)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method
