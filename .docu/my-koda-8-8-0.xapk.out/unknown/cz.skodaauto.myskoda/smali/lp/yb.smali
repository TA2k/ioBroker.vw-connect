.class public abstract Llp/yb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lh2/d6;Ll2/o;I)V
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
    const v3, -0x3775738f

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
    new-instance v4, Li40/j0;

    .line 86
    .line 87
    const/16 v3, 0x11

    .line 88
    .line 89
    invoke-direct {v4, v3, v0, v1}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_6
    check-cast v4, Lay0/k;

    .line 96
    .line 97
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 98
    .line 99
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    check-cast v3, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-eqz v3, :cond_7

    .line 110
    .line 111
    const v3, -0x105bcaaa

    .line 112
    .line 113
    .line 114
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 118
    .line 119
    .line 120
    const/4 v3, 0x0

    .line 121
    goto :goto_5

    .line 122
    :cond_7
    const v3, 0x31054eee

    .line 123
    .line 124
    .line 125
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 129
    .line 130
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    check-cast v3, Lhi/a;

    .line 135
    .line 136
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    :goto_5
    new-instance v6, Laf/a;

    .line 140
    .line 141
    const/16 v5, 0x16

    .line 142
    .line 143
    invoke-direct {v6, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 144
    .line 145
    .line 146
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    if-eqz v4, :cond_b

    .line 151
    .line 152
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 153
    .line 154
    if-eqz v3, :cond_8

    .line 155
    .line 156
    move-object v3, v4

    .line 157
    check-cast v3, Landroidx/lifecycle/k;

    .line 158
    .line 159
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    :goto_6
    move-object v7, v3

    .line 164
    goto :goto_7

    .line 165
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 166
    .line 167
    goto :goto_6

    .line 168
    :goto_7
    const-class v3, Ljh/l;

    .line 169
    .line 170
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 171
    .line 172
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    const/4 v5, 0x0

    .line 177
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    move-object v12, v3

    .line 182
    check-cast v12, Ljh/l;

    .line 183
    .line 184
    invoke-static {v8}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    iget-object v4, v12, Ljh/l;->j:Lyy0/l1;

    .line 189
    .line 190
    invoke-static {v4, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Llc/q;

    .line 199
    .line 200
    invoke-virtual {v8, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v5

    .line 204
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    if-nez v5, :cond_9

    .line 209
    .line 210
    if-ne v6, v9, :cond_a

    .line 211
    .line 212
    :cond_9
    new-instance v10, Lio/ktor/utils/io/g0;

    .line 213
    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    const/16 v17, 0x6

    .line 217
    .line 218
    const/4 v11, 0x1

    .line 219
    const-class v13, Ljh/l;

    .line 220
    .line 221
    const-string v14, "onUiEvent"

    .line 222
    .line 223
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/firmware/WallboxFirmwareUiEvent;)V"

    .line 224
    .line 225
    invoke-direct/range {v10 .. v17}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v8, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    move-object v6, v10

    .line 232
    :cond_a
    check-cast v6, Lhy0/g;

    .line 233
    .line 234
    check-cast v6, Lay0/k;

    .line 235
    .line 236
    const/16 v5, 0x8

    .line 237
    .line 238
    invoke-interface {v3, v4, v6, v8, v5}, Leh/n;->J(Llc/q;Lay0/k;Ll2/o;I)V

    .line 239
    .line 240
    .line 241
    goto :goto_8

    .line 242
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 243
    .line 244
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 245
    .line 246
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    throw v0

    .line 250
    :cond_c
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 251
    .line 252
    .line 253
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 254
    .line 255
    .line 256
    move-result-object v3

    .line 257
    if-eqz v3, :cond_d

    .line 258
    .line 259
    new-instance v4, Li40/k0;

    .line 260
    .line 261
    const/16 v5, 0x1c

    .line 262
    .line 263
    invoke-direct {v4, v2, v5, v0, v1}, Li40/k0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 267
    .line 268
    :cond_d
    return-void
.end method

.method public static final b(Lun0/a;)[Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_5

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    if-eq p0, v0, :cond_4

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    if-eq p0, v0, :cond_2

    .line 13
    .line 14
    const/4 v0, 0x3

    .line 15
    if-ne p0, v0, :cond_1

    .line 16
    .line 17
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 18
    .line 19
    const/16 v0, 0x21

    .line 20
    .line 21
    if-lt p0, v0, :cond_0

    .line 22
    .line 23
    const-string p0, "android.permission.POST_NOTIFICATIONS"

    .line 24
    .line 25
    filled-new-array {p0}, [Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    new-array p0, v1, [Ljava/lang/String;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    new-instance p0, La8/r0;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_2
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 40
    .line 41
    const/16 v0, 0x1f

    .line 42
    .line 43
    const-string v1, "android.permission.BLUETOOTH"

    .line 44
    .line 45
    if-lt p0, v0, :cond_3

    .line 46
    .line 47
    const-string p0, "android.permission.BLUETOOTH_SCAN"

    .line 48
    .line 49
    const-string v0, "android.permission.BLUETOOTH_CONNECT"

    .line 50
    .line 51
    filled-new-array {v1, p0, v0}, [Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :cond_3
    filled-new-array {v1}, [Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :cond_4
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string v0, "android.permission.ACCESS_BACKGROUND_LOCATION"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    .line 71
    .line 72
    invoke-virtual {p0, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    const-string v0, "android.permission.ACCESS_COARSE_LOCATION"

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    invoke-static {p0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    new-array v0, v1, [Ljava/lang/String;

    .line 85
    .line 86
    invoke-virtual {p0, v0}, Lnx0/c;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, [Ljava/lang/String;

    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_5
    const-string p0, "android.permission.CAMERA"

    .line 94
    .line 95
    filled-new-array {p0}, [Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0
.end method
