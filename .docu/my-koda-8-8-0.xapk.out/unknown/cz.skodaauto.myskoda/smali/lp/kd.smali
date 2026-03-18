.class public abstract Llp/kd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxh/e;Lay0/k;Ll2/o;I)V
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
    const-string v3, "exportFilters"

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
    const v3, -0x593db75c

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v3, v2, 0x6

    .line 23
    .line 24
    const/4 v4, 0x4

    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    move v3, v4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int/2addr v3, v2

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v3, v2

    .line 39
    :goto_1
    and-int/lit8 v5, v2, 0x30

    .line 40
    .line 41
    const/16 v6, 0x20

    .line 42
    .line 43
    if-nez v5, :cond_3

    .line 44
    .line 45
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eqz v5, :cond_2

    .line 50
    .line 51
    move v5, v6

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v5, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v3, v5

    .line 56
    :cond_3
    and-int/lit8 v5, v3, 0x13

    .line 57
    .line 58
    const/16 v7, 0x12

    .line 59
    .line 60
    const/4 v8, 0x1

    .line 61
    const/4 v10, 0x0

    .line 62
    if-eq v5, v7, :cond_4

    .line 63
    .line 64
    move v5, v8

    .line 65
    goto :goto_3

    .line 66
    :cond_4
    move v5, v10

    .line 67
    :goto_3
    and-int/lit8 v7, v3, 0x1

    .line 68
    .line 69
    invoke-virtual {v9, v7, v5}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    if-eqz v5, :cond_e

    .line 74
    .line 75
    and-int/lit8 v5, v3, 0xe

    .line 76
    .line 77
    if-ne v5, v4, :cond_5

    .line 78
    .line 79
    move v4, v8

    .line 80
    goto :goto_4

    .line 81
    :cond_5
    move v4, v10

    .line 82
    :goto_4
    and-int/lit8 v3, v3, 0x70

    .line 83
    .line 84
    if-ne v3, v6, :cond_6

    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_6
    move v8, v10

    .line 88
    :goto_5
    or-int v3, v4, v8

    .line 89
    .line 90
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-nez v3, :cond_7

    .line 97
    .line 98
    if-ne v4, v11, :cond_8

    .line 99
    .line 100
    :cond_7
    new-instance v4, Li40/j0;

    .line 101
    .line 102
    const/16 v3, 0x1c

    .line 103
    .line 104
    invoke-direct {v4, v3, v0, v1}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_8
    check-cast v4, Lay0/k;

    .line 111
    .line 112
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 113
    .line 114
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    check-cast v3, Ljava/lang/Boolean;

    .line 119
    .line 120
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-eqz v3, :cond_9

    .line 125
    .line 126
    const v3, -0x105bcaaa

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    const/4 v3, 0x0

    .line 136
    goto :goto_6

    .line 137
    :cond_9
    const v3, 0x31054eee

    .line 138
    .line 139
    .line 140
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 141
    .line 142
    .line 143
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 144
    .line 145
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    check-cast v3, Lhi/a;

    .line 150
    .line 151
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 152
    .line 153
    .line 154
    :goto_6
    new-instance v7, Laf/a;

    .line 155
    .line 156
    const/16 v5, 0x17

    .line 157
    .line 158
    invoke-direct {v7, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 162
    .line 163
    .line 164
    move-result-object v5

    .line 165
    if-eqz v5, :cond_d

    .line 166
    .line 167
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 168
    .line 169
    if-eqz v3, :cond_a

    .line 170
    .line 171
    move-object v3, v5

    .line 172
    check-cast v3, Landroidx/lifecycle/k;

    .line 173
    .line 174
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    :goto_7
    move-object v8, v3

    .line 179
    goto :goto_8

    .line 180
    :cond_a
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :goto_8
    const-class v3, Lkd/p;

    .line 184
    .line 185
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 186
    .line 187
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    const/4 v6, 0x0

    .line 192
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    move-object v14, v3

    .line 197
    check-cast v14, Lkd/p;

    .line 198
    .line 199
    sget-object v3, Lzb/x;->b:Ll2/u2;

    .line 200
    .line 201
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    const-string v4, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.HomeChargingHistoryUi"

    .line 206
    .line 207
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    check-cast v3, Lfd/b;

    .line 211
    .line 212
    iget-object v4, v14, Lkd/p;->k:Lyy0/l1;

    .line 213
    .line 214
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    check-cast v4, Llc/q;

    .line 223
    .line 224
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result v5

    .line 228
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    if-nez v5, :cond_b

    .line 233
    .line 234
    if-ne v6, v11, :cond_c

    .line 235
    .line 236
    :cond_b
    new-instance v12, Lio/ktor/utils/io/g0;

    .line 237
    .line 238
    const/16 v18, 0x0

    .line 239
    .line 240
    const/16 v19, 0x14

    .line 241
    .line 242
    const/4 v13, 0x1

    .line 243
    const-class v15, Lkd/p;

    .line 244
    .line 245
    const-string v16, "onUiEvent"

    .line 246
    .line 247
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/charginghistory/presentation/home/overview/HomeChargingHistoryUiEvent;)V"

    .line 248
    .line 249
    invoke-direct/range {v12 .. v19}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    move-object v6, v12

    .line 256
    :cond_c
    check-cast v6, Lhy0/g;

    .line 257
    .line 258
    check-cast v6, Lay0/k;

    .line 259
    .line 260
    const/16 v5, 0x8

    .line 261
    .line 262
    invoke-interface {v3, v4, v6, v9, v5}, Lfd/b;->s0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 263
    .line 264
    .line 265
    goto :goto_9

    .line 266
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 267
    .line 268
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 269
    .line 270
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    throw v0

    .line 274
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 275
    .line 276
    .line 277
    :goto_9
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 278
    .line 279
    .line 280
    move-result-object v3

    .line 281
    if-eqz v3, :cond_f

    .line 282
    .line 283
    new-instance v4, Ljk/b;

    .line 284
    .line 285
    const/4 v5, 0x1

    .line 286
    invoke-direct {v4, v2, v5, v0, v1}, Ljk/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 290
    .line 291
    :cond_f
    return-void
.end method

.method public static final b(Lij0/a;Ljava/util/List;)Ljava/util/LinkedHashMap;
    .locals 14

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p1, Ljava/lang/Iterable;

    .line 12
    .line 13
    const/16 v0, 0xa

    .line 14
    .line 15
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-static {v0}, Lmx0/x;->k(I)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/16 v1, 0x10

    .line 24
    .line 25
    if-ge v0, v1, :cond_0

    .line 26
    .line 27
    move v0, v1

    .line 28
    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 29
    .line 30
    invoke-direct {v1, v0}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_5

    .line 42
    .line 43
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Lvk0/a0;

    .line 48
    .line 49
    new-instance v2, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 52
    .line 53
    .line 54
    iget-object v3, v0, Lvk0/a0;->a:Ljava/time/DayOfWeek;

    .line 55
    .line 56
    iget-boolean v4, v0, Lvk0/a0;->d:Z

    .line 57
    .line 58
    iget-object v5, v0, Lvk0/a0;->b:Ljava/time/DayOfWeek;

    .line 59
    .line 60
    sget-object v6, Lvk0/z;->a:[I

    .line 61
    .line 62
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    aget v6, v6, v7

    .line 67
    .line 68
    packed-switch v6, :pswitch_data_0

    .line 69
    .line 70
    .line 71
    new-instance p0, La8/r0;

    .line 72
    .line 73
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :pswitch_0
    sget-object v6, Ljava/time/DayOfWeek;->SATURDAY:Ljava/time/DayOfWeek;

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :pswitch_1
    sget-object v6, Ljava/time/DayOfWeek;->FRIDAY:Ljava/time/DayOfWeek;

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :pswitch_2
    sget-object v6, Ljava/time/DayOfWeek;->THURSDAY:Ljava/time/DayOfWeek;

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :pswitch_3
    sget-object v6, Ljava/time/DayOfWeek;->WEDNESDAY:Ljava/time/DayOfWeek;

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :pswitch_4
    sget-object v6, Ljava/time/DayOfWeek;->TUESDAY:Ljava/time/DayOfWeek;

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :pswitch_5
    sget-object v6, Ljava/time/DayOfWeek;->MONDAY:Ljava/time/DayOfWeek;

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :pswitch_6
    sget-object v6, Ljava/time/DayOfWeek;->SUNDAY:Ljava/time/DayOfWeek;

    .line 96
    .line 97
    :goto_1
    const/4 v7, 0x0

    .line 98
    if-ne v5, v6, :cond_1

    .line 99
    .line 100
    if-eqz v4, :cond_1

    .line 101
    .line 102
    new-array v3, v7, [Ljava/lang/Object;

    .line 103
    .line 104
    move-object v4, p0

    .line 105
    check-cast v4, Ljj0/f;

    .line 106
    .line 107
    const v5, 0x7f12068e

    .line 108
    .line 109
    .line 110
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_1
    if-eqz v4, :cond_2

    .line 119
    .line 120
    const-string v4, ""

    .line 121
    .line 122
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    move-object v6, p0

    .line 127
    check-cast v6, Ljj0/f;

    .line 128
    .line 129
    const v8, 0x7f12068d

    .line 130
    .line 131
    .line 132
    invoke-virtual {v6, v8, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    :cond_2
    invoke-static {v3}, Ljp/c1;->e(Ljava/time/DayOfWeek;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    if-eq v3, v5, :cond_3

    .line 147
    .line 148
    invoke-static {v5}, Ljp/c1;->e(Ljava/time/DayOfWeek;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    new-instance v4, Ljava/lang/StringBuilder;

    .line 153
    .line 154
    const-string v5, " - "

    .line 155
    .line 156
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    :cond_3
    :goto_2
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    iget-object v8, v0, Lvk0/a0;->c:Ljava/util/ArrayList;

    .line 174
    .line 175
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    if-eqz v0, :cond_4

    .line 180
    .line 181
    new-array v0, v7, [Ljava/lang/Object;

    .line 182
    .line 183
    move-object v3, p0

    .line 184
    check-cast v3, Ljj0/f;

    .line 185
    .line 186
    const v4, 0x7f1205f2

    .line 187
    .line 188
    .line 189
    invoke-virtual {v3, v4, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    goto :goto_3

    .line 194
    :cond_4
    new-instance v12, Lw81/d;

    .line 195
    .line 196
    const/4 v0, 0x5

    .line 197
    invoke-direct {v12, v0}, Lw81/d;-><init>(I)V

    .line 198
    .line 199
    .line 200
    const/16 v13, 0x1e

    .line 201
    .line 202
    const-string v9, "\n"

    .line 203
    .line 204
    const/4 v10, 0x0

    .line 205
    const/4 v11, 0x0

    .line 206
    invoke-static/range {v8 .. v13}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    :goto_3
    invoke-interface {v1, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    goto/16 :goto_0

    .line 214
    .line 215
    :cond_5
    return-object v1

    .line 216
    nop

    .line 217
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
