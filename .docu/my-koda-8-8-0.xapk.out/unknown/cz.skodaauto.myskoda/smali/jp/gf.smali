.class public abstract Ljp/gf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lqb/e;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V
    .locals 10

    .line 1
    move/from16 v7, p7

    .line 2
    .line 3
    const-string v0, "onDenied"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "onDeniedAfterSettingsResult"

    .line 9
    .line 10
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v0, "onNotGrantedYet"

    .line 14
    .line 15
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    move-object/from16 v0, p6

    .line 19
    .line 20
    check-cast v0, Ll2/t;

    .line 21
    .line 22
    const v1, 0x776c8ee7

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 26
    .line 27
    .line 28
    and-int/lit8 v1, v7, 0x6

    .line 29
    .line 30
    if-nez v1, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    const/4 v1, 0x4

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v1, 0x2

    .line 41
    :goto_0
    or-int/2addr v1, v7

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v1, v7

    .line 44
    :goto_1
    and-int/lit8 v2, v7, 0x30

    .line 45
    .line 46
    if-nez v2, :cond_3

    .line 47
    .line 48
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    const/16 v2, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v2, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr v1, v2

    .line 60
    :cond_3
    and-int/lit16 v2, v7, 0x180

    .line 61
    .line 62
    if-nez v2, :cond_5

    .line 63
    .line 64
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_4

    .line 69
    .line 70
    const/16 v2, 0x100

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    const/16 v2, 0x80

    .line 74
    .line 75
    :goto_3
    or-int/2addr v1, v2

    .line 76
    :cond_5
    and-int/lit16 v2, v7, 0xc00

    .line 77
    .line 78
    if-nez v2, :cond_7

    .line 79
    .line 80
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_6

    .line 85
    .line 86
    const/16 v2, 0x800

    .line 87
    .line 88
    goto :goto_4

    .line 89
    :cond_6
    const/16 v2, 0x400

    .line 90
    .line 91
    :goto_4
    or-int/2addr v1, v2

    .line 92
    :cond_7
    and-int/lit16 v2, v7, 0x6000

    .line 93
    .line 94
    if-nez v2, :cond_9

    .line 95
    .line 96
    invoke-virtual {v0, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-eqz v2, :cond_8

    .line 101
    .line 102
    const/16 v2, 0x4000

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_8
    const/16 v2, 0x2000

    .line 106
    .line 107
    :goto_5
    or-int/2addr v1, v2

    .line 108
    :cond_9
    const/high16 v2, 0x30000

    .line 109
    .line 110
    and-int/2addr v2, v7

    .line 111
    if-nez v2, :cond_b

    .line 112
    .line 113
    invoke-virtual {v0, p5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_a

    .line 118
    .line 119
    const/high16 v2, 0x20000

    .line 120
    .line 121
    goto :goto_6

    .line 122
    :cond_a
    const/high16 v2, 0x10000

    .line 123
    .line 124
    :goto_6
    or-int/2addr v1, v2

    .line 125
    :cond_b
    const v2, 0x12493

    .line 126
    .line 127
    .line 128
    and-int/2addr v2, v1

    .line 129
    const v3, 0x12492

    .line 130
    .line 131
    .line 132
    const/4 v4, 0x0

    .line 133
    if-eq v2, v3, :cond_c

    .line 134
    .line 135
    const/4 v2, 0x1

    .line 136
    goto :goto_7

    .line 137
    :cond_c
    move v2, v4

    .line 138
    :goto_7
    and-int/lit8 v3, v1, 0x1

    .line 139
    .line 140
    invoke-virtual {v0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    if-eqz v2, :cond_14

    .line 145
    .line 146
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 147
    .line 148
    .line 149
    and-int/lit8 v2, v7, 0x1

    .line 150
    .line 151
    if-eqz v2, :cond_e

    .line 152
    .line 153
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 154
    .line 155
    .line 156
    move-result v2

    .line 157
    if-eqz v2, :cond_d

    .line 158
    .line 159
    goto :goto_8

    .line 160
    :cond_d
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 161
    .line 162
    .line 163
    :cond_e
    :goto_8
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 164
    .line 165
    .line 166
    sget-object v2, Lqb/d;->c:Lqb/d;

    .line 167
    .line 168
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    if-eqz v2, :cond_f

    .line 173
    .line 174
    const v2, 0x4e849512

    .line 175
    .line 176
    .line 177
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 178
    .line 179
    .line 180
    shr-int/lit8 v1, v1, 0xf

    .line 181
    .line 182
    and-int/lit8 v1, v1, 0xe

    .line 183
    .line 184
    invoke-static {v1, p5, v0, v4}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_9

    .line 188
    :cond_f
    sget-object v1, Lqb/d;->e:Lqb/d;

    .line 189
    .line 190
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v1

    .line 194
    if-eqz v1, :cond_10

    .line 195
    .line 196
    const v1, 0x4e849a7e

    .line 197
    .line 198
    .line 199
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    goto :goto_9

    .line 209
    :cond_10
    sget-object v1, Lqb/d;->a:Lqb/d;

    .line 210
    .line 211
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v1

    .line 215
    if-eqz v1, :cond_11

    .line 216
    .line 217
    const v1, 0x4e849fb1

    .line 218
    .line 219
    .line 220
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 224
    .line 225
    .line 226
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    goto :goto_9

    .line 230
    :cond_11
    sget-object v1, Lqb/d;->b:Lqb/d;

    .line 231
    .line 232
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    if-eqz v1, :cond_12

    .line 237
    .line 238
    const v1, 0x4e84a5c4

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    invoke-interface {p3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    goto :goto_9

    .line 251
    :cond_12
    sget-object v1, Lqb/d;->d:Lqb/d;

    .line 252
    .line 253
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v1

    .line 257
    if-eqz v1, :cond_13

    .line 258
    .line 259
    const v1, 0x4e84ac98

    .line 260
    .line 261
    .line 262
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    invoke-interface {p4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    goto :goto_9

    .line 272
    :cond_13
    const v1, 0x4e84b0cb

    .line 273
    .line 274
    .line 275
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 279
    .line 280
    .line 281
    goto :goto_9

    .line 282
    :cond_14
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 283
    .line 284
    .line 285
    :goto_9
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 286
    .line 287
    .line 288
    move-result-object v9

    .line 289
    if-eqz v9, :cond_15

    .line 290
    .line 291
    new-instance v0, Ld80/d;

    .line 292
    .line 293
    const/4 v8, 0x7

    .line 294
    move-object v1, p0

    .line 295
    move-object v2, p1

    .line 296
    move-object v3, p2

    .line 297
    move-object v4, p3

    .line 298
    move-object v5, p4

    .line 299
    move-object v6, p5

    .line 300
    invoke-direct/range {v0 .. v8}, Ld80/d;-><init>(Ljava/lang/Object;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Llx0/e;II)V

    .line 301
    .line 302
    .line 303
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 304
    .line 305
    :cond_15
    return-void
.end method

.method public static final b(Ll2/o;)Lqb/c;
    .locals 4

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/content/Context;

    .line 10
    .line 11
    invoke-static {p0}, Lc/i;->a(Ll2/o;)Le/i;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-interface {v1}, Le/i;->getActivityResultRegistry()Le/h;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v1, 0x0

    .line 23
    :goto_0
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 28
    .line 29
    if-ne v2, v3, :cond_1

    .line 30
    .line 31
    new-instance v2, Lqb/c;

    .line 32
    .line 33
    invoke-direct {v2, v1, v0}, Lqb/c;-><init>(Le/h;Landroid/content/Context;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    check-cast v2, Lqb/c;

    .line 40
    .line 41
    return-object v2
.end method

.method public static final c(Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;)Lg40/p;
    .locals 25

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lg40/p;

    .line 9
    .line 10
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getId()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getType()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    sparse-switch v4, :sswitch_data_0

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :sswitch_0
    const-string v4, "SERVICE_APPOINTMENT"

    .line 30
    .line 31
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-nez v3, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    sget-object v3, Lg40/s;->h:Lg40/s;

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :sswitch_1
    const-string v4, "MARKETING_CONSENT"

    .line 42
    .line 43
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-nez v3, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    sget-object v3, Lg40/s;->e:Lg40/s;

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :sswitch_2
    const-string v4, "PROLONGATION"

    .line 54
    .line 55
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-nez v3, :cond_2

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    sget-object v3, Lg40/s;->g:Lg40/s;

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :sswitch_3
    const-string v4, "PREFERRED_DEALER_SELECTION"

    .line 66
    .line 67
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-nez v3, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    sget-object v3, Lg40/s;->f:Lg40/s;

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :sswitch_4
    const-string v4, "CAR_IN_GARAGE"

    .line 78
    .line 79
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_5

    .line 84
    .line 85
    sget-object v3, Lg40/s;->d:Lg40/s;

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :sswitch_5
    const-string v4, "TELEMETRIC"

    .line 89
    .line 90
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    if-nez v3, :cond_4

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_4
    sget-object v3, Lg40/s;->i:Lg40/s;

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :sswitch_6
    const-string v4, "THIRD_PARTY_CONSENT"

    .line 101
    .line 102
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-nez v3, :cond_6

    .line 107
    .line 108
    :cond_5
    :goto_0
    sget-object v3, Lg40/s;->k:Lg40/s;

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_6
    sget-object v3, Lg40/s;->j:Lg40/s;

    .line 112
    .line 113
    :goto_1
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getStatus()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    sparse-switch v0, :sswitch_data_1

    .line 125
    .line 126
    .line 127
    goto :goto_3

    .line 128
    :sswitch_7
    const-string v0, "FAILED"

    .line 129
    .line 130
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-nez v0, :cond_7

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_7
    sget-object v0, Lg40/r;->h:Lg40/r;

    .line 138
    .line 139
    :goto_2
    move-object v4, v0

    .line 140
    goto :goto_4

    .line 141
    :sswitch_8
    const-string v0, "ACTIVE"

    .line 142
    .line 143
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-nez v0, :cond_8

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_8
    sget-object v0, Lg40/r;->e:Lg40/r;

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :sswitch_9
    const-string v0, "COMPLETED"

    .line 154
    .line 155
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    if-nez v0, :cond_9

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_9
    sget-object v0, Lg40/r;->g:Lg40/r;

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :sswitch_a
    const-string v0, "INACTIVE"

    .line 166
    .line 167
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-eqz v0, :cond_a

    .line 172
    .line 173
    sget-object v0, Lg40/r;->d:Lg40/r;

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :sswitch_b
    const-string v0, "IN_PROGRESS"

    .line 177
    .line 178
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    if-nez v0, :cond_b

    .line 183
    .line 184
    :cond_a
    :goto_3
    sget-object v0, Lg40/r;->i:Lg40/r;

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_b
    sget-object v0, Lg40/r;->f:Lg40/r;

    .line 188
    .line 189
    goto :goto_2

    .line 190
    :goto_4
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getEnrollmentRequired()Z

    .line 191
    .line 192
    .line 193
    move-result v5

    .line 194
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getName()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getDescription()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getDetailedDescription()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v8

    .line 206
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getPoints()I

    .line 207
    .line 208
    .line 209
    move-result v9

    .line 210
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getImageUrl()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v10

    .line 214
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getHighlighted()Z

    .line 215
    .line 216
    .line 217
    move-result v11

    .line 218
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getDisplayImage()Z

    .line 219
    .line 220
    .line 221
    move-result v12

    .line 222
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getTotalActivities()I

    .line 223
    .line 224
    .line 225
    move-result v13

    .line 226
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getCompletedActivities()I

    .line 227
    .line 228
    .line 229
    move-result v14

    .line 230
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getEndsAt()Ljava/time/OffsetDateTime;

    .line 231
    .line 232
    .line 233
    move-result-object v15

    .line 234
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getCompletedAt()Ljava/time/OffsetDateTime;

    .line 235
    .line 236
    .line 237
    move-result-object v16

    .line 238
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getVin()Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object v17

    .line 242
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getVehicleName()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v18

    .line 246
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getShowEligibilityHint()Ljava/lang/Boolean;

    .line 247
    .line 248
    .line 249
    move-result-object v19

    .line 250
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getProgressType()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    move-object/from16 v20, v1

    .line 255
    .line 256
    if-eqz v0, :cond_e

    .line 257
    .line 258
    const-string v1, "STANDARD"

    .line 259
    .line 260
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v1

    .line 264
    if-eqz v1, :cond_c

    .line 265
    .line 266
    sget-object v0, Lg40/q;->d:Lg40/q;

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_c
    const-string v1, "NEGATIVE"

    .line 270
    .line 271
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v0

    .line 275
    if-eqz v0, :cond_d

    .line 276
    .line 277
    sget-object v0, Lg40/q;->e:Lg40/q;

    .line 278
    .line 279
    goto :goto_5

    .line 280
    :cond_d
    sget-object v0, Lg40/q;->f:Lg40/q;

    .line 281
    .line 282
    goto :goto_5

    .line 283
    :cond_e
    const/4 v0, 0x0

    .line 284
    :goto_5
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getMaxFailedAttempts()Ljava/lang/Integer;

    .line 285
    .line 286
    .line 287
    move-result-object v21

    .line 288
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getAttemptsRemaining()Ljava/lang/Integer;

    .line 289
    .line 290
    .line 291
    move-result-object v22

    .line 292
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getDaysToComplete()Ljava/lang/Integer;

    .line 293
    .line 294
    .line 295
    move-result-object v23

    .line 296
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;->getDaysCompleted()Ljava/lang/Integer;

    .line 297
    .line 298
    .line 299
    move-result-object v24

    .line 300
    move-object/from16 v1, v20

    .line 301
    .line 302
    move-object/from16 v20, v0

    .line 303
    .line 304
    invoke-direct/range {v1 .. v24}, Lg40/p;-><init>(Ljava/lang/String;Lg40/s;Lg40/r;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ZZIILjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lg40/q;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 305
    .line 306
    .line 307
    return-object v1

    .line 308
    nop

    .line 309
    :sswitch_data_0
    .sparse-switch
        -0x780cf977 -> :sswitch_6
        -0x4134c226 -> :sswitch_5
        -0x3aa6734a -> :sswitch_4
        0x294176e4 -> :sswitch_3
        0x294609ec -> :sswitch_2
        0x3fa266c1 -> :sswitch_1
        0x503c68d5 -> :sswitch_0
    .end sparse-switch

    .line 310
    .line 311
    .line 312
    .line 313
    .line 314
    .line 315
    .line 316
    .line 317
    .line 318
    .line 319
    .line 320
    .line 321
    .line 322
    .line 323
    .line 324
    .line 325
    .line 326
    .line 327
    .line 328
    .line 329
    .line 330
    .line 331
    .line 332
    .line 333
    .line 334
    .line 335
    .line 336
    .line 337
    .line 338
    .line 339
    :sswitch_data_1
    .sparse-switch
        -0x2408abf9 -> :sswitch_b
        0x301e4c6b -> :sswitch_a
        0x5279062b -> :sswitch_9
        0x72c27306 -> :sswitch_8
        0x7b29883d -> :sswitch_7
    .end sparse-switch
.end method
