.class public final Lo8/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/r;


# static fields
.field public static final h:[I

.field public static final i:Lb81/b;

.field public static final j:Lb81/b;


# instance fields
.field public d:Lhr/x0;

.field public e:Z

.field public f:Lwe0/b;

.field public g:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x15

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lo8/m;->h:[I

    .line 9
    .line 10
    new-instance v0, Lb81/b;

    .line 11
    .line 12
    new-instance v1, Lj9/d;

    .line 13
    .line 14
    const/16 v2, 0xf

    .line 15
    .line 16
    invoke-direct {v1, v2}, Lj9/d;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, v1}, Lb81/b;-><init>(Lj9/d;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lo8/m;->i:Lb81/b;

    .line 23
    .line 24
    new-instance v0, Lb81/b;

    .line 25
    .line 26
    new-instance v1, Lj9/d;

    .line 27
    .line 28
    const/16 v2, 0x10

    .line 29
    .line 30
    invoke-direct {v1, v2}, Lj9/d;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-direct {v0, v1}, Lb81/b;-><init>(Lj9/d;)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Lo8/m;->j:Lb81/b;

    .line 37
    .line 38
    return-void

    .line 39
    :array_0
    .array-data 4
        0x5
        0x4
        0xc
        0x8
        0x3
        0xa
        0x9
        0xb
        0x6
        0x2
        0x0
        0x1
        0x7
        0x10
        0xf
        0xe
        0x11
        0x12
        0x13
        0x14
        0x15
    .end array-data
.end method


# virtual methods
.method public final a(Ljava/util/ArrayList;I)V
    .locals 6

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x0

    .line 4
    packed-switch p2, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    :pswitch_0
    goto :goto_0

    .line 8
    :pswitch_1
    new-instance p0, Lr8/a;

    .line 9
    .line 10
    invoke-direct {p0, v2}, Lr8/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_2
    new-instance p0, Lr8/a;

    .line 18
    .line 19
    invoke-direct {p0, v1}, Lr8/a;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_3
    new-instance p0, Lk9/a;

    .line 27
    .line 28
    invoke-direct {p0, v2, v1}, Lk9/a;-><init>(BI)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :pswitch_4
    new-instance p0, Lr8/a;

    .line 36
    .line 37
    invoke-direct {p0, v0}, Lr8/a;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_5
    new-instance p0, Lk9/a;

    .line 45
    .line 46
    invoke-direct {p0, v2, v2}, Lk9/a;-><init>(BI)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :pswitch_6
    new-instance p2, Lq8/b;

    .line 54
    .line 55
    iget-boolean v0, p0, Lo8/m;->e:Z

    .line 56
    .line 57
    xor-int/2addr v0, v1

    .line 58
    iget-object p0, p0, Lo8/m;->f:Lwe0/b;

    .line 59
    .line 60
    invoke-direct {p2, v0, p0}, Lq8/b;-><init>(ILwe0/b;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :pswitch_7
    sget-object p0, Lo8/m;->j:Lb81/b;

    .line 68
    .line 69
    new-array p2, v2, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-virtual {p0, p2}, Lb81/b;->o([Ljava/lang/Object;)Lo8/o;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-eqz p0, :cond_0

    .line 76
    .line 77
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    :cond_0
    :goto_0
    return-void

    .line 81
    :pswitch_8
    new-instance p2, Lk9/a;

    .line 82
    .line 83
    iget p0, p0, Lo8/m;->g:I

    .line 84
    .line 85
    invoke-direct {p2, p0}, Lk9/a;-><init>(I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :pswitch_9
    new-instance p0, Lw9/d;

    .line 93
    .line 94
    invoke-direct {p0}, Lw9/d;-><init>()V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :pswitch_a
    iget-object p2, p0, Lo8/m;->d:Lhr/x0;

    .line 102
    .line 103
    if-nez p2, :cond_1

    .line 104
    .line 105
    sget-object p2, Lhr/h0;->e:Lhr/f0;

    .line 106
    .line 107
    sget-object p2, Lhr/x0;->h:Lhr/x0;

    .line 108
    .line 109
    iput-object p2, p0, Lo8/m;->d:Lhr/x0;

    .line 110
    .line 111
    :cond_1
    new-instance p2, Lv9/d0;

    .line 112
    .line 113
    iget-boolean v0, p0, Lo8/m;->e:Z

    .line 114
    .line 115
    xor-int/2addr v0, v1

    .line 116
    iget-object v1, p0, Lo8/m;->f:Lwe0/b;

    .line 117
    .line 118
    new-instance v3, Lw7/u;

    .line 119
    .line 120
    const-wide/16 v4, 0x0

    .line 121
    .line 122
    invoke-direct {v3, v4, v5}, Lw7/u;-><init>(J)V

    .line 123
    .line 124
    .line 125
    new-instance v4, Laq/m;

    .line 126
    .line 127
    iget-object p0, p0, Lo8/m;->d:Lhr/x0;

    .line 128
    .line 129
    invoke-direct {v4, p0, v2}, Laq/m;-><init>(Ljava/util/List;Z)V

    .line 130
    .line 131
    .line 132
    invoke-direct {p2, v0, v1, v3, v4}, Lv9/d0;-><init>(ILl9/h;Lw7/u;Laq/m;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    return-void

    .line 139
    :pswitch_b
    new-instance p0, Lv9/z;

    .line 140
    .line 141
    invoke-direct {p0}, Lv9/z;-><init>()V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    return-void

    .line 148
    :pswitch_c
    new-instance p0, Lj9/e;

    .line 149
    .line 150
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    return-void

    .line 157
    :pswitch_d
    new-instance p2, Li9/j;

    .line 158
    .line 159
    iget-object v0, p0, Lo8/m;->f:Lwe0/b;

    .line 160
    .line 161
    iget-boolean v1, p0, Lo8/m;->e:Z

    .line 162
    .line 163
    if-eqz v1, :cond_2

    .line 164
    .line 165
    move v1, v2

    .line 166
    goto :goto_1

    .line 167
    :cond_2
    const/16 v1, 0x20

    .line 168
    .line 169
    :goto_1
    invoke-direct {p2, v0, v1}, Li9/j;-><init>(Ll9/h;I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    new-instance p2, Li9/m;

    .line 176
    .line 177
    iget-object v0, p0, Lo8/m;->f:Lwe0/b;

    .line 178
    .line 179
    iget-boolean p0, p0, Lo8/m;->e:Z

    .line 180
    .line 181
    if-eqz p0, :cond_3

    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_3
    const/16 v2, 0x10

    .line 185
    .line 186
    :goto_2
    invoke-direct {p2, v0, v2}, Li9/m;-><init>(Ll9/h;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    return-void

    .line 193
    :pswitch_e
    new-instance p0, Lh9/d;

    .line 194
    .line 195
    invoke-direct {p0}, Lh9/d;-><init>()V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :pswitch_f
    new-instance p2, Lg9/d;

    .line 203
    .line 204
    iget-object v1, p0, Lo8/m;->f:Lwe0/b;

    .line 205
    .line 206
    iget-boolean p0, p0, Lo8/m;->e:Z

    .line 207
    .line 208
    if-eqz p0, :cond_4

    .line 209
    .line 210
    move v0, v2

    .line 211
    :cond_4
    invoke-direct {p2, v1, v0}, Lg9/d;-><init>(Ll9/h;I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    return-void

    .line 218
    :pswitch_10
    new-instance p0, Lu8/b;

    .line 219
    .line 220
    invoke-direct {p0}, Lu8/b;-><init>()V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    return-void

    .line 227
    :pswitch_11
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    sget-object p2, Lo8/m;->i:Lb81/b;

    .line 236
    .line 237
    invoke-virtual {p2, p0}, Lb81/b;->o([Ljava/lang/Object;)Lo8/o;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    if-eqz p0, :cond_5

    .line 242
    .line 243
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    return-void

    .line 247
    :cond_5
    new-instance p0, Lt8/c;

    .line 248
    .line 249
    invoke-direct {p0}, Lt8/c;-><init>()V

    .line 250
    .line 251
    .line 252
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    return-void

    .line 256
    :pswitch_12
    new-instance p0, Lp8/a;

    .line 257
    .line 258
    invoke-direct {p0}, Lp8/a;-><init>()V

    .line 259
    .line 260
    .line 261
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    return-void

    .line 265
    :pswitch_13
    new-instance p0, Lv9/d;

    .line 266
    .line 267
    invoke-direct {p0}, Lv9/d;-><init>()V

    .line 268
    .line 269
    .line 270
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    return-void

    .line 274
    :pswitch_14
    new-instance p0, Lv9/c;

    .line 275
    .line 276
    invoke-direct {p0}, Lv9/c;-><init>()V

    .line 277
    .line 278
    .line 279
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    return-void

    .line 283
    :pswitch_15
    new-instance p0, Lv9/a;

    .line 284
    .line 285
    invoke-direct {p0}, Lv9/a;-><init>()V

    .line 286
    .line 287
    .line 288
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    return-void

    .line 292
    nop

    .line 293
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final declared-synchronized c(Landroid/net/Uri;Ljava/util/Map;)[Lo8/o;
    .locals 27

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    sget-object v2, Lo8/m;->h:[I

    .line 7
    .line 8
    const/16 v3, 0x15

    .line 9
    .line 10
    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 11
    .line 12
    .line 13
    const-string v4, "Content-Type"

    .line 14
    .line 15
    move-object/from16 v5, p2

    .line 16
    .line 17
    invoke-interface {v5, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    check-cast v4, Ljava/util/List;

    .line 22
    .line 23
    const/4 v5, 0x0

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    if-eqz v6, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-interface {v4, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Ljava/lang/String;

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    :goto_0
    const/4 v4, 0x0

    .line 41
    :goto_1
    const/4 v6, -0x1

    .line 42
    if-nez v4, :cond_2

    .line 43
    .line 44
    goto/16 :goto_4

    .line 45
    .line 46
    :cond_2
    invoke-static {v4}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v7

    .line 57
    const/16 v8, 0x14

    .line 58
    .line 59
    const/16 v9, 0x13

    .line 60
    .line 61
    const/16 v10, 0x12

    .line 62
    .line 63
    const/16 v11, 0x11

    .line 64
    .line 65
    const/16 v12, 0x10

    .line 66
    .line 67
    const/16 v13, 0xf

    .line 68
    .line 69
    const/16 v14, 0xe

    .line 70
    .line 71
    const/16 v15, 0xd

    .line 72
    .line 73
    const/16 v16, 0xc

    .line 74
    .line 75
    const/16 v17, 0xb

    .line 76
    .line 77
    const/16 v18, 0xa

    .line 78
    .line 79
    const/16 v19, 0x9

    .line 80
    .line 81
    const/16 v20, 0x8

    .line 82
    .line 83
    const/16 v21, 0x7

    .line 84
    .line 85
    const/16 v22, 0x6

    .line 86
    .line 87
    const/16 v23, 0x5

    .line 88
    .line 89
    const/16 v24, 0x4

    .line 90
    .line 91
    const/16 v25, 0x3

    .line 92
    .line 93
    const/16 v26, 0x1

    .line 94
    .line 95
    sparse-switch v7, :sswitch_data_0

    .line 96
    .line 97
    .line 98
    :goto_2
    move v4, v6

    .line 99
    goto/16 :goto_3

    .line 100
    .line 101
    :sswitch_0
    const-string v7, "video/x-matroska"

    .line 102
    .line 103
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-nez v4, :cond_3

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_3
    const/16 v4, 0x1f

    .line 111
    .line 112
    goto/16 :goto_3

    .line 113
    .line 114
    :sswitch_1
    const-string v7, "audio/webm"

    .line 115
    .line 116
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-nez v4, :cond_4

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_4
    const/16 v4, 0x1e

    .line 124
    .line 125
    goto/16 :goto_3

    .line 126
    .line 127
    :sswitch_2
    const-string v7, "audio/mpeg"

    .line 128
    .line 129
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-nez v4, :cond_5

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_5
    const/16 v4, 0x1d

    .line 137
    .line 138
    goto/16 :goto_3

    .line 139
    .line 140
    :sswitch_3
    const-string v7, "audio/midi"

    .line 141
    .line 142
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-nez v4, :cond_6

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_6
    const/16 v4, 0x1c

    .line 150
    .line 151
    goto/16 :goto_3

    .line 152
    .line 153
    :sswitch_4
    const-string v7, "audio/flac"

    .line 154
    .line 155
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v4

    .line 159
    if-nez v4, :cond_7

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_7
    const/16 v4, 0x1b

    .line 163
    .line 164
    goto/16 :goto_3

    .line 165
    .line 166
    :sswitch_5
    const-string v7, "audio/eac3"

    .line 167
    .line 168
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v4

    .line 172
    if-nez v4, :cond_8

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_8
    const/16 v4, 0x1a

    .line 176
    .line 177
    goto/16 :goto_3

    .line 178
    .line 179
    :sswitch_6
    const-string v7, "audio/3gpp"

    .line 180
    .line 181
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    if-nez v4, :cond_9

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_9
    const/16 v4, 0x19

    .line 189
    .line 190
    goto/16 :goto_3

    .line 191
    .line 192
    :sswitch_7
    const-string v7, "video/mp4"

    .line 193
    .line 194
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v4

    .line 198
    if-nez v4, :cond_a

    .line 199
    .line 200
    goto :goto_2

    .line 201
    :cond_a
    const/16 v4, 0x18

    .line 202
    .line 203
    goto/16 :goto_3

    .line 204
    .line 205
    :sswitch_8
    const-string v7, "audio/wav"

    .line 206
    .line 207
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    if-nez v4, :cond_b

    .line 212
    .line 213
    goto :goto_2

    .line 214
    :cond_b
    const/16 v4, 0x17

    .line 215
    .line 216
    goto/16 :goto_3

    .line 217
    .line 218
    :sswitch_9
    const-string v7, "audio/ogg"

    .line 219
    .line 220
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v4

    .line 224
    if-nez v4, :cond_c

    .line 225
    .line 226
    goto/16 :goto_2

    .line 227
    .line 228
    :cond_c
    const/16 v4, 0x16

    .line 229
    .line 230
    goto/16 :goto_3

    .line 231
    .line 232
    :sswitch_a
    const-string v7, "audio/mp4"

    .line 233
    .line 234
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v4

    .line 238
    if-nez v4, :cond_d

    .line 239
    .line 240
    goto/16 :goto_2

    .line 241
    .line 242
    :cond_d
    move v4, v3

    .line 243
    goto/16 :goto_3

    .line 244
    .line 245
    :sswitch_b
    const-string v7, "audio/amr"

    .line 246
    .line 247
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v4

    .line 251
    if-nez v4, :cond_e

    .line 252
    .line 253
    goto/16 :goto_2

    .line 254
    .line 255
    :cond_e
    move v4, v8

    .line 256
    goto/16 :goto_3

    .line 257
    .line 258
    :sswitch_c
    const-string v7, "audio/ac4"

    .line 259
    .line 260
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v4

    .line 264
    if-nez v4, :cond_f

    .line 265
    .line 266
    goto/16 :goto_2

    .line 267
    .line 268
    :cond_f
    move v4, v9

    .line 269
    goto/16 :goto_3

    .line 270
    .line 271
    :sswitch_d
    const-string v7, "audio/ac3"

    .line 272
    .line 273
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 274
    .line 275
    .line 276
    move-result v4

    .line 277
    if-nez v4, :cond_10

    .line 278
    .line 279
    goto/16 :goto_2

    .line 280
    .line 281
    :cond_10
    move v4, v10

    .line 282
    goto/16 :goto_3

    .line 283
    .line 284
    :sswitch_e
    const-string v7, "video/x-flv"

    .line 285
    .line 286
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v4

    .line 290
    if-nez v4, :cond_11

    .line 291
    .line 292
    goto/16 :goto_2

    .line 293
    .line 294
    :cond_11
    move v4, v11

    .line 295
    goto/16 :goto_3

    .line 296
    .line 297
    :sswitch_f
    const-string v7, "application/webm"

    .line 298
    .line 299
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    move-result v4

    .line 303
    if-nez v4, :cond_12

    .line 304
    .line 305
    goto/16 :goto_2

    .line 306
    .line 307
    :cond_12
    move v4, v12

    .line 308
    goto/16 :goto_3

    .line 309
    .line 310
    :sswitch_10
    const-string v7, "audio/x-matroska"

    .line 311
    .line 312
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result v4

    .line 316
    if-nez v4, :cond_13

    .line 317
    .line 318
    goto/16 :goto_2

    .line 319
    .line 320
    :cond_13
    move v4, v13

    .line 321
    goto/16 :goto_3

    .line 322
    .line 323
    :sswitch_11
    const-string v7, "image/png"

    .line 324
    .line 325
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v4

    .line 329
    if-nez v4, :cond_14

    .line 330
    .line 331
    goto/16 :goto_2

    .line 332
    .line 333
    :cond_14
    move v4, v14

    .line 334
    goto/16 :goto_3

    .line 335
    .line 336
    :sswitch_12
    const-string v7, "image/bmp"

    .line 337
    .line 338
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    move-result v4

    .line 342
    if-nez v4, :cond_15

    .line 343
    .line 344
    goto/16 :goto_2

    .line 345
    .line 346
    :cond_15
    move v4, v15

    .line 347
    goto/16 :goto_3

    .line 348
    .line 349
    :sswitch_13
    const-string v7, "text/vtt"

    .line 350
    .line 351
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 352
    .line 353
    .line 354
    move-result v4

    .line 355
    if-nez v4, :cond_16

    .line 356
    .line 357
    goto/16 :goto_2

    .line 358
    .line 359
    :cond_16
    move/from16 v4, v16

    .line 360
    .line 361
    goto/16 :goto_3

    .line 362
    .line 363
    :sswitch_14
    const-string v7, "video/x-msvideo"

    .line 364
    .line 365
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 366
    .line 367
    .line 368
    move-result v4

    .line 369
    if-nez v4, :cond_17

    .line 370
    .line 371
    goto/16 :goto_2

    .line 372
    .line 373
    :cond_17
    move/from16 v4, v17

    .line 374
    .line 375
    goto/16 :goto_3

    .line 376
    .line 377
    :sswitch_15
    const-string v7, "application/mp4"

    .line 378
    .line 379
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 380
    .line 381
    .line 382
    move-result v4

    .line 383
    if-nez v4, :cond_18

    .line 384
    .line 385
    goto/16 :goto_2

    .line 386
    .line 387
    :cond_18
    move/from16 v4, v18

    .line 388
    .line 389
    goto/16 :goto_3

    .line 390
    .line 391
    :sswitch_16
    const-string v7, "image/webp"

    .line 392
    .line 393
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    move-result v4

    .line 397
    if-nez v4, :cond_19

    .line 398
    .line 399
    goto/16 :goto_2

    .line 400
    .line 401
    :cond_19
    move/from16 v4, v19

    .line 402
    .line 403
    goto/16 :goto_3

    .line 404
    .line 405
    :sswitch_17
    const-string v7, "image/jpeg"

    .line 406
    .line 407
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v4

    .line 411
    if-nez v4, :cond_1a

    .line 412
    .line 413
    goto/16 :goto_2

    .line 414
    .line 415
    :cond_1a
    move/from16 v4, v20

    .line 416
    .line 417
    goto/16 :goto_3

    .line 418
    .line 419
    :sswitch_18
    const-string v7, "image/heif"

    .line 420
    .line 421
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 422
    .line 423
    .line 424
    move-result v4

    .line 425
    if-nez v4, :cond_1b

    .line 426
    .line 427
    goto/16 :goto_2

    .line 428
    .line 429
    :cond_1b
    move/from16 v4, v21

    .line 430
    .line 431
    goto :goto_3

    .line 432
    :sswitch_19
    const-string v7, "image/heic"

    .line 433
    .line 434
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 435
    .line 436
    .line 437
    move-result v4

    .line 438
    if-nez v4, :cond_1c

    .line 439
    .line 440
    goto/16 :goto_2

    .line 441
    .line 442
    :cond_1c
    move/from16 v4, v22

    .line 443
    .line 444
    goto :goto_3

    .line 445
    :sswitch_1a
    const-string v7, "image/avif"

    .line 446
    .line 447
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v4

    .line 451
    if-nez v4, :cond_1d

    .line 452
    .line 453
    goto/16 :goto_2

    .line 454
    .line 455
    :cond_1d
    move/from16 v4, v23

    .line 456
    .line 457
    goto :goto_3

    .line 458
    :sswitch_1b
    const-string v7, "audio/amr-wb"

    .line 459
    .line 460
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v4

    .line 464
    if-nez v4, :cond_1e

    .line 465
    .line 466
    goto/16 :goto_2

    .line 467
    .line 468
    :cond_1e
    move/from16 v4, v24

    .line 469
    .line 470
    goto :goto_3

    .line 471
    :sswitch_1c
    const-string v7, "video/webm"

    .line 472
    .line 473
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    move-result v4

    .line 477
    if-nez v4, :cond_1f

    .line 478
    .line 479
    goto/16 :goto_2

    .line 480
    .line 481
    :cond_1f
    move/from16 v4, v25

    .line 482
    .line 483
    goto :goto_3

    .line 484
    :sswitch_1d
    const-string v7, "video/mp2t"

    .line 485
    .line 486
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 487
    .line 488
    .line 489
    move-result v4

    .line 490
    if-nez v4, :cond_20

    .line 491
    .line 492
    goto/16 :goto_2

    .line 493
    .line 494
    :cond_20
    const/4 v4, 0x2

    .line 495
    goto :goto_3

    .line 496
    :sswitch_1e
    const-string v7, "video/mp2p"

    .line 497
    .line 498
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 499
    .line 500
    .line 501
    move-result v4

    .line 502
    if-nez v4, :cond_21

    .line 503
    .line 504
    goto/16 :goto_2

    .line 505
    .line 506
    :cond_21
    move/from16 v4, v26

    .line 507
    .line 508
    goto :goto_3

    .line 509
    :sswitch_1f
    const-string v7, "audio/eac3-joc"

    .line 510
    .line 511
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result v4

    .line 515
    if-nez v4, :cond_22

    .line 516
    .line 517
    goto/16 :goto_2

    .line 518
    .line 519
    :cond_22
    move v4, v5

    .line 520
    :goto_3
    packed-switch v4, :pswitch_data_0

    .line 521
    .line 522
    .line 523
    :goto_4
    move v8, v6

    .line 524
    goto :goto_5

    .line 525
    :pswitch_0
    move/from16 v8, v21

    .line 526
    .line 527
    goto :goto_5

    .line 528
    :pswitch_1
    move v8, v13

    .line 529
    goto :goto_5

    .line 530
    :pswitch_2
    move/from16 v8, v24

    .line 531
    .line 532
    goto :goto_5

    .line 533
    :pswitch_3
    move/from16 v8, v16

    .line 534
    .line 535
    goto :goto_5

    .line 536
    :pswitch_4
    move/from16 v8, v19

    .line 537
    .line 538
    goto :goto_5

    .line 539
    :pswitch_5
    move/from16 v8, v26

    .line 540
    .line 541
    goto :goto_5

    .line 542
    :pswitch_6
    move/from16 v8, v23

    .line 543
    .line 544
    goto :goto_5

    .line 545
    :pswitch_7
    move v8, v11

    .line 546
    goto :goto_5

    .line 547
    :pswitch_8
    move v8, v9

    .line 548
    goto :goto_5

    .line 549
    :pswitch_9
    move v8, v15

    .line 550
    goto :goto_5

    .line 551
    :pswitch_a
    move v8, v12

    .line 552
    goto :goto_5

    .line 553
    :pswitch_b
    move/from16 v8, v20

    .line 554
    .line 555
    goto :goto_5

    .line 556
    :pswitch_c
    move v8, v10

    .line 557
    goto :goto_5

    .line 558
    :pswitch_d
    move v8, v14

    .line 559
    goto :goto_5

    .line 560
    :pswitch_e
    move v8, v3

    .line 561
    goto :goto_5

    .line 562
    :pswitch_f
    move/from16 v8, v25

    .line 563
    .line 564
    goto :goto_5

    .line 565
    :pswitch_10
    move/from16 v8, v22

    .line 566
    .line 567
    goto :goto_5

    .line 568
    :pswitch_11
    move/from16 v8, v17

    .line 569
    .line 570
    goto :goto_5

    .line 571
    :pswitch_12
    move/from16 v8, v18

    .line 572
    .line 573
    goto :goto_5

    .line 574
    :pswitch_13
    move v8, v5

    .line 575
    :goto_5
    :pswitch_14
    if-eq v8, v6, :cond_23

    .line 576
    .line 577
    :try_start_1
    invoke-virtual {v1, v0, v8}, Lo8/m;->a(Ljava/util/ArrayList;I)V

    .line 578
    .line 579
    .line 580
    goto :goto_6

    .line 581
    :catchall_0
    move-exception v0

    .line 582
    goto :goto_8

    .line 583
    :cond_23
    :goto_6
    invoke-static/range {p1 .. p1}, Lkp/n9;->b(Landroid/net/Uri;)I

    .line 584
    .line 585
    .line 586
    move-result v4

    .line 587
    if-eq v4, v6, :cond_24

    .line 588
    .line 589
    if-eq v4, v8, :cond_24

    .line 590
    .line 591
    invoke-virtual {v1, v0, v4}, Lo8/m;->a(Ljava/util/ArrayList;I)V

    .line 592
    .line 593
    .line 594
    :cond_24
    move v6, v5

    .line 595
    :goto_7
    if-ge v6, v3, :cond_26

    .line 596
    .line 597
    aget v7, v2, v6

    .line 598
    .line 599
    if-eq v7, v8, :cond_25

    .line 600
    .line 601
    if-eq v7, v4, :cond_25

    .line 602
    .line 603
    invoke-virtual {v1, v0, v7}, Lo8/m;->a(Ljava/util/ArrayList;I)V

    .line 604
    .line 605
    .line 606
    :cond_25
    add-int/lit8 v6, v6, 0x1

    .line 607
    .line 608
    goto :goto_7

    .line 609
    :cond_26
    new-array v2, v5, [Lo8/o;

    .line 610
    .line 611
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v0

    .line 615
    check-cast v0, [Lo8/o;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 616
    .line 617
    monitor-exit p0

    .line 618
    return-object v0

    .line 619
    :goto_8
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 620
    throw v0

    .line 621
    :sswitch_data_0
    .sparse-switch
        -0x7e929daa -> :sswitch_1f
        -0x6315f78b -> :sswitch_1e
        -0x6315f787 -> :sswitch_1d
        -0x63118f53 -> :sswitch_1c
        -0x5fc6f775 -> :sswitch_1b
        -0x58abd7ba -> :sswitch_1a
        -0x58a8e8f5 -> :sswitch_19
        -0x58a8e8f2 -> :sswitch_18
        -0x58a7d764 -> :sswitch_17
        -0x58a21830 -> :sswitch_16
        -0x4a681e4e -> :sswitch_15
        -0x405dba54 -> :sswitch_14
        -0x3be2f26c -> :sswitch_13
        -0x3468a12f -> :sswitch_12
        -0x34686c8b -> :sswitch_11
        -0x17118226 -> :sswitch_10
        -0x2974308 -> :sswitch_f
        0xd45707 -> :sswitch_e
        0xb269698 -> :sswitch_d
        0xb269699 -> :sswitch_c
        0xb26980d -> :sswitch_b
        0xb26c538 -> :sswitch_a
        0xb26cbd6 -> :sswitch_9
        0xb26e933 -> :sswitch_8
        0x4f62635d -> :sswitch_7
        0x59976a2d -> :sswitch_6
        0x59ae0c65 -> :sswitch_5
        0x59aeaa01 -> :sswitch_4
        0x59b1cdba -> :sswitch_3
        0x59b1e81e -> :sswitch_2
        0x59b64a32 -> :sswitch_1
        0x79909c15 -> :sswitch_0
    .end sparse-switch

    .line 622
    .line 623
    .line 624
    .line 625
    .line 626
    .line 627
    .line 628
    .line 629
    .line 630
    .line 631
    .line 632
    .line 633
    .line 634
    .line 635
    .line 636
    .line 637
    .line 638
    .line 639
    .line 640
    .line 641
    .line 642
    .line 643
    .line 644
    .line 645
    .line 646
    .line 647
    .line 648
    .line 649
    .line 650
    .line 651
    .line 652
    .line 653
    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    .line 663
    .line 664
    .line 665
    .line 666
    .line 667
    .line 668
    .line 669
    .line 670
    .line 671
    .line 672
    .line 673
    .line 674
    .line 675
    .line 676
    .line 677
    .line 678
    .line 679
    .line 680
    .line 681
    .line 682
    .line 683
    .line 684
    .line 685
    .line 686
    .line 687
    .line 688
    .line 689
    .line 690
    .line 691
    .line 692
    .line 693
    .line 694
    .line 695
    .line 696
    .line 697
    .line 698
    .line 699
    .line 700
    .line 701
    .line 702
    .line 703
    .line 704
    .line 705
    .line 706
    .line 707
    .line 708
    .line 709
    .line 710
    .line 711
    .line 712
    .line 713
    .line 714
    .line 715
    .line 716
    .line 717
    .line 718
    .line 719
    .line 720
    .line 721
    .line 722
    .line 723
    .line 724
    .line 725
    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    .line 731
    .line 732
    .line 733
    .line 734
    .line 735
    .line 736
    .line 737
    .line 738
    .line 739
    .line 740
    .line 741
    .line 742
    .line 743
    .line 744
    .line 745
    .line 746
    .line 747
    .line 748
    .line 749
    .line 750
    .line 751
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_14
        :pswitch_14
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_10
        :pswitch_10
        :pswitch_6
        :pswitch_13
        :pswitch_5
        :pswitch_f
        :pswitch_b
        :pswitch_4
        :pswitch_3
        :pswitch_b
        :pswitch_f
        :pswitch_13
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_10
        :pswitch_10
    .end packed-switch
.end method

.method public final declared-synchronized g()[Lo8/o;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    sget-object v0, Landroid/net/Uri;->EMPTY:Landroid/net/Uri;

    .line 3
    .line 4
    new-instance v1, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Lo8/m;->c(Landroid/net/Uri;Ljava/util/Map;)[Lo8/o;

    .line 10
    .line 11
    .line 12
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    monitor-exit p0

    .line 14
    return-object v0

    .line 15
    :catchall_0
    move-exception v0

    .line 16
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 17
    throw v0
.end method
