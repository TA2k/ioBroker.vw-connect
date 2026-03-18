.class public abstract Lck/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ltd/p;


# direct methods
.method static constructor <clinit>()V
    .locals 26

    .line 1
    new-instance v0, Ltd/f;

    .line 2
    .line 3
    const-string v1, "February"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltd/f;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v9, Ltd/d;->f:Ltd/d;

    .line 9
    .line 10
    new-instance v2, Ltd/e;

    .line 11
    .line 12
    const/4 v8, 0x0

    .line 13
    const/4 v10, 0x1

    .line 14
    const-string v3, "Thu 01.02. 10:51h"

    .line 15
    .line 16
    const-string v4, "123"

    .line 17
    .line 18
    const-string v5, "Hardenbergstra\u00dfe 22, 10623 Berlin"

    .line 19
    .line 20
    const-string v6, "_,__ \u20ac"

    .line 21
    .line 22
    const-string v7, "~ 86,80 kWh"

    .line 23
    .line 24
    invoke-direct/range {v2 .. v10}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 25
    .line 26
    .line 27
    sget-object v10, Ltd/d;->e:Ltd/d;

    .line 28
    .line 29
    new-instance v3, Ltd/e;

    .line 30
    .line 31
    const/4 v9, 0x0

    .line 32
    const/4 v11, 0x1

    .line 33
    const-string v4, "Sat 27.01. 13:51h"

    .line 34
    .line 35
    const-string v5, "123"

    .line 36
    .line 37
    const-string v6, "My Wallbox Home"

    .line 38
    .line 39
    const-string v7, "128 kWh"

    .line 40
    .line 41
    const-string v8, "8h 30min"

    .line 42
    .line 43
    invoke-direct/range {v3 .. v11}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 44
    .line 45
    .line 46
    move-object v1, v3

    .line 47
    new-instance v3, Ltd/e;

    .line 48
    .line 49
    const-string v4, "Sat 27.01. 13:51h"

    .line 50
    .line 51
    const-string v5, "123"

    .line 52
    .line 53
    const-string v6, "My Wallbox Home"

    .line 54
    .line 55
    const-string v7, "128 kWh"

    .line 56
    .line 57
    const-string v8, "8h 30min"

    .line 58
    .line 59
    invoke-direct/range {v3 .. v11}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 60
    .line 61
    .line 62
    move-object v12, v3

    .line 63
    new-instance v3, Ltd/e;

    .line 64
    .line 65
    const/4 v9, 0x1

    .line 66
    const-string v4, "Sat 27.01. 13:51h"

    .line 67
    .line 68
    const-string v5, "123"

    .line 69
    .line 70
    const-string v6, "My Wallbox Home"

    .line 71
    .line 72
    const-string v7, "128 kWh"

    .line 73
    .line 74
    const-string v8, "8h 30min"

    .line 75
    .line 76
    invoke-direct/range {v3 .. v11}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 77
    .line 78
    .line 79
    move-object v13, v3

    .line 80
    new-instance v14, Ltd/f;

    .line 81
    .line 82
    const-string v3, "January"

    .line 83
    .line 84
    invoke-direct {v14, v3}, Ltd/f;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    sget-object v22, Ltd/d;->d:Ltd/d;

    .line 88
    .line 89
    new-instance v15, Ltd/e;

    .line 90
    .line 91
    const/16 v21, 0x0

    .line 92
    .line 93
    const/16 v23, 0x1

    .line 94
    .line 95
    const-string v16, "Thu 31.01. 10:28h"

    .line 96
    .line 97
    const-string v17, "123"

    .line 98
    .line 99
    const-string v18, "Ludwigkirchstra\u00dfe 6, 10719 Berlin"

    .line 100
    .line 101
    const-string v19, "134,60 \u20ac"

    .line 102
    .line 103
    const-string v20, "120 kWh"

    .line 104
    .line 105
    invoke-direct/range {v15 .. v23}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 106
    .line 107
    .line 108
    move-object/from16 v24, v15

    .line 109
    .line 110
    new-instance v15, Ltd/e;

    .line 111
    .line 112
    const-string v16, "Wed 30.01. 19:02h"

    .line 113
    .line 114
    const-string v17, "123"

    .line 115
    .line 116
    const-string v18, "Georg-Eckert-Stra\u00dfe 11, 38125 Berlin"

    .line 117
    .line 118
    const-string v19, "58,90 \u20ac"

    .line 119
    .line 120
    const-string v20, "54 kWh"

    .line 121
    .line 122
    invoke-direct/range {v15 .. v23}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 123
    .line 124
    .line 125
    move-object/from16 v25, v15

    .line 126
    .line 127
    new-instance v15, Ltd/e;

    .line 128
    .line 129
    const-string v16, "Mon 29.01. 13:51h"

    .line 130
    .line 131
    const-string v17, "123"

    .line 132
    .line 133
    const-string v18, "Ludwigkirchstra\u00dfe 6, 10719 Berlin"

    .line 134
    .line 135
    const-string v19, "53,20 \u20ac"

    .line 136
    .line 137
    const-string v20, "54 kWh"

    .line 138
    .line 139
    invoke-direct/range {v15 .. v23}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 140
    .line 141
    .line 142
    new-instance v3, Ltd/e;

    .line 143
    .line 144
    const-string v4, "Sun 28.01. 13:51h"

    .line 145
    .line 146
    const-string v5, "123"

    .line 147
    .line 148
    const-string v6, "Dad\'s Wallbox"

    .line 149
    .line 150
    const-string v7, "88 kWh"

    .line 151
    .line 152
    const-string v8, "6h 15min"

    .line 153
    .line 154
    invoke-direct/range {v3 .. v11}, Ltd/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLtd/d;Z)V

    .line 155
    .line 156
    .line 157
    const/16 v4, 0xa

    .line 158
    .line 159
    new-array v4, v4, [Ltd/g;

    .line 160
    .line 161
    const/4 v5, 0x0

    .line 162
    aput-object v0, v4, v5

    .line 163
    .line 164
    const/4 v0, 0x1

    .line 165
    aput-object v2, v4, v0

    .line 166
    .line 167
    const/4 v2, 0x2

    .line 168
    aput-object v1, v4, v2

    .line 169
    .line 170
    const/4 v1, 0x3

    .line 171
    aput-object v12, v4, v1

    .line 172
    .line 173
    const/4 v1, 0x4

    .line 174
    aput-object v13, v4, v1

    .line 175
    .line 176
    const/4 v1, 0x5

    .line 177
    aput-object v14, v4, v1

    .line 178
    .line 179
    const/4 v1, 0x6

    .line 180
    aput-object v24, v4, v1

    .line 181
    .line 182
    const/4 v1, 0x7

    .line 183
    aput-object v25, v4, v1

    .line 184
    .line 185
    const/16 v1, 0x8

    .line 186
    .line 187
    aput-object v15, v4, v1

    .line 188
    .line 189
    const/16 v1, 0x9

    .line 190
    .line 191
    aput-object v3, v4, v1

    .line 192
    .line 193
    invoke-static {v4}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 194
    .line 195
    .line 196
    move-result-object v9

    .line 197
    new-instance v1, Ltd/a;

    .line 198
    .line 199
    new-instance v2, Ltd/b;

    .line 200
    .line 201
    const-string v3, "1"

    .line 202
    .line 203
    const-string v4, ""

    .line 204
    .line 205
    invoke-direct {v2, v3, v4}, Ltd/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    const-string v3, "    "

    .line 209
    .line 210
    invoke-direct {v1, v2, v3, v0}, Ltd/a;-><init>(Ltd/b;Ljava/lang/String;Z)V

    .line 211
    .line 212
    .line 213
    new-instance v0, Ltd/a;

    .line 214
    .line 215
    new-instance v2, Ltd/b;

    .line 216
    .line 217
    const-string v3, "2"

    .line 218
    .line 219
    invoke-direct {v2, v3, v4}, Ltd/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    const-string v3, "   "

    .line 223
    .line 224
    invoke-direct {v0, v2, v3, v5}, Ltd/a;-><init>(Ltd/b;Ljava/lang/String;Z)V

    .line 225
    .line 226
    .line 227
    new-instance v2, Ltd/a;

    .line 228
    .line 229
    new-instance v3, Ltd/b;

    .line 230
    .line 231
    const-string v6, "3"

    .line 232
    .line 233
    invoke-direct {v3, v6, v4}, Ltd/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    const-string v4, "      "

    .line 237
    .line 238
    invoke-direct {v2, v3, v4, v5}, Ltd/a;-><init>(Ltd/b;Ljava/lang/String;Z)V

    .line 239
    .line 240
    .line 241
    filled-new-array {v1, v0, v2}, [Ltd/a;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 246
    .line 247
    .line 248
    move-result-object v12

    .line 249
    new-instance v6, Ltd/p;

    .line 250
    .line 251
    const-string v11, "January 01 - February 09"

    .line 252
    .line 253
    const/16 v13, 0x40

    .line 254
    .line 255
    const-string v7, "*It can take up to 24 hours to collect all data"

    .line 256
    .line 257
    const/4 v8, 0x0

    .line 258
    const/4 v10, 0x0

    .line 259
    invoke-direct/range {v6 .. v13}, Ltd/p;-><init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;I)V

    .line 260
    .line 261
    .line 262
    sput-object v6, Lck/i;->a:Ltd/p;

    .line 263
    .line 264
    return-void
.end method

.method public static final a(Ltd/p;Lay0/k;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v9, p2

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const p2, 0x3cd990aa

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x6

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-nez p2, :cond_2

    .line 14
    .line 15
    and-int/lit8 p2, p3, 0x8

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    :goto_0
    if-eqz p2, :cond_1

    .line 29
    .line 30
    move p2, v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 p2, 0x2

    .line 33
    :goto_1
    or-int/2addr p2, p3

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move p2, p3

    .line 36
    :goto_2
    and-int/lit8 v1, p3, 0x30

    .line 37
    .line 38
    const/16 v2, 0x20

    .line 39
    .line 40
    if-nez v1, :cond_4

    .line 41
    .line 42
    invoke-virtual {v9, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    move v1, v2

    .line 49
    goto :goto_3

    .line 50
    :cond_3
    const/16 v1, 0x10

    .line 51
    .line 52
    :goto_3
    or-int/2addr p2, v1

    .line 53
    :cond_4
    and-int/lit8 v1, p2, 0x13

    .line 54
    .line 55
    const/16 v3, 0x12

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    const/4 v5, 0x1

    .line 59
    if-eq v1, v3, :cond_5

    .line 60
    .line 61
    move v1, v5

    .line 62
    goto :goto_4

    .line 63
    :cond_5
    move v1, v4

    .line 64
    :goto_4
    and-int/lit8 v3, p2, 0x1

    .line 65
    .line 66
    invoke-virtual {v9, v3, v1}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_b

    .line 71
    .line 72
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 73
    .line 74
    const/high16 v3, 0x3f800000    # 1.0f

    .line 75
    .line 76
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    and-int/lit8 v3, p2, 0xe

    .line 81
    .line 82
    if-eq v3, v0, :cond_7

    .line 83
    .line 84
    and-int/lit8 v0, p2, 0x8

    .line 85
    .line 86
    if-eqz v0, :cond_6

    .line 87
    .line 88
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_6

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_6
    move v0, v4

    .line 96
    goto :goto_6

    .line 97
    :cond_7
    :goto_5
    move v0, v5

    .line 98
    :goto_6
    and-int/lit8 p2, p2, 0x70

    .line 99
    .line 100
    if-ne p2, v2, :cond_8

    .line 101
    .line 102
    move v4, v5

    .line 103
    :cond_8
    or-int p2, v0, v4

    .line 104
    .line 105
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-nez p2, :cond_9

    .line 110
    .line 111
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 112
    .line 113
    if-ne v0, p2, :cond_a

    .line 114
    .line 115
    :cond_9
    new-instance v0, Lck/f;

    .line 116
    .line 117
    const/4 p2, 0x0

    .line 118
    invoke-direct {v0, p0, p1, p2}, Lck/f;-><init>(Ltd/p;Lay0/k;I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_a
    move-object v8, v0

    .line 125
    check-cast v8, Lay0/k;

    .line 126
    .line 127
    const/4 v10, 0x6

    .line 128
    const/16 v11, 0x1fe

    .line 129
    .line 130
    move-object v0, v1

    .line 131
    const/4 v1, 0x0

    .line 132
    const/4 v2, 0x0

    .line 133
    const/4 v3, 0x0

    .line 134
    const/4 v4, 0x0

    .line 135
    const/4 v5, 0x0

    .line 136
    const/4 v6, 0x0

    .line 137
    const/4 v7, 0x0

    .line 138
    invoke-static/range {v0 .. v11}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 139
    .line 140
    .line 141
    goto :goto_7

    .line 142
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 143
    .line 144
    .line 145
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    if-eqz p2, :cond_c

    .line 150
    .line 151
    new-instance v0, Lck/e;

    .line 152
    .line 153
    const/4 v1, 0x2

    .line 154
    invoke-direct {v0, p0, p1, p3, v1}, Lck/e;-><init>(Ltd/p;Lay0/k;II)V

    .line 155
    .line 156
    .line 157
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 158
    .line 159
    :cond_c
    return-void
.end method

.method public static final b(Ltd/p;Lay0/k;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x6180023e

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_2

    .line 12
    .line 13
    and-int/lit8 v0, p3, 0x8

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    :goto_0
    if-eqz v0, :cond_1

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 v0, 0x2

    .line 31
    :goto_1
    or-int/2addr v0, p3

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move v0, p3

    .line 34
    :goto_2
    and-int/lit8 v1, p3, 0x30

    .line 35
    .line 36
    if-nez v1, :cond_4

    .line 37
    .line 38
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    const/16 v1, 0x20

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_3
    const/16 v1, 0x10

    .line 48
    .line 49
    :goto_3
    or-int/2addr v0, v1

    .line 50
    :cond_4
    and-int/lit8 v1, v0, 0x13

    .line 51
    .line 52
    const/16 v2, 0x12

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    if-eq v1, v2, :cond_5

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    goto :goto_4

    .line 59
    :cond_5
    move v1, v3

    .line 60
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 61
    .line 62
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_7

    .line 67
    .line 68
    iget-boolean v1, p0, Ltd/p;->d:Z

    .line 69
    .line 70
    if-eqz v1, :cond_6

    .line 71
    .line 72
    const v1, 0x2f873afc

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    shr-int/lit8 v0, v0, 0x3

    .line 79
    .line 80
    and-int/lit8 v0, v0, 0xe

    .line 81
    .line 82
    invoke-static {p1, p2, v0}, Lck/i;->c(Lay0/k;Ll2/o;I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 86
    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_6
    const v1, 0x2f87ed99

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 93
    .line 94
    .line 95
    and-int/lit8 v1, v0, 0xe

    .line 96
    .line 97
    const/16 v2, 0x8

    .line 98
    .line 99
    or-int/2addr v1, v2

    .line 100
    and-int/lit8 v0, v0, 0x70

    .line 101
    .line 102
    or-int/2addr v0, v1

    .line 103
    invoke-static {p0, p1, p2, v0}, Lck/i;->g(Ltd/p;Lay0/k;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_7
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 111
    .line 112
    .line 113
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    if-eqz p2, :cond_8

    .line 118
    .line 119
    new-instance v0, Lck/e;

    .line 120
    .line 121
    const/4 v1, 0x0

    .line 122
    invoke-direct {v0, p0, p1, p3, v1}, Lck/e;-><init>(Ltd/p;Lay0/k;II)V

    .line 123
    .line 124
    .line 125
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 126
    .line 127
    :cond_8
    return-void
.end method

.method public static final c(Lay0/k;Ll2/o;I)V
    .locals 7

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p1, -0x713eecc2

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    const/4 v1, 0x4

    .line 14
    if-nez p1, :cond_1

    .line 15
    .line 16
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    move p1, v1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p1, v0

    .line 25
    :goto_0
    or-int/2addr p1, p2

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move p1, p2

    .line 28
    :goto_1
    and-int/lit8 v2, p1, 0x3

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v5, 0x1

    .line 32
    if-eq v2, v0, :cond_2

    .line 33
    .line 34
    move v0, v5

    .line 35
    goto :goto_2

    .line 36
    :cond_2
    move v0, v3

    .line 37
    :goto_2
    and-int/lit8 v2, p1, 0x1

    .line 38
    .line 39
    invoke-virtual {v4, v2, v0}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_9

    .line 44
    .line 45
    and-int/lit8 p1, p1, 0xe

    .line 46
    .line 47
    if-ne p1, v1, :cond_3

    .line 48
    .line 49
    move v0, v5

    .line 50
    goto :goto_3

    .line 51
    :cond_3
    move v0, v3

    .line 52
    :goto_3
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 57
    .line 58
    if-nez v0, :cond_4

    .line 59
    .line 60
    if-ne v2, v6, :cond_5

    .line 61
    .line 62
    :cond_4
    new-instance v2, Lak/n;

    .line 63
    .line 64
    const/16 v0, 0x11

    .line 65
    .line 66
    invoke-direct {v2, v0, p0}, Lak/n;-><init>(ILay0/k;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v4, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_5
    move-object v0, v2

    .line 73
    check-cast v0, Lay0/a;

    .line 74
    .line 75
    if-ne p1, v1, :cond_6

    .line 76
    .line 77
    move v3, v5

    .line 78
    :cond_6
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-nez v3, :cond_7

    .line 83
    .line 84
    if-ne p1, v6, :cond_8

    .line 85
    .line 86
    :cond_7
    new-instance p1, Lal/c;

    .line 87
    .line 88
    const/4 v1, 0x3

    .line 89
    invoke-direct {p1, v1, p0}, Lal/c;-><init>(ILay0/k;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v4, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_8
    move-object v1, p1

    .line 96
    check-cast v1, Lay0/n;

    .line 97
    .line 98
    const/4 v5, 0x0

    .line 99
    const/16 v6, 0xc

    .line 100
    .line 101
    const/4 v2, 0x0

    .line 102
    const/4 v3, 0x0

    .line 103
    invoke-static/range {v0 .. v6}, Lkp/z8;->b(Lay0/a;Lay0/n;Ljd/k;Lh2/e8;Ll2/o;II)V

    .line 104
    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_9
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    :goto_4
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-eqz p1, :cond_a

    .line 115
    .line 116
    new-instance v0, Lck/g;

    .line 117
    .line 118
    const/4 v1, 0x0

    .line 119
    invoke-direct {v0, p2, v1, p0}, Lck/g;-><init>(IILay0/k;)V

    .line 120
    .line 121
    .line 122
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 123
    .line 124
    :cond_a
    return-void
.end method

.method public static final d(Ltd/e;ILay0/k;Ll2/o;I)V
    .locals 35

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
    move/from16 v4, p4

    .line 8
    .line 9
    move-object/from16 v10, p3

    .line 10
    .line 11
    check-cast v10, Ll2/t;

    .line 12
    .line 13
    const v0, 0x74afe704

    .line 14
    .line 15
    .line 16
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, v4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    and-int/lit8 v0, v4, 0x8

    .line 24
    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    :goto_0
    if-eqz v0, :cond_1

    .line 37
    .line 38
    const/4 v0, 0x4

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/4 v0, 0x2

    .line 41
    :goto_1
    or-int/2addr v0, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v0, v4

    .line 44
    :goto_2
    and-int/lit8 v6, v4, 0x30

    .line 45
    .line 46
    if-nez v6, :cond_4

    .line 47
    .line 48
    invoke-virtual {v10, v2}, Ll2/t;->e(I)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_3

    .line 53
    .line 54
    const/16 v6, 0x20

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    const/16 v6, 0x10

    .line 58
    .line 59
    :goto_3
    or-int/2addr v0, v6

    .line 60
    :cond_4
    and-int/lit16 v6, v4, 0x180

    .line 61
    .line 62
    if-nez v6, :cond_6

    .line 63
    .line 64
    invoke-virtual {v10, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-eqz v6, :cond_5

    .line 69
    .line 70
    const/16 v6, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v6, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v6

    .line 76
    :cond_6
    and-int/lit16 v6, v0, 0x93

    .line 77
    .line 78
    const/16 v8, 0x92

    .line 79
    .line 80
    const/4 v15, 0x0

    .line 81
    if-eq v6, v8, :cond_7

    .line 82
    .line 83
    const/4 v6, 0x1

    .line 84
    goto :goto_5

    .line 85
    :cond_7
    move v6, v15

    .line 86
    :goto_5
    and-int/lit8 v8, v0, 0x1

    .line 87
    .line 88
    invoke-virtual {v10, v8, v6}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v6

    .line 92
    if-eqz v6, :cond_1f

    .line 93
    .line 94
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 95
    .line 96
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 97
    .line 98
    invoke-static {v6, v8, v10, v15}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 99
    .line 100
    .line 101
    move-result-object v9

    .line 102
    iget-wide v11, v10, Ll2/t;->T:J

    .line 103
    .line 104
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 105
    .line 106
    .line 107
    move-result v11

    .line 108
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 109
    .line 110
    .line 111
    move-result-object v12

    .line 112
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 113
    .line 114
    invoke-static {v10, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v15

    .line 118
    sget-object v17, Lv3/k;->m1:Lv3/j;

    .line 119
    .line 120
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    move-object/from16 v17, v6

    .line 124
    .line 125
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 126
    .line 127
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 128
    .line 129
    .line 130
    iget-boolean v14, v10, Ll2/t;->S:Z

    .line 131
    .line 132
    if-eqz v14, :cond_8

    .line 133
    .line 134
    invoke-virtual {v10, v6}, Ll2/t;->l(Lay0/a;)V

    .line 135
    .line 136
    .line 137
    goto :goto_6

    .line 138
    :cond_8
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 139
    .line 140
    .line 141
    :goto_6
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 142
    .line 143
    invoke-static {v14, v9, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v9, Lv3/j;->f:Lv3/h;

    .line 147
    .line 148
    invoke-static {v9, v12, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 152
    .line 153
    iget-boolean v5, v10, Ll2/t;->S:Z

    .line 154
    .line 155
    if-nez v5, :cond_9

    .line 156
    .line 157
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v5

    .line 169
    if-nez v5, :cond_a

    .line 170
    .line 171
    :cond_9
    invoke-static {v11, v10, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 172
    .line 173
    .line 174
    :cond_a
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 175
    .line 176
    invoke-static {v5, v15, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 177
    .line 178
    .line 179
    const/high16 v15, 0x3f800000    # 1.0f

    .line 180
    .line 181
    invoke-static {v13, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 182
    .line 183
    .line 184
    move-result-object v21

    .line 185
    iget-boolean v7, v1, Ltd/e;->h:Z

    .line 186
    .line 187
    iget-object v11, v1, Ltd/e;->e:Ljava/lang/String;

    .line 188
    .line 189
    iget-object v15, v1, Ltd/e;->d:Ljava/lang/String;

    .line 190
    .line 191
    and-int/lit16 v4, v0, 0x380

    .line 192
    .line 193
    move/from16 v22, v0

    .line 194
    .line 195
    const/16 v0, 0x100

    .line 196
    .line 197
    if-ne v4, v0, :cond_b

    .line 198
    .line 199
    const/4 v0, 0x1

    .line 200
    goto :goto_7

    .line 201
    :cond_b
    const/4 v0, 0x0

    .line 202
    :goto_7
    and-int/lit8 v4, v22, 0xe

    .line 203
    .line 204
    move/from16 v20, v0

    .line 205
    .line 206
    const/4 v0, 0x4

    .line 207
    const/16 v28, 0x8

    .line 208
    .line 209
    if-eq v4, v0, :cond_d

    .line 210
    .line 211
    and-int/lit8 v0, v22, 0x8

    .line 212
    .line 213
    if-eqz v0, :cond_c

    .line 214
    .line 215
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v0

    .line 219
    if-eqz v0, :cond_c

    .line 220
    .line 221
    goto :goto_8

    .line 222
    :cond_c
    const/4 v0, 0x0

    .line 223
    goto :goto_9

    .line 224
    :cond_d
    :goto_8
    const/4 v0, 0x1

    .line 225
    :goto_9
    or-int v0, v20, v0

    .line 226
    .line 227
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v4

    .line 231
    if-nez v0, :cond_e

    .line 232
    .line 233
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 234
    .line 235
    if-ne v4, v0, :cond_f

    .line 236
    .line 237
    :cond_e
    new-instance v4, Laa/k;

    .line 238
    .line 239
    const/16 v0, 0x12

    .line 240
    .line 241
    invoke-direct {v4, v0, v3, v1}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    :cond_f
    move-object/from16 v25, v4

    .line 248
    .line 249
    check-cast v25, Lay0/a;

    .line 250
    .line 251
    const/16 v26, 0xe

    .line 252
    .line 253
    const/16 v23, 0x0

    .line 254
    .line 255
    const/16 v24, 0x0

    .line 256
    .line 257
    move/from16 v22, v7

    .line 258
    .line 259
    invoke-static/range {v21 .. v26}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    move/from16 v4, v28

    .line 264
    .line 265
    int-to-float v4, v4

    .line 266
    const/4 v7, 0x0

    .line 267
    const/4 v3, 0x1

    .line 268
    invoke-static {v0, v7, v4, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    invoke-static {v0}, Lzb/o0;->b(Lx2/s;)Lx2/s;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    sget-object v3, Lx2/c;->m:Lx2/i;

    .line 277
    .line 278
    sget-object v7, Lk1/j;->a:Lk1/c;

    .line 279
    .line 280
    move-object/from16 v19, v15

    .line 281
    .line 282
    const/16 v15, 0x30

    .line 283
    .line 284
    invoke-static {v7, v3, v10, v15}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 285
    .line 286
    .line 287
    move-result-object v3

    .line 288
    move-object/from16 v20, v8

    .line 289
    .line 290
    iget-wide v7, v10, Ll2/t;->T:J

    .line 291
    .line 292
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 293
    .line 294
    .line 295
    move-result v7

    .line 296
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 297
    .line 298
    .line 299
    move-result-object v8

    .line 300
    invoke-static {v10, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 305
    .line 306
    .line 307
    iget-boolean v15, v10, Ll2/t;->S:Z

    .line 308
    .line 309
    if-eqz v15, :cond_10

    .line 310
    .line 311
    invoke-virtual {v10, v6}, Ll2/t;->l(Lay0/a;)V

    .line 312
    .line 313
    .line 314
    goto :goto_a

    .line 315
    :cond_10
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 316
    .line 317
    .line 318
    :goto_a
    invoke-static {v14, v3, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 319
    .line 320
    .line 321
    invoke-static {v9, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 322
    .line 323
    .line 324
    iget-boolean v3, v10, Ll2/t;->S:Z

    .line 325
    .line 326
    if-nez v3, :cond_11

    .line 327
    .line 328
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 333
    .line 334
    .line 335
    move-result-object v8

    .line 336
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 337
    .line 338
    .line 339
    move-result v3

    .line 340
    if-nez v3, :cond_12

    .line 341
    .line 342
    :cond_11
    invoke-static {v7, v10, v7, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 343
    .line 344
    .line 345
    :cond_12
    invoke-static {v5, v0, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 346
    .line 347
    .line 348
    iget-object v0, v1, Ltd/e;->g:Ltd/d;

    .line 349
    .line 350
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 351
    .line 352
    .line 353
    move-result v0

    .line 354
    if-eqz v0, :cond_14

    .line 355
    .line 356
    const/4 v3, 0x1

    .line 357
    if-eq v0, v3, :cond_13

    .line 358
    .line 359
    const/4 v0, 0x0

    .line 360
    goto :goto_b

    .line 361
    :cond_13
    const v0, 0x7f08059d

    .line 362
    .line 363
    .line 364
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    goto :goto_b

    .line 369
    :cond_14
    const/4 v3, 0x1

    .line 370
    const v0, 0x7f0802d5

    .line 371
    .line 372
    .line 373
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    :goto_b
    if-nez v0, :cond_15

    .line 378
    .line 379
    const v0, 0x582c06ce

    .line 380
    .line 381
    .line 382
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 383
    .line 384
    .line 385
    const/4 v0, 0x0

    .line 386
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 387
    .line 388
    .line 389
    move-object/from16 v29, v5

    .line 390
    .line 391
    move-object v3, v6

    .line 392
    move-object v2, v9

    .line 393
    move-object/from16 v30, v11

    .line 394
    .line 395
    move-object v1, v12

    .line 396
    move-object/from16 v15, v20

    .line 397
    .line 398
    move v5, v0

    .line 399
    move-object/from16 v0, v17

    .line 400
    .line 401
    :goto_c
    const/16 v4, 0x30

    .line 402
    .line 403
    goto :goto_d

    .line 404
    :cond_15
    const v7, 0x582c06cf

    .line 405
    .line 406
    .line 407
    invoke-virtual {v10, v7}, Ll2/t;->Y(I)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 411
    .line 412
    .line 413
    move-result v0

    .line 414
    const/4 v7, 0x6

    .line 415
    invoke-static {v0, v7, v10}, Ljp/ha;->c(IILl2/o;)Lj3/f;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 420
    .line 421
    invoke-virtual {v10, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v7

    .line 425
    check-cast v7, Lj91/e;

    .line 426
    .line 427
    invoke-virtual {v7}, Lj91/e;->q()J

    .line 428
    .line 429
    .line 430
    move-result-wide v7

    .line 431
    const/16 v15, 0x18

    .line 432
    .line 433
    int-to-float v15, v15

    .line 434
    invoke-static {v13, v15}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 435
    .line 436
    .line 437
    move-result-object v15

    .line 438
    move-object/from16 v18, v11

    .line 439
    .line 440
    const/16 v11, 0x1b0

    .line 441
    .line 442
    move-object/from16 v22, v12

    .line 443
    .line 444
    const/4 v12, 0x0

    .line 445
    move-object/from16 v23, v6

    .line 446
    .line 447
    const/4 v6, 0x0

    .line 448
    move-object/from16 v29, v5

    .line 449
    .line 450
    move-object v2, v9

    .line 451
    move-object/from16 v30, v18

    .line 452
    .line 453
    move-object/from16 v1, v22

    .line 454
    .line 455
    move-object/from16 v3, v23

    .line 456
    .line 457
    move-object v5, v0

    .line 458
    move-wide v8, v7

    .line 459
    move-object v7, v15

    .line 460
    move-object/from16 v0, v17

    .line 461
    .line 462
    move-object/from16 v15, v20

    .line 463
    .line 464
    invoke-static/range {v5 .. v12}, Lh2/f5;->b(Lj3/f;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 465
    .line 466
    .line 467
    const/4 v5, 0x0

    .line 468
    invoke-static {v13, v4, v10, v5}, Lvj/b;->C(Lx2/p;FLl2/t;Z)V

    .line 469
    .line 470
    .line 471
    goto :goto_c

    .line 472
    :goto_d
    invoke-static {v0, v15, v10, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    iget-wide v7, v10, Ll2/t;->T:J

    .line 477
    .line 478
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 479
    .line 480
    .line 481
    move-result v7

    .line 482
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 483
    .line 484
    .line 485
    move-result-object v8

    .line 486
    invoke-static {v10, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 487
    .line 488
    .line 489
    move-result-object v9

    .line 490
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 491
    .line 492
    .line 493
    iget-boolean v11, v10, Ll2/t;->S:Z

    .line 494
    .line 495
    if-eqz v11, :cond_16

    .line 496
    .line 497
    invoke-virtual {v10, v3}, Ll2/t;->l(Lay0/a;)V

    .line 498
    .line 499
    .line 500
    goto :goto_e

    .line 501
    :cond_16
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 502
    .line 503
    .line 504
    :goto_e
    invoke-static {v14, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 505
    .line 506
    .line 507
    invoke-static {v2, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 508
    .line 509
    .line 510
    iget-boolean v6, v10, Ll2/t;->S:Z

    .line 511
    .line 512
    if-nez v6, :cond_18

    .line 513
    .line 514
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    move-result-object v6

    .line 518
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 519
    .line 520
    .line 521
    move-result-object v8

    .line 522
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 523
    .line 524
    .line 525
    move-result v6

    .line 526
    if-nez v6, :cond_17

    .line 527
    .line 528
    goto :goto_10

    .line 529
    :cond_17
    :goto_f
    move-object/from16 v6, v29

    .line 530
    .line 531
    goto :goto_11

    .line 532
    :cond_18
    :goto_10
    invoke-static {v7, v10, v7, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 533
    .line 534
    .line 535
    goto :goto_f

    .line 536
    :goto_11
    invoke-static {v6, v9, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 537
    .line 538
    .line 539
    move/from16 v16, v5

    .line 540
    .line 541
    new-instance v5, Lg4/g;

    .line 542
    .line 543
    move-object/from16 v7, p0

    .line 544
    .line 545
    iget-object v8, v7, Ltd/e;->a:Ljava/lang/String;

    .line 546
    .line 547
    invoke-direct {v5, v8}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 548
    .line 549
    .line 550
    const-string v8, "charging_statistics_item_title_"

    .line 551
    .line 552
    move/from16 v9, p1

    .line 553
    .line 554
    invoke-static {v8, v9, v13}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 555
    .line 556
    .line 557
    move-result-object v8

    .line 558
    invoke-static {v10}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 559
    .line 560
    .line 561
    move-result-object v11

    .line 562
    invoke-virtual {v11}, Lj91/f;->b()Lg4/p0;

    .line 563
    .line 564
    .line 565
    move-result-object v11

    .line 566
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 567
    .line 568
    .line 569
    move-result-object v12

    .line 570
    invoke-virtual {v12}, Lj91/e;->q()J

    .line 571
    .line 572
    .line 573
    move-result-wide v20

    .line 574
    const/16 v23, 0x0

    .line 575
    .line 576
    const v24, 0xfff0

    .line 577
    .line 578
    .line 579
    move-object/from16 v29, v6

    .line 580
    .line 581
    move-object v6, v8

    .line 582
    move-object v7, v11

    .line 583
    move-wide/from16 v8, v20

    .line 584
    .line 585
    move-object/from16 v21, v10

    .line 586
    .line 587
    const-wide/16 v10, 0x0

    .line 588
    .line 589
    move-object v15, v13

    .line 590
    const-wide/16 v12, 0x0

    .line 591
    .line 592
    move-object/from16 v17, v14

    .line 593
    .line 594
    const/4 v14, 0x0

    .line 595
    move-object/from16 v22, v15

    .line 596
    .line 597
    move/from16 v20, v16

    .line 598
    .line 599
    const-wide/16 v15, 0x0

    .line 600
    .line 601
    move-object/from16 v25, v17

    .line 602
    .line 603
    const/16 v17, 0x0

    .line 604
    .line 605
    const/16 v26, 0x1

    .line 606
    .line 607
    const/16 v18, 0x0

    .line 608
    .line 609
    move-object/from16 v28, v19

    .line 610
    .line 611
    const/16 v19, 0x0

    .line 612
    .line 613
    move/from16 v31, v20

    .line 614
    .line 615
    const/16 v20, 0x0

    .line 616
    .line 617
    move-object/from16 v32, v22

    .line 618
    .line 619
    const/16 v22, 0x0

    .line 620
    .line 621
    move-object/from16 v4, p0

    .line 622
    .line 623
    move-object/from16 v26, v2

    .line 624
    .line 625
    move-object/from16 v27, v25

    .line 626
    .line 627
    move-object/from16 v34, v28

    .line 628
    .line 629
    move-object/from16 v33, v29

    .line 630
    .line 631
    move-object/from16 v2, v32

    .line 632
    .line 633
    move-object/from16 v25, v1

    .line 634
    .line 635
    move/from16 v1, p1

    .line 636
    .line 637
    invoke-static/range {v5 .. v24}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 638
    .line 639
    .line 640
    new-instance v5, Lg4/g;

    .line 641
    .line 642
    iget-object v6, v4, Ltd/e;->c:Ljava/lang/String;

    .line 643
    .line 644
    invoke-direct {v5, v6}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 645
    .line 646
    .line 647
    const-string v6, "charging_statistics_subtitle_"

    .line 648
    .line 649
    invoke-static {v6, v1, v2}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 650
    .line 651
    .line 652
    move-result-object v6

    .line 653
    invoke-static/range {v21 .. v21}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 654
    .line 655
    .line 656
    move-result-object v7

    .line 657
    invoke-virtual {v7}, Lj91/f;->e()Lg4/p0;

    .line 658
    .line 659
    .line 660
    move-result-object v7

    .line 661
    invoke-static/range {v21 .. v21}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 662
    .line 663
    .line 664
    move-result-object v8

    .line 665
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 666
    .line 667
    .line 668
    move-result-wide v8

    .line 669
    invoke-static/range {v5 .. v24}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 670
    .line 671
    .line 672
    move-object/from16 v10, v21

    .line 673
    .line 674
    const/4 v5, 0x1

    .line 675
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 676
    .line 677
    .line 678
    const/high16 v5, 0x3f800000    # 1.0f

    .line 679
    .line 680
    invoke-static {v2, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 681
    .line 682
    .line 683
    move-result-object v5

    .line 684
    sget-object v6, Lx2/c;->r:Lx2/h;

    .line 685
    .line 686
    const/16 v7, 0x30

    .line 687
    .line 688
    invoke-static {v0, v6, v10, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 689
    .line 690
    .line 691
    move-result-object v0

    .line 692
    iget-wide v6, v10, Ll2/t;->T:J

    .line 693
    .line 694
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 695
    .line 696
    .line 697
    move-result v6

    .line 698
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 699
    .line 700
    .line 701
    move-result-object v7

    .line 702
    invoke-static {v10, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 703
    .line 704
    .line 705
    move-result-object v5

    .line 706
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 707
    .line 708
    .line 709
    iget-boolean v8, v10, Ll2/t;->S:Z

    .line 710
    .line 711
    if-eqz v8, :cond_19

    .line 712
    .line 713
    invoke-virtual {v10, v3}, Ll2/t;->l(Lay0/a;)V

    .line 714
    .line 715
    .line 716
    :goto_12
    move-object/from16 v3, v27

    .line 717
    .line 718
    goto :goto_13

    .line 719
    :cond_19
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 720
    .line 721
    .line 722
    goto :goto_12

    .line 723
    :goto_13
    invoke-static {v3, v0, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 724
    .line 725
    .line 726
    move-object/from16 v0, v26

    .line 727
    .line 728
    invoke-static {v0, v7, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 729
    .line 730
    .line 731
    iget-boolean v0, v10, Ll2/t;->S:Z

    .line 732
    .line 733
    if-nez v0, :cond_1a

    .line 734
    .line 735
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 736
    .line 737
    .line 738
    move-result-object v0

    .line 739
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 740
    .line 741
    .line 742
    move-result-object v3

    .line 743
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 744
    .line 745
    .line 746
    move-result v0

    .line 747
    if-nez v0, :cond_1b

    .line 748
    .line 749
    :cond_1a
    move-object/from16 v0, v25

    .line 750
    .line 751
    goto :goto_15

    .line 752
    :cond_1b
    :goto_14
    move-object/from16 v6, v33

    .line 753
    .line 754
    goto :goto_16

    .line 755
    :goto_15
    invoke-static {v6, v10, v6, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 756
    .line 757
    .line 758
    goto :goto_14

    .line 759
    :goto_16
    invoke-static {v6, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 760
    .line 761
    .line 762
    const v0, 0x57715417

    .line 763
    .line 764
    .line 765
    move-object/from16 v3, v34

    .line 766
    .line 767
    if-eqz v3, :cond_1c

    .line 768
    .line 769
    const v5, 0x581bae6e

    .line 770
    .line 771
    .line 772
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 773
    .line 774
    .line 775
    new-instance v5, Lg4/g;

    .line 776
    .line 777
    invoke-direct {v5, v3}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 778
    .line 779
    .line 780
    const-string v3, "charging_statistics_primary_value_"

    .line 781
    .line 782
    invoke-static {v3, v1, v2}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 783
    .line 784
    .line 785
    move-result-object v6

    .line 786
    invoke-static {v10}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 787
    .line 788
    .line 789
    move-result-object v3

    .line 790
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 791
    .line 792
    .line 793
    move-result-object v7

    .line 794
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 795
    .line 796
    .line 797
    move-result-object v3

    .line 798
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 799
    .line 800
    .line 801
    move-result-wide v8

    .line 802
    const/16 v23, 0x0

    .line 803
    .line 804
    const v24, 0xfff0

    .line 805
    .line 806
    .line 807
    move-object/from16 v21, v10

    .line 808
    .line 809
    const-wide/16 v10, 0x0

    .line 810
    .line 811
    const-wide/16 v12, 0x0

    .line 812
    .line 813
    const/4 v14, 0x0

    .line 814
    const-wide/16 v15, 0x0

    .line 815
    .line 816
    const/16 v17, 0x0

    .line 817
    .line 818
    const/16 v18, 0x0

    .line 819
    .line 820
    const/16 v19, 0x0

    .line 821
    .line 822
    const/16 v20, 0x0

    .line 823
    .line 824
    const/16 v22, 0x0

    .line 825
    .line 826
    invoke-static/range {v5 .. v24}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 827
    .line 828
    .line 829
    move-object/from16 v10, v21

    .line 830
    .line 831
    const/4 v3, 0x0

    .line 832
    :goto_17
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 833
    .line 834
    .line 835
    move-object/from16 v5, v30

    .line 836
    .line 837
    goto :goto_18

    .line 838
    :cond_1c
    const/4 v3, 0x0

    .line 839
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 840
    .line 841
    .line 842
    goto :goto_17

    .line 843
    :goto_18
    if-eqz v5, :cond_1d

    .line 844
    .line 845
    const v0, 0x58220e4a

    .line 846
    .line 847
    .line 848
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 849
    .line 850
    .line 851
    new-instance v0, Lg4/g;

    .line 852
    .line 853
    invoke-direct {v0, v5}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 854
    .line 855
    .line 856
    const-string v5, "charging_statistics_secondary_value_"

    .line 857
    .line 858
    invoke-static {v5, v1, v2}, Lc1/j0;->k(Ljava/lang/String;ILx2/p;)Lx2/s;

    .line 859
    .line 860
    .line 861
    move-result-object v6

    .line 862
    invoke-static {v10}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 863
    .line 864
    .line 865
    move-result-object v5

    .line 866
    invoke-virtual {v5}, Lj91/f;->a()Lg4/p0;

    .line 867
    .line 868
    .line 869
    move-result-object v7

    .line 870
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 871
    .line 872
    .line 873
    move-result-object v5

    .line 874
    invoke-virtual {v5}, Lj91/e;->s()J

    .line 875
    .line 876
    .line 877
    move-result-wide v8

    .line 878
    const/16 v23, 0x0

    .line 879
    .line 880
    const v24, 0xfff0

    .line 881
    .line 882
    .line 883
    move-object/from16 v21, v10

    .line 884
    .line 885
    const-wide/16 v10, 0x0

    .line 886
    .line 887
    const-wide/16 v12, 0x0

    .line 888
    .line 889
    const/4 v14, 0x0

    .line 890
    const-wide/16 v15, 0x0

    .line 891
    .line 892
    const/16 v17, 0x0

    .line 893
    .line 894
    const/16 v18, 0x0

    .line 895
    .line 896
    const/16 v19, 0x0

    .line 897
    .line 898
    const/16 v20, 0x0

    .line 899
    .line 900
    const/16 v22, 0x0

    .line 901
    .line 902
    move-object v5, v0

    .line 903
    invoke-static/range {v5 .. v24}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 904
    .line 905
    .line 906
    move-object/from16 v10, v21

    .line 907
    .line 908
    :goto_19
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 909
    .line 910
    .line 911
    const/4 v5, 0x1

    .line 912
    goto :goto_1a

    .line 913
    :cond_1d
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 914
    .line 915
    .line 916
    goto :goto_19

    .line 917
    :goto_1a
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 918
    .line 919
    .line 920
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 921
    .line 922
    .line 923
    iget-boolean v0, v4, Ltd/e;->f:Z

    .line 924
    .line 925
    if-nez v0, :cond_1e

    .line 926
    .line 927
    const v0, 0x1455d603

    .line 928
    .line 929
    .line 930
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 931
    .line 932
    .line 933
    new-instance v0, Lxf0/i2;

    .line 934
    .line 935
    const/16 v5, 0x1b

    .line 936
    .line 937
    invoke-direct {v0, v5}, Lxf0/i2;-><init>(I)V

    .line 938
    .line 939
    .line 940
    invoke-static {v2, v0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 941
    .line 942
    .line 943
    move-result-object v0

    .line 944
    invoke-static {v3, v3, v10, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 945
    .line 946
    .line 947
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 948
    .line 949
    .line 950
    :goto_1b
    const/4 v3, 0x1

    .line 951
    goto :goto_1c

    .line 952
    :cond_1e
    const v0, 0x1456f6d2

    .line 953
    .line 954
    .line 955
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 956
    .line 957
    .line 958
    const/16 v0, 0x20

    .line 959
    .line 960
    int-to-float v0, v0

    .line 961
    invoke-static {v2, v0, v10, v3}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 962
    .line 963
    .line 964
    goto :goto_1b

    .line 965
    :goto_1c
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 966
    .line 967
    .line 968
    goto :goto_1d

    .line 969
    :cond_1f
    move-object v4, v1

    .line 970
    move v1, v2

    .line 971
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 972
    .line 973
    .line 974
    :goto_1d
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 975
    .line 976
    .line 977
    move-result-object v6

    .line 978
    if-eqz v6, :cond_20

    .line 979
    .line 980
    new-instance v0, Lck/h;

    .line 981
    .line 982
    const/4 v5, 0x0

    .line 983
    move-object/from16 v3, p2

    .line 984
    .line 985
    move v2, v1

    .line 986
    move-object v1, v4

    .line 987
    move/from16 v4, p4

    .line 988
    .line 989
    invoke-direct/range {v0 .. v5}, Lck/h;-><init>(Ljava/lang/Object;ILay0/k;II)V

    .line 990
    .line 991
    .line 992
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 993
    .line 994
    :cond_20
    return-void
.end method

.method public static final e(IILjava/lang/String;Ll2/o;)V
    .locals 25

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    check-cast v3, Ll2/t;

    .line 8
    .line 9
    const v4, 0x66c4ea94

    .line 10
    .line 11
    .line 12
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v4, p1, 0x6

    .line 16
    .line 17
    if-nez v4, :cond_1

    .line 18
    .line 19
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    if-eqz v4, :cond_0

    .line 24
    .line 25
    const/4 v4, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v4, 0x2

    .line 28
    :goto_0
    or-int v4, p1, v4

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move/from16 v4, p1

    .line 32
    .line 33
    :goto_1
    and-int/lit8 v5, p1, 0x30

    .line 34
    .line 35
    const/16 v6, 0x10

    .line 36
    .line 37
    if-nez v5, :cond_3

    .line 38
    .line 39
    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    const/16 v5, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v5, v6

    .line 49
    :goto_2
    or-int/2addr v4, v5

    .line 50
    :cond_3
    and-int/lit8 v5, v4, 0x13

    .line 51
    .line 52
    const/16 v7, 0x12

    .line 53
    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x1

    .line 56
    if-eq v5, v7, :cond_4

    .line 57
    .line 58
    move v5, v9

    .line 59
    goto :goto_3

    .line 60
    :cond_4
    move v5, v8

    .line 61
    :goto_3
    and-int/2addr v4, v9

    .line 62
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_8

    .line 67
    .line 68
    const/high16 v4, 0x3f800000    # 1.0f

    .line 69
    .line 70
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 71
    .line 72
    invoke-static {v10, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 77
    .line 78
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 79
    .line 80
    invoke-static {v5, v7, v3, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    iget-wide v7, v3, Ll2/t;->T:J

    .line 85
    .line 86
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 87
    .line 88
    .line 89
    move-result v7

    .line 90
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 91
    .line 92
    .line 93
    move-result-object v8

    .line 94
    invoke-static {v3, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 99
    .line 100
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 104
    .line 105
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 106
    .line 107
    .line 108
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 109
    .line 110
    if-eqz v12, :cond_5

    .line 111
    .line 112
    invoke-virtual {v3, v11}, Ll2/t;->l(Lay0/a;)V

    .line 113
    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_5
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 117
    .line 118
    .line 119
    :goto_4
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 120
    .line 121
    invoke-static {v11, v5, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 125
    .line 126
    invoke-static {v5, v8, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 127
    .line 128
    .line 129
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 130
    .line 131
    iget-boolean v8, v3, Ll2/t;->S:Z

    .line 132
    .line 133
    if-nez v8, :cond_6

    .line 134
    .line 135
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 140
    .line 141
    .line 142
    move-result-object v11

    .line 143
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v8

    .line 147
    if-nez v8, :cond_7

    .line 148
    .line 149
    :cond_6
    invoke-static {v7, v3, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 150
    .line 151
    .line 152
    :cond_7
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 153
    .line 154
    invoke-static {v5, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 155
    .line 156
    .line 157
    int-to-float v14, v6

    .line 158
    const/4 v15, 0x7

    .line 159
    const/4 v11, 0x0

    .line 160
    const/4 v12, 0x0

    .line 161
    const/4 v13, 0x0

    .line 162
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    invoke-static {v4}, Lzb/o0;->b(Lx2/s;)Lx2/s;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    new-instance v5, Ljava/lang/StringBuilder;

    .line 171
    .line 172
    const-string v6, "charging_statistics_section_title_"

    .line 173
    .line 174
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    invoke-static {v4, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v4

    .line 188
    new-instance v5, Lg4/g;

    .line 189
    .line 190
    invoke-direct {v5, v2}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 194
    .line 195
    invoke-virtual {v3, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v6

    .line 199
    check-cast v6, Lj91/f;

    .line 200
    .line 201
    invoke-virtual {v6}, Lj91/f;->k()Lg4/p0;

    .line 202
    .line 203
    .line 204
    move-result-object v6

    .line 205
    const/16 v21, 0x0

    .line 206
    .line 207
    const v22, 0xfff8

    .line 208
    .line 209
    .line 210
    move-object/from16 v19, v3

    .line 211
    .line 212
    move-object v3, v5

    .line 213
    move-object v5, v6

    .line 214
    const-wide/16 v6, 0x0

    .line 215
    .line 216
    move v11, v9

    .line 217
    const-wide/16 v8, 0x0

    .line 218
    .line 219
    move-object v13, v10

    .line 220
    move v12, v11

    .line 221
    const-wide/16 v10, 0x0

    .line 222
    .line 223
    move v14, v12

    .line 224
    const/4 v12, 0x0

    .line 225
    move-object/from16 v16, v13

    .line 226
    .line 227
    move v15, v14

    .line 228
    const-wide/16 v13, 0x0

    .line 229
    .line 230
    move/from16 v17, v15

    .line 231
    .line 232
    const/4 v15, 0x0

    .line 233
    move-object/from16 v18, v16

    .line 234
    .line 235
    const/16 v16, 0x0

    .line 236
    .line 237
    move/from16 v20, v17

    .line 238
    .line 239
    const/16 v17, 0x0

    .line 240
    .line 241
    move-object/from16 v23, v18

    .line 242
    .line 243
    const/16 v18, 0x0

    .line 244
    .line 245
    move/from16 v24, v20

    .line 246
    .line 247
    const/16 v20, 0x0

    .line 248
    .line 249
    move-object/from16 v1, v23

    .line 250
    .line 251
    move/from16 v0, v24

    .line 252
    .line 253
    invoke-static/range {v3 .. v22}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 254
    .line 255
    .line 256
    move-object/from16 v3, v19

    .line 257
    .line 258
    const/16 v4, 0x8

    .line 259
    .line 260
    int-to-float v4, v4

    .line 261
    invoke-static {v1, v4, v3, v0}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 262
    .line 263
    .line 264
    goto :goto_5

    .line 265
    :cond_8
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 266
    .line 267
    .line 268
    :goto_5
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    if-eqz v0, :cond_9

    .line 273
    .line 274
    new-instance v1, Lck/d;

    .line 275
    .line 276
    const/4 v3, 0x0

    .line 277
    move/from16 v4, p0

    .line 278
    .line 279
    move/from16 v5, p1

    .line 280
    .line 281
    invoke-direct {v1, v2, v4, v5, v3}, Lck/d;-><init>(Ljava/lang/String;III)V

    .line 282
    .line 283
    .line 284
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 285
    .line 286
    :cond_9
    return-void
.end method

.method public static final f(Ltd/p;Lay0/k;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v9, p2

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const p2, 0x7ea14540

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x6

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-nez p2, :cond_2

    .line 14
    .line 15
    and-int/lit8 p2, p3, 0x8

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    :goto_0
    if-eqz p2, :cond_1

    .line 29
    .line 30
    move p2, v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 p2, 0x2

    .line 33
    :goto_1
    or-int/2addr p2, p3

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move p2, p3

    .line 36
    :goto_2
    and-int/lit8 v1, p3, 0x30

    .line 37
    .line 38
    const/16 v2, 0x20

    .line 39
    .line 40
    if-nez v1, :cond_4

    .line 41
    .line 42
    invoke-virtual {v9, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    move v1, v2

    .line 49
    goto :goto_3

    .line 50
    :cond_3
    const/16 v1, 0x10

    .line 51
    .line 52
    :goto_3
    or-int/2addr p2, v1

    .line 53
    :cond_4
    and-int/lit8 v1, p2, 0x13

    .line 54
    .line 55
    const/16 v3, 0x12

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    const/4 v5, 0x1

    .line 59
    if-eq v1, v3, :cond_5

    .line 60
    .line 61
    move v1, v5

    .line 62
    goto :goto_4

    .line 63
    :cond_5
    move v1, v4

    .line 64
    :goto_4
    and-int/lit8 v3, p2, 0x1

    .line 65
    .line 66
    invoke-virtual {v9, v3, v1}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_b

    .line 71
    .line 72
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 73
    .line 74
    const/high16 v3, 0x3f800000    # 1.0f

    .line 75
    .line 76
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    and-int/lit8 v3, p2, 0xe

    .line 81
    .line 82
    if-eq v3, v0, :cond_7

    .line 83
    .line 84
    and-int/lit8 v0, p2, 0x8

    .line 85
    .line 86
    if-eqz v0, :cond_6

    .line 87
    .line 88
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_6

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_6
    move v0, v4

    .line 96
    goto :goto_6

    .line 97
    :cond_7
    :goto_5
    move v0, v5

    .line 98
    :goto_6
    and-int/lit8 p2, p2, 0x70

    .line 99
    .line 100
    if-ne p2, v2, :cond_8

    .line 101
    .line 102
    move v4, v5

    .line 103
    :cond_8
    or-int p2, v0, v4

    .line 104
    .line 105
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-nez p2, :cond_9

    .line 110
    .line 111
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 112
    .line 113
    if-ne v0, p2, :cond_a

    .line 114
    .line 115
    :cond_9
    new-instance v0, Lck/f;

    .line 116
    .line 117
    const/4 p2, 0x1

    .line 118
    invoke-direct {v0, p0, p1, p2}, Lck/f;-><init>(Ltd/p;Lay0/k;I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_a
    move-object v8, v0

    .line 125
    check-cast v8, Lay0/k;

    .line 126
    .line 127
    const/4 v10, 0x6

    .line 128
    const/16 v11, 0x1fe

    .line 129
    .line 130
    move-object v0, v1

    .line 131
    const/4 v1, 0x0

    .line 132
    const/4 v2, 0x0

    .line 133
    const/4 v3, 0x0

    .line 134
    const/4 v4, 0x0

    .line 135
    const/4 v5, 0x0

    .line 136
    const/4 v6, 0x0

    .line 137
    const/4 v7, 0x0

    .line 138
    invoke-static/range {v0 .. v11}, La/a;->b(Lx2/s;Lm1/t;Lk1/z0;Lk1/g;Lx2/i;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 139
    .line 140
    .line 141
    goto :goto_7

    .line 142
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 143
    .line 144
    .line 145
    :goto_7
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    if-eqz p2, :cond_c

    .line 150
    .line 151
    new-instance v0, Lck/e;

    .line 152
    .line 153
    const/4 v1, 0x3

    .line 154
    invoke-direct {v0, p0, p1, p3, v1}, Lck/e;-><init>(Ltd/p;Lay0/k;II)V

    .line 155
    .line 156
    .line 157
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 158
    .line 159
    :cond_c
    return-void
.end method

.method public static final g(Ltd/p;Lay0/k;Ll2/o;I)V
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    check-cast v3, Ll2/t;

    .line 8
    .line 9
    const v4, -0x1189f0bb

    .line 10
    .line 11
    .line 12
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v4, p3, 0x6

    .line 16
    .line 17
    const/4 v5, 0x2

    .line 18
    if-nez v4, :cond_2

    .line 19
    .line 20
    and-int/lit8 v4, p3, 0x8

    .line 21
    .line 22
    if-nez v4, :cond_0

    .line 23
    .line 24
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    :goto_0
    if-eqz v4, :cond_1

    .line 34
    .line 35
    const/4 v4, 0x4

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v4, v5

    .line 38
    :goto_1
    or-int v4, p3, v4

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    move/from16 v4, p3

    .line 42
    .line 43
    :goto_2
    and-int/lit8 v6, p3, 0x30

    .line 44
    .line 45
    const/16 v7, 0x10

    .line 46
    .line 47
    if-nez v6, :cond_4

    .line 48
    .line 49
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-eqz v6, :cond_3

    .line 54
    .line 55
    const/16 v6, 0x20

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_3
    move v6, v7

    .line 59
    :goto_3
    or-int/2addr v4, v6

    .line 60
    :cond_4
    and-int/lit8 v6, v4, 0x13

    .line 61
    .line 62
    const/16 v8, 0x12

    .line 63
    .line 64
    const/4 v9, 0x1

    .line 65
    const/4 v10, 0x0

    .line 66
    if-eq v6, v8, :cond_5

    .line 67
    .line 68
    move v6, v9

    .line 69
    goto :goto_4

    .line 70
    :cond_5
    move v6, v10

    .line 71
    :goto_4
    and-int/lit8 v8, v4, 0x1

    .line 72
    .line 73
    invoke-virtual {v3, v8, v6}, Ll2/t;->O(IZ)Z

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    if-eqz v6, :cond_c

    .line 78
    .line 79
    const/16 v6, 0x18

    .line 80
    .line 81
    int-to-float v6, v6

    .line 82
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 83
    .line 84
    invoke-static {v8, v6}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v11

    .line 88
    invoke-static {v3, v11}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 89
    .line 90
    .line 91
    and-int/lit8 v11, v4, 0xe

    .line 92
    .line 93
    const/16 v12, 0x8

    .line 94
    .line 95
    or-int/2addr v11, v12

    .line 96
    and-int/lit8 v4, v4, 0x70

    .line 97
    .line 98
    or-int/2addr v4, v11

    .line 99
    invoke-static {v0, v1, v3, v4}, Lck/i;->f(Ltd/p;Lay0/k;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    sget-object v11, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 103
    .line 104
    int-to-float v7, v7

    .line 105
    const/4 v12, 0x0

    .line 106
    invoke-static {v11, v7, v12, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 111
    .line 112
    sget-object v11, Lx2/c;->p:Lx2/h;

    .line 113
    .line 114
    invoke-static {v7, v11, v3, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    iget-wide v11, v3, Ll2/t;->T:J

    .line 119
    .line 120
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 121
    .line 122
    .line 123
    move-result v11

    .line 124
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 125
    .line 126
    .line 127
    move-result-object v12

    .line 128
    invoke-static {v3, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 133
    .line 134
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 138
    .line 139
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 140
    .line 141
    .line 142
    iget-boolean v14, v3, Ll2/t;->S:Z

    .line 143
    .line 144
    if-eqz v14, :cond_6

    .line 145
    .line 146
    invoke-virtual {v3, v13}, Ll2/t;->l(Lay0/a;)V

    .line 147
    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_6
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 151
    .line 152
    .line 153
    :goto_5
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 154
    .line 155
    invoke-static {v13, v7, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 156
    .line 157
    .line 158
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 159
    .line 160
    invoke-static {v7, v12, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 161
    .line 162
    .line 163
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 164
    .line 165
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 166
    .line 167
    if-nez v12, :cond_7

    .line 168
    .line 169
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v12

    .line 173
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 174
    .line 175
    .line 176
    move-result-object v13

    .line 177
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v12

    .line 181
    if-nez v12, :cond_8

    .line 182
    .line 183
    :cond_7
    invoke-static {v11, v3, v11, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 184
    .line 185
    .line 186
    :cond_8
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 187
    .line 188
    invoke-static {v7, v5, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 189
    .line 190
    .line 191
    iget-boolean v5, v0, Ltd/p;->b:Z

    .line 192
    .line 193
    if-eqz v5, :cond_9

    .line 194
    .line 195
    const v5, 0x2dc36446

    .line 196
    .line 197
    .line 198
    invoke-virtual {v3, v5}, Ll2/t;->Y(I)V

    .line 199
    .line 200
    .line 201
    invoke-static {v8, v6}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    invoke-static {v3, v5}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 206
    .line 207
    .line 208
    const-string v5, "charging_statistics_disclaimer"

    .line 209
    .line 210
    invoke-static {v8, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v5

    .line 214
    iget-object v7, v0, Ltd/p;->a:Ljava/lang/String;

    .line 215
    .line 216
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    sget-object v11, Lj91/j;->a:Ll2/u2;

    .line 220
    .line 221
    invoke-virtual {v3, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v11

    .line 225
    check-cast v11, Lj91/f;

    .line 226
    .line 227
    invoke-virtual {v11}, Lj91/f;->e()Lg4/p0;

    .line 228
    .line 229
    .line 230
    move-result-object v11

    .line 231
    const/16 v23, 0x0

    .line 232
    .line 233
    const v24, 0xfff8

    .line 234
    .line 235
    .line 236
    move-object/from16 v21, v3

    .line 237
    .line 238
    move v12, v6

    .line 239
    move-object v3, v7

    .line 240
    const-wide/16 v6, 0x0

    .line 241
    .line 242
    move-object v14, v8

    .line 243
    move v13, v9

    .line 244
    const-wide/16 v8, 0x0

    .line 245
    .line 246
    move v15, v10

    .line 247
    const/4 v10, 0x0

    .line 248
    move/from16 v17, v4

    .line 249
    .line 250
    move-object v4, v11

    .line 251
    move/from16 v16, v12

    .line 252
    .line 253
    const-wide/16 v11, 0x0

    .line 254
    .line 255
    move/from16 v18, v13

    .line 256
    .line 257
    const/4 v13, 0x0

    .line 258
    move-object/from16 v19, v14

    .line 259
    .line 260
    const/4 v14, 0x0

    .line 261
    move/from16 v22, v15

    .line 262
    .line 263
    move/from16 v20, v16

    .line 264
    .line 265
    const-wide/16 v15, 0x0

    .line 266
    .line 267
    move/from16 v25, v17

    .line 268
    .line 269
    const/16 v17, 0x0

    .line 270
    .line 271
    move/from16 v26, v18

    .line 272
    .line 273
    const/16 v18, 0x0

    .line 274
    .line 275
    move-object/from16 v27, v19

    .line 276
    .line 277
    const/16 v19, 0x0

    .line 278
    .line 279
    move/from16 v28, v20

    .line 280
    .line 281
    const/16 v20, 0x0

    .line 282
    .line 283
    move/from16 v29, v22

    .line 284
    .line 285
    const/16 v22, 0x180

    .line 286
    .line 287
    move/from16 v30, v25

    .line 288
    .line 289
    move-object/from16 v0, v27

    .line 290
    .line 291
    move/from16 v2, v28

    .line 292
    .line 293
    move/from16 v1, v29

    .line 294
    .line 295
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 296
    .line 297
    .line 298
    move-object/from16 v3, v21

    .line 299
    .line 300
    :goto_6
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 301
    .line 302
    .line 303
    goto :goto_7

    .line 304
    :cond_9
    move/from16 v30, v4

    .line 305
    .line 306
    move v2, v6

    .line 307
    move-object v0, v8

    .line 308
    move v1, v10

    .line 309
    const v4, 0x2d63ec87

    .line 310
    .line 311
    .line 312
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 313
    .line 314
    .line 315
    goto :goto_6

    .line 316
    :goto_7
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    invoke-static {v3, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 321
    .line 322
    .line 323
    move-object/from16 v0, p0

    .line 324
    .line 325
    iget-boolean v2, v0, Ltd/p;->g:Z

    .line 326
    .line 327
    if-eqz v2, :cond_a

    .line 328
    .line 329
    const v2, -0x7222d201

    .line 330
    .line 331
    .line 332
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 333
    .line 334
    .line 335
    sget-object v2, Lck/c;->d:Lt2/b;

    .line 336
    .line 337
    const/4 v4, 0x6

    .line 338
    invoke-static {v2, v3, v4}, Ldk/b;->i(Lt2/b;Ll2/o;I)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    :goto_8
    move-object/from16 v2, p1

    .line 345
    .line 346
    :goto_9
    const/4 v13, 0x1

    .line 347
    goto :goto_a

    .line 348
    :cond_a
    iget-object v2, v0, Ltd/p;->c:Ljava/util/List;

    .line 349
    .line 350
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 351
    .line 352
    .line 353
    move-result v2

    .line 354
    if-eqz v2, :cond_b

    .line 355
    .line 356
    const v2, -0x7222c4af

    .line 357
    .line 358
    .line 359
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 360
    .line 361
    .line 362
    invoke-static {v3, v1}, Lck/i;->h(Ll2/o;I)V

    .line 363
    .line 364
    .line 365
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 366
    .line 367
    .line 368
    goto :goto_8

    .line 369
    :cond_b
    const v2, -0x7222bf2a

    .line 370
    .line 371
    .line 372
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 373
    .line 374
    .line 375
    move-object/from16 v2, p1

    .line 376
    .line 377
    move/from16 v4, v30

    .line 378
    .line 379
    invoke-static {v0, v2, v3, v4}, Lck/i;->a(Ltd/p;Lay0/k;Ll2/o;I)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 383
    .line 384
    .line 385
    goto :goto_9

    .line 386
    :goto_a
    invoke-virtual {v3, v13}, Ll2/t;->q(Z)V

    .line 387
    .line 388
    .line 389
    goto :goto_b

    .line 390
    :cond_c
    move-object v2, v1

    .line 391
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 392
    .line 393
    .line 394
    :goto_b
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 395
    .line 396
    .line 397
    move-result-object v1

    .line 398
    if-eqz v1, :cond_d

    .line 399
    .line 400
    new-instance v3, Lck/e;

    .line 401
    .line 402
    const/4 v4, 0x1

    .line 403
    move/from16 v5, p3

    .line 404
    .line 405
    invoke-direct {v3, v0, v2, v5, v4}, Lck/e;-><init>(Ltd/p;Lay0/k;II)V

    .line 406
    .line 407
    .line 408
    iput-object v3, v1, Ll2/u1;->d:Lay0/n;

    .line 409
    .line 410
    :cond_d
    return-void
.end method

.method public static final h(Ll2/o;I)V
    .locals 7

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, 0x73ed4023

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {v5, v0, p0}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    const/16 v6, 0x6c06

    .line 25
    .line 26
    const-string v0, "charging_statistics"

    .line 27
    .line 28
    const v1, 0x7f120927

    .line 29
    .line 30
    .line 31
    const v2, 0x7f120926

    .line 32
    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-static/range {v0 .. v6}, Ldk/e;->a(Ljava/lang/String;IIILay0/a;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 40
    .line 41
    .line 42
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-eqz p0, :cond_2

    .line 47
    .line 48
    new-instance v0, Lck/a;

    .line 49
    .line 50
    const/4 v1, 0x2

    .line 51
    invoke-direct {v0, p1, v1}, Lck/a;-><init>(II)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 55
    .line 56
    :cond_2
    return-void
.end method

.method public static final i(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v7, p2

    .line 12
    check-cast v7, Ll2/t;

    .line 13
    .line 14
    const p2, 0x36067893

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v7, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    const/4 p2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p2, 0x2

    .line 29
    :goto_0
    or-int/2addr p2, p3

    .line 30
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr p2, v0

    .line 42
    and-int/lit8 v0, p2, 0x13

    .line 43
    .line 44
    const/16 v1, 0x12

    .line 45
    .line 46
    if-eq v0, v1, :cond_2

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/4 v0, 0x0

    .line 51
    :goto_2
    and-int/lit8 v1, p2, 0x1

    .line 52
    .line 53
    invoke-virtual {v7, v1, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    new-instance v0, Lak/l;

    .line 60
    .line 61
    const/4 v1, 0x5

    .line 62
    invoke-direct {v0, v1, p1}, Lak/l;-><init>(ILay0/k;)V

    .line 63
    .line 64
    .line 65
    const v1, -0x2357c6f6

    .line 66
    .line 67
    .line 68
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    new-instance v0, Lak/l;

    .line 73
    .line 74
    const/4 v1, 0x6

    .line 75
    invoke-direct {v0, v1, p1}, Lak/l;-><init>(ILay0/k;)V

    .line 76
    .line 77
    .line 78
    const v1, -0x4215d29c

    .line 79
    .line 80
    .line 81
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    and-int/lit8 p2, p2, 0xe

    .line 86
    .line 87
    const/16 v0, 0x6db8

    .line 88
    .line 89
    or-int v8, v0, p2

    .line 90
    .line 91
    const/16 v9, 0x20

    .line 92
    .line 93
    sget-object v2, Lck/c;->a:Lt2/b;

    .line 94
    .line 95
    sget-object v3, Lck/c;->c:Lt2/b;

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    move-object v1, p0

    .line 99
    invoke-static/range {v1 .. v9}, Llc/a;->a(Llc/q;Lay0/o;Lay0/o;Lt2/b;Lt2/b;Lay0/n;Ll2/o;II)V

    .line 100
    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_3
    move-object v1, p0

    .line 104
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 105
    .line 106
    .line 107
    :goto_3
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    if-eqz p0, :cond_4

    .line 112
    .line 113
    new-instance p2, Lak/m;

    .line 114
    .line 115
    const/4 v0, 0x1

    .line 116
    invoke-direct {p2, v1, p1, p3, v0}, Lak/m;-><init>(Llc/q;Lay0/k;II)V

    .line 117
    .line 118
    .line 119
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 120
    .line 121
    :cond_4
    return-void
.end method
