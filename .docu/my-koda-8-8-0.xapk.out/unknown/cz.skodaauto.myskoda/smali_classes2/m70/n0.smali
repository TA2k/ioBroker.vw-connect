.class public abstract Lm70/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    sget-object v0, Ll70/a0;->d:Ll70/a0;

    .line 2
    .line 3
    sget-object v1, Ljava/time/Month;->MAY:Ljava/time/Month;

    .line 4
    .line 5
    const/16 v2, 0x7e9

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    invoke-static {v2, v1, v3}, Ljava/time/LocalDate;->of(ILjava/time/Month;I)Ljava/time/LocalDate;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    const-string v4, "of(...)"

    .line 13
    .line 14
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v5, Lm70/a;

    .line 18
    .line 19
    new-instance v6, Llx0/l;

    .line 20
    .line 21
    const-string v7, "Rome"

    .line 22
    .line 23
    const-string v8, "Terracina"

    .line 24
    .line 25
    invoke-direct {v6, v7, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const-string v8, "21:02"

    .line 29
    .line 30
    invoke-static {v8}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    const-string v9, "22:43"

    .line 35
    .line 36
    invoke-static {v9}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    new-instance v10, Llx0/l;

    .line 41
    .line 42
    invoke-direct {v10, v8, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    const/16 v8, 0x6f

    .line 46
    .line 47
    int-to-double v8, v8

    .line 48
    const-wide v11, 0x408f400000000000L    # 1000.0

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    mul-double/2addr v8, v11

    .line 54
    invoke-direct {v5, v6, v10, v8, v9}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 55
    .line 56
    .line 57
    new-instance v6, Lm70/a;

    .line 58
    .line 59
    new-instance v8, Llx0/l;

    .line 60
    .line 61
    const-string v9, "Florence"

    .line 62
    .line 63
    invoke-direct {v8, v9, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    const-string v7, "05:20"

    .line 67
    .line 68
    invoke-static {v7}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    const-string v10, "09:45"

    .line 73
    .line 74
    invoke-static {v10}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 75
    .line 76
    .line 77
    move-result-object v10

    .line 78
    new-instance v13, Llx0/l;

    .line 79
    .line 80
    invoke-direct {v13, v7, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const/16 v7, 0x113

    .line 84
    .line 85
    int-to-double v14, v7

    .line 86
    mul-double/2addr v14, v11

    .line 87
    invoke-direct {v6, v8, v13, v14, v15}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 88
    .line 89
    .line 90
    filled-new-array {v5, v6}, [Lm70/a;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    invoke-static {v5}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    invoke-static {v3, v5}, Lm70/n0;->a(Ljava/time/LocalDate;Ljava/util/List;)Ll70/a;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    const/4 v5, 0x2

    .line 103
    invoke-static {v2, v1, v5}, Ljava/time/LocalDate;->of(ILjava/time/Month;I)Ljava/time/LocalDate;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    new-instance v6, Lm70/a;

    .line 111
    .line 112
    new-instance v7, Llx0/l;

    .line 113
    .line 114
    const-string v8, "Innsbruck"

    .line 115
    .line 116
    invoke-direct {v7, v8, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    const-string v9, "16:01"

    .line 120
    .line 121
    invoke-static {v9}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 122
    .line 123
    .line 124
    move-result-object v9

    .line 125
    const-string v10, "23:47"

    .line 126
    .line 127
    invoke-static {v10}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    new-instance v13, Llx0/l;

    .line 132
    .line 133
    invoke-direct {v13, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    const/16 v9, 0x1e8

    .line 137
    .line 138
    int-to-double v9, v9

    .line 139
    mul-double/2addr v9, v11

    .line 140
    invoke-direct {v6, v7, v13, v9, v10}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 141
    .line 142
    .line 143
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    invoke-static {v5, v6}, Lm70/n0;->a(Ljava/time/LocalDate;Ljava/util/List;)Ll70/a;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    const/4 v6, 0x1

    .line 152
    invoke-static {v2, v1, v6}, Ljava/time/LocalDate;->of(ILjava/time/Month;I)Ljava/time/LocalDate;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    new-instance v2, Lm70/a;

    .line 160
    .line 161
    new-instance v6, Llx0/l;

    .line 162
    .line 163
    const-string v7, "Prague"

    .line 164
    .line 165
    invoke-direct {v6, v7, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    const-string v8, "06:03"

    .line 169
    .line 170
    invoke-static {v8}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 171
    .line 172
    .line 173
    move-result-object v8

    .line 174
    const-string v9, "14:08"

    .line 175
    .line 176
    invoke-static {v9}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 177
    .line 178
    .line 179
    move-result-object v9

    .line 180
    new-instance v10, Llx0/l;

    .line 181
    .line 182
    invoke-direct {v10, v8, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    const/16 v8, 0x227

    .line 186
    .line 187
    int-to-double v8, v8

    .line 188
    mul-double/2addr v8, v11

    .line 189
    invoke-direct {v2, v6, v10, v8, v9}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 190
    .line 191
    .line 192
    new-instance v6, Lm70/a;

    .line 193
    .line 194
    new-instance v8, Llx0/l;

    .line 195
    .line 196
    const-string v9, "Jankovcova"

    .line 197
    .line 198
    invoke-direct {v8, v9, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    const-string v9, "08:00"

    .line 202
    .line 203
    invoke-static {v9}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 204
    .line 205
    .line 206
    move-result-object v9

    .line 207
    const-string v10, "09:09"

    .line 208
    .line 209
    invoke-static {v10}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 210
    .line 211
    .line 212
    move-result-object v10

    .line 213
    new-instance v13, Llx0/l;

    .line 214
    .line 215
    invoke-direct {v13, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    const/16 v9, 0x1964

    .line 219
    .line 220
    int-to-double v9, v9

    .line 221
    invoke-direct {v6, v8, v13, v9, v10}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 222
    .line 223
    .line 224
    filled-new-array {v2, v6}, [Lm70/a;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    invoke-static {v1, v2}, Lm70/n0;->a(Ljava/time/LocalDate;Ljava/util/List;)Ll70/a;

    .line 233
    .line 234
    .line 235
    move-result-object v1

    .line 236
    const/16 v2, 0x802

    .line 237
    .line 238
    sget-object v6, Ljava/time/Month;->APRIL:Ljava/time/Month;

    .line 239
    .line 240
    const/16 v8, 0x1e

    .line 241
    .line 242
    invoke-static {v2, v6, v8}, Ljava/time/LocalDate;->of(ILjava/time/Month;I)Ljava/time/LocalDate;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    new-instance v4, Lm70/a;

    .line 250
    .line 251
    new-instance v6, Llx0/l;

    .line 252
    .line 253
    const-string v8, "Berlin"

    .line 254
    .line 255
    invoke-direct {v6, v7, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    const-string v7, "16:00"

    .line 259
    .line 260
    invoke-static {v7}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    const-string v8, "16:43"

    .line 265
    .line 266
    invoke-static {v8}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 267
    .line 268
    .line 269
    move-result-object v8

    .line 270
    new-instance v9, Llx0/l;

    .line 271
    .line 272
    invoke-direct {v9, v7, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    const/16 v7, 0x37

    .line 276
    .line 277
    int-to-double v7, v7

    .line 278
    mul-double/2addr v7, v11

    .line 279
    invoke-direct {v4, v6, v9, v7, v8}, Lm70/a;-><init>(Llx0/l;Llx0/l;D)V

    .line 280
    .line 281
    .line 282
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-static {v2, v4}, Lm70/n0;->a(Ljava/time/LocalDate;Ljava/util/List;)Ll70/a;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    filled-new-array {v3, v5, v1, v2}, [Ll70/a;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    new-instance v2, Ll70/j;

    .line 299
    .line 300
    const/4 v3, 0x0

    .line 301
    invoke-direct {v2, v0, v1, v3}, Ll70/j;-><init>(Ll70/a0;Ljava/util/List;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    sput-object v0, Lm70/n0;->a:Ljava/util/List;

    .line 309
    .line 310
    return-void
.end method

.method public static final a(Ljava/time/LocalDate;Ljava/util/List;)Ll70/a;
    .locals 33

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Iterable;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    if-eqz v4, :cond_0

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    check-cast v4, Lm70/a;

    .line 22
    .line 23
    iget-wide v4, v4, Lm70/a;->c:D

    .line 24
    .line 25
    add-double/2addr v2, v4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    double-to-int v1, v2

    .line 28
    int-to-double v6, v1

    .line 29
    new-instance v4, Ljava/util/ArrayList;

    .line 30
    .line 31
    const/16 v1, 0xa

    .line 32
    .line 33
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_1

    .line 49
    .line 50
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Lm70/a;

    .line 55
    .line 56
    iget-object v3, v2, Lm70/a;->a:Llx0/l;

    .line 57
    .line 58
    iget-object v5, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v11, v5

    .line 61
    check-cast v11, Ljava/lang/String;

    .line 62
    .line 63
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 64
    .line 65
    move-object v12, v3

    .line 66
    check-cast v12, Ljava/lang/String;

    .line 67
    .line 68
    iget-object v3, v2, Lm70/a;->b:Llx0/l;

    .line 69
    .line 70
    iget-object v5, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v13, v5

    .line 73
    check-cast v13, Ljava/time/LocalTime;

    .line 74
    .line 75
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v14, v3

    .line 78
    check-cast v14, Ljava/time/LocalTime;

    .line 79
    .line 80
    iget-wide v2, v2, Lm70/a;->c:D

    .line 81
    .line 82
    new-instance v8, Ll70/i;

    .line 83
    .line 84
    sget v5, Lmy0/c;->g:I

    .line 85
    .line 86
    sget-object v5, Lmy0/e;->i:Lmy0/e;

    .line 87
    .line 88
    invoke-static {v1, v5}, Lmy0/h;->s(ILmy0/e;)J

    .line 89
    .line 90
    .line 91
    move-result-wide v19

    .line 92
    const/16 v31, 0x0

    .line 93
    .line 94
    sget-object v32, Ll70/m;->a:Ll70/m;

    .line 95
    .line 96
    const-string v9, "id"

    .line 97
    .line 98
    const/4 v15, 0x0

    .line 99
    const/16 v16, 0x0

    .line 100
    .line 101
    const/16 v21, 0x0

    .line 102
    .line 103
    const/16 v22, 0x0

    .line 104
    .line 105
    const/16 v23, 0x0

    .line 106
    .line 107
    const/16 v24, 0x0

    .line 108
    .line 109
    const/16 v25, 0x0

    .line 110
    .line 111
    const/16 v26, 0x0

    .line 112
    .line 113
    const/16 v27, 0x0

    .line 114
    .line 115
    const/16 v28, 0x0

    .line 116
    .line 117
    const/16 v29, 0x0

    .line 118
    .line 119
    const/16 v30, 0x0

    .line 120
    .line 121
    move-object/from16 v10, p0

    .line 122
    .line 123
    move-wide/from16 v17, v2

    .line 124
    .line 125
    invoke-direct/range {v8 .. v32}, Ll70/i;-><init>(Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalTime;Ljava/time/LocalTime;Lqr0/d;Lqr0/d;DJLqr0/l;Lqr0/l;Lqr0/p;Lqr0/i;Lqr0/h;Lqr0/g;Lqr0/j;Lqr0/g;Lqr0/i;Ll70/u;Ljava/util/List;Ll70/o;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_1
    new-instance v2, Ll70/a;

    .line 133
    .line 134
    const/4 v5, 0x0

    .line 135
    move-object/from16 v3, p0

    .line 136
    .line 137
    invoke-direct/range {v2 .. v7}, Ll70/a;-><init>(Ljava/time/LocalDate;Ljava/util/ArrayList;Ll70/u;D)V

    .line 138
    .line 139
    .line 140
    return-object v2
.end method
