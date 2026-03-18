.class public final Lk70/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;

.field public m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lqu/c;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lk70/c;->d:I

    .line 1
    iput-object p1, p0, Lk70/c;->h:Ljava/lang/Object;

    iput-object p2, p0, Lk70/c;->i:Ljava/lang/Object;

    iput-object p3, p0, Lk70/c;->j:Ljava/lang/Object;

    iput-object p4, p0, Lk70/c;->k:Ljava/lang/Object;

    iput-object p5, p0, Lk70/c;->l:Ljava/lang/Object;

    iput-object p6, p0, Lk70/c;->m:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lk70/d;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lk70/c;->d:I

    .line 2
    iput-object p2, p0, Lk70/c;->i:Ljava/lang/Object;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lk70/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lqp/g;

    .line 9
    .line 10
    move-object v7, p3

    .line 11
    check-cast v7, Lkotlin/coroutines/Continuation;

    .line 12
    .line 13
    new-instance v0, Lk70/c;

    .line 14
    .line 15
    iget-object p3, p0, Lk70/c;->h:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v1, p3

    .line 18
    check-cast v1, Landroid/content/Context;

    .line 19
    .line 20
    iget-object p3, p0, Lk70/c;->i:Ljava/lang/Object;

    .line 21
    .line 22
    move-object v2, p3

    .line 23
    check-cast v2, Lqu/c;

    .line 24
    .line 25
    iget-object p3, p0, Lk70/c;->j:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v3, p3

    .line 28
    check-cast v3, Ll2/b1;

    .line 29
    .line 30
    iget-object p3, p0, Lk70/c;->k:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v4, p3

    .line 33
    check-cast v4, Ll2/b1;

    .line 34
    .line 35
    iget-object p3, p0, Lk70/c;->l:Ljava/lang/Object;

    .line 36
    .line 37
    move-object v5, p3

    .line 38
    check-cast v5, Ll2/b1;

    .line 39
    .line 40
    iget-object p0, p0, Lk70/c;->m:Ljava/lang/Object;

    .line 41
    .line 42
    move-object v6, p0

    .line 43
    check-cast v6, Ll2/b1;

    .line 44
    .line 45
    invoke-direct/range {v0 .. v7}, Lk70/c;-><init>(Landroid/content/Context;Lqu/c;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 46
    .line 47
    .line 48
    iput-object p1, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 49
    .line 50
    iput-object p2, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 51
    .line 52
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    invoke-virtual {v0, p0}, Lk70/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_0
    check-cast p1, Lyy0/j;

    .line 61
    .line 62
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    new-instance v0, Lk70/c;

    .line 65
    .line 66
    iget-object p0, p0, Lk70/c;->i:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lk70/d;

    .line 69
    .line 70
    invoke-direct {v0, p3, p0}, Lk70/c;-><init>(Lkotlin/coroutines/Continuation;Lk70/d;)V

    .line 71
    .line 72
    .line 73
    iput-object p1, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 74
    .line 75
    iput-object p2, v0, Lk70/c;->h:Ljava/lang/Object;

    .line 76
    .line 77
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    invoke-virtual {v0, p0}, Lk70/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lk70/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v4, v1

    .line 11
    check-cast v4, Lvy0/b0;

    .line 12
    .line 13
    iget-object v1, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v5, v1

    .line 16
    check-cast v5, Lqp/g;

    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v2, v0, Lk70/c;->e:I

    .line 21
    .line 22
    const/4 v10, 0x1

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    if-eq v2, v10, :cond_0

    .line 26
    .line 27
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_0
    invoke-static/range {p1 .. p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    throw v0

    .line 40
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    new-instance v2, Lvu/l;

    .line 44
    .line 45
    iget-object v3, v0, Lk70/c;->h:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v3, Landroid/content/Context;

    .line 48
    .line 49
    iget-object v6, v0, Lk70/c;->i:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v6, Lqu/c;

    .line 52
    .line 53
    iget-object v7, v0, Lk70/c;->j:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v7, Ll2/b1;

    .line 56
    .line 57
    iget-object v8, v0, Lk70/c;->k:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v8, Ll2/b1;

    .line 60
    .line 61
    iget-object v9, v0, Lk70/c;->l:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v9, Ll2/b1;

    .line 64
    .line 65
    invoke-direct/range {v2 .. v9}, Lvu/l;-><init>(Landroid/content/Context;Lvy0/b0;Lqp/g;Lqu/c;Ll2/b1;Ll2/b1;Ll2/b1;)V

    .line 66
    .line 67
    .line 68
    iget-object v3, v0, Lk70/c;->m:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v3, Ll2/b1;

    .line 71
    .line 72
    invoke-interface {v3, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    iput-object v2, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 77
    .line 78
    iput-object v2, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 79
    .line 80
    iput v10, v0, Lk70/c;->e:I

    .line 81
    .line 82
    invoke-static {v0}, Lvy0/e0;->h(Lrx0/c;)V

    .line 83
    .line 84
    .line 85
    return-object v1

    .line 86
    :pswitch_0
    iget-object v1, v0, Lk70/c;->i:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v1, Lk70/d;

    .line 89
    .line 90
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 91
    .line 92
    iget v3, v0, Lk70/c;->e:I

    .line 93
    .line 94
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    const/4 v5, 0x2

    .line 97
    const/4 v6, 0x1

    .line 98
    const/4 v7, 0x0

    .line 99
    if-eqz v3, :cond_6

    .line 100
    .line 101
    if-eq v3, v6, :cond_4

    .line 102
    .line 103
    if-ne v3, v5, :cond_3

    .line 104
    .line 105
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_2
    move-object v2, v4

    .line 109
    goto/16 :goto_7

    .line 110
    .line 111
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 112
    .line 113
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 114
    .line 115
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw v0

    .line 119
    :cond_4
    iget-object v3, v0, Lk70/c;->m:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v3, Li70/t;

    .line 122
    .line 123
    iget-object v8, v0, Lk70/c;->l:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v8, Ljava/lang/String;

    .line 126
    .line 127
    iget-object v9, v0, Lk70/c;->k:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v9, Ll70/k;

    .line 130
    .line 131
    iget-object v10, v0, Lk70/c;->j:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v10, Lss0/k;

    .line 134
    .line 135
    iget-object v11, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v11, Lyy0/j;

    .line 138
    .line 139
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    move-object/from16 v12, p1

    .line 143
    .line 144
    :cond_5
    move-object/from16 v16, v8

    .line 145
    .line 146
    goto/16 :goto_2

    .line 147
    .line 148
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    iget-object v3, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 152
    .line 153
    move-object v11, v3

    .line 154
    check-cast v11, Lyy0/j;

    .line 155
    .line 156
    iget-object v3, v0, Lk70/c;->h:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v3, Lne0/s;

    .line 159
    .line 160
    instance-of v8, v3, Lne0/e;

    .line 161
    .line 162
    if-eqz v8, :cond_b

    .line 163
    .line 164
    check-cast v3, Lne0/e;

    .line 165
    .line 166
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 167
    .line 168
    move-object v10, v3

    .line 169
    check-cast v10, Lss0/k;

    .line 170
    .line 171
    iget-object v3, v1, Lk70/d;->b:Lk70/x;

    .line 172
    .line 173
    check-cast v3, Li70/c;

    .line 174
    .line 175
    iget-object v3, v3, Li70/c;->d:Lyy0/l1;

    .line 176
    .line 177
    iget-object v3, v3, Lyy0/l1;->d:Lyy0/a2;

    .line 178
    .line 179
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    move-object v9, v3

    .line 184
    check-cast v9, Ll70/k;

    .line 185
    .line 186
    iget-object v3, v10, Lss0/k;->a:Ljava/lang/String;

    .line 187
    .line 188
    iget-object v8, v9, Ll70/k;->a:Ll70/b;

    .line 189
    .line 190
    if-eqz v8, :cond_7

    .line 191
    .line 192
    iget-object v12, v8, Ll70/b;->a:Ljava/time/LocalDate;

    .line 193
    .line 194
    const-string v13, "ddMMyyyy"

    .line 195
    .line 196
    invoke-static {v13}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 197
    .line 198
    .line 199
    move-result-object v14

    .line 200
    invoke-virtual {v12, v14}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v12

    .line 204
    iget-object v8, v8, Ll70/b;->b:Ljava/time/LocalDate;

    .line 205
    .line 206
    invoke-static {v13}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 207
    .line 208
    .line 209
    move-result-object v13

    .line 210
    invoke-virtual {v8, v13}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v8

    .line 214
    const/4 v13, 0x3

    .line 215
    filled-new-array {v12, v8, v3}, [Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    invoke-static {v3, v13}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    const-string v8, "tripStatistics_from_%s_to_%s_%s.csv"

    .line 224
    .line 225
    invoke-static {v8, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    :goto_0
    move-object v8, v3

    .line 230
    goto :goto_1

    .line 231
    :cond_7
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v3

    .line 235
    invoke-static {v3, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    const-string v8, "tripStatistics_%s.csv"

    .line 240
    .line 241
    invoke-static {v8, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    goto :goto_0

    .line 246
    :goto_1
    iget-object v3, v1, Lk70/d;->a:Li70/t;

    .line 247
    .line 248
    iget-object v12, v1, Lk70/d;->d:Lam0/c;

    .line 249
    .line 250
    iput-object v7, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 251
    .line 252
    iput-object v7, v0, Lk70/c;->h:Ljava/lang/Object;

    .line 253
    .line 254
    iput-object v11, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 255
    .line 256
    iput-object v10, v0, Lk70/c;->j:Ljava/lang/Object;

    .line 257
    .line 258
    iput-object v9, v0, Lk70/c;->k:Ljava/lang/Object;

    .line 259
    .line 260
    iput-object v8, v0, Lk70/c;->l:Ljava/lang/Object;

    .line 261
    .line 262
    iput-object v3, v0, Lk70/c;->m:Ljava/lang/Object;

    .line 263
    .line 264
    iput v6, v0, Lk70/c;->e:I

    .line 265
    .line 266
    invoke-virtual {v12, v0}, Lam0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v12

    .line 270
    if-ne v12, v2, :cond_5

    .line 271
    .line 272
    goto/16 :goto_7

    .line 273
    .line 274
    :goto_2
    check-cast v12, Lcm0/b;

    .line 275
    .line 276
    iget-object v8, v10, Lss0/k;->a:Ljava/lang/String;

    .line 277
    .line 278
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 279
    .line 280
    .line 281
    const-string v10, "environment"

    .line 282
    .line 283
    invoke-static {v12, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    const-string v10, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 287
    .line 288
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    const-string v10, "filter"

    .line 292
    .line 293
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    iget-object v10, v3, Li70/t;->c:Lxl0/g;

    .line 297
    .line 298
    invoke-interface {v10, v12}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v10

    .line 302
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    invoke-static {v9}, Li70/t;->a(Ll70/k;)Llx0/l;

    .line 307
    .line 308
    .line 309
    move-result-object v9

    .line 310
    invoke-virtual {v12}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v12

    .line 314
    new-instance v13, Llx0/l;

    .line 315
    .line 316
    const-string v14, "timezone"

    .line 317
    .line 318
    invoke-direct {v13, v14, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    const-string v12, "format(...)"

    .line 322
    .line 323
    if-eqz v9, :cond_8

    .line 324
    .line 325
    iget-object v14, v9, Llx0/l;->d:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast v14, Ljava/time/OffsetDateTime;

    .line 328
    .line 329
    if-eqz v14, :cond_8

    .line 330
    .line 331
    sget-object v15, Ljava/time/format/DateTimeFormatter;->ISO_OFFSET_DATE_TIME:Ljava/time/format/DateTimeFormatter;

    .line 332
    .line 333
    invoke-virtual {v14, v15}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v14

    .line 337
    invoke-static {v14, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    new-instance v15, Llx0/l;

    .line 341
    .line 342
    const-string v5, "from"

    .line 343
    .line 344
    invoke-direct {v15, v5, v14}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 345
    .line 346
    .line 347
    goto :goto_3

    .line 348
    :cond_8
    move-object v15, v7

    .line 349
    :goto_3
    if-eqz v9, :cond_9

    .line 350
    .line 351
    iget-object v5, v9, Llx0/l;->e:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast v5, Ljava/time/OffsetDateTime;

    .line 354
    .line 355
    if-eqz v5, :cond_9

    .line 356
    .line 357
    sget-object v9, Ljava/time/format/DateTimeFormatter;->ISO_OFFSET_DATE_TIME:Ljava/time/format/DateTimeFormatter;

    .line 358
    .line 359
    invoke-virtual {v5, v9}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v5

    .line 363
    invoke-static {v5, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    new-instance v9, Llx0/l;

    .line 367
    .line 368
    const-string v12, "to"

    .line 369
    .line 370
    invoke-direct {v9, v12, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 371
    .line 372
    .line 373
    goto :goto_4

    .line 374
    :cond_9
    move-object v9, v7

    .line 375
    :goto_4
    filled-new-array {v13, v15, v9}, [Llx0/l;

    .line 376
    .line 377
    .line 378
    move-result-object v5

    .line 379
    invoke-static {v5}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 380
    .line 381
    .line 382
    move-result-object v5

    .line 383
    iget-object v3, v3, Li70/t;->d:Lxl0/p;

    .line 384
    .line 385
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v8

    .line 389
    invoke-static {v8, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    move-result-object v6

    .line 393
    const-string v8, "api/v1/trip-statistics/%s/single-trips/export"

    .line 394
    .line 395
    invoke-static {v8, v6}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v6

    .line 399
    check-cast v3, Ldm0/a;

    .line 400
    .line 401
    invoke-virtual {v3, v10, v6, v5}, Ldm0/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v15

    .line 405
    sget-object v14, Llg0/b;->d:Llg0/b;

    .line 406
    .line 407
    iget-object v3, v1, Lk70/d;->e:Lkc0/i;

    .line 408
    .line 409
    invoke-virtual {v3}, Lkc0/i;->invoke()Ljava/lang/Object;

    .line 410
    .line 411
    .line 412
    move-result-object v3

    .line 413
    check-cast v3, Ljava/lang/String;

    .line 414
    .line 415
    if-eqz v3, :cond_a

    .line 416
    .line 417
    const-string v5, "Bearer "

    .line 418
    .line 419
    invoke-virtual {v5, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v3

    .line 423
    new-instance v5, Llx0/l;

    .line 424
    .line 425
    const-string v6, "Authorization"

    .line 426
    .line 427
    invoke-direct {v5, v6, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 428
    .line 429
    .line 430
    filled-new-array {v5}, [Llx0/l;

    .line 431
    .line 432
    .line 433
    move-result-object v3

    .line 434
    invoke-static {v3}, Lmx0/x;->j([Llx0/l;)Ljava/util/HashMap;

    .line 435
    .line 436
    .line 437
    move-result-object v3

    .line 438
    move-object/from16 v19, v3

    .line 439
    .line 440
    goto :goto_5

    .line 441
    :cond_a
    move-object/from16 v19, v7

    .line 442
    .line 443
    :goto_5
    new-instance v13, Llg0/c;

    .line 444
    .line 445
    const-string v18, ""

    .line 446
    .line 447
    move-object/from16 v17, v16

    .line 448
    .line 449
    invoke-direct/range {v13 .. v19}, Llg0/c;-><init>(Llg0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/HashMap;)V

    .line 450
    .line 451
    .line 452
    iget-object v1, v1, Lk70/d;->f:Lkg0/a;

    .line 453
    .line 454
    invoke-virtual {v1, v13}, Lkg0/a;->a(Llg0/c;)Lyy0/m1;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    goto :goto_6

    .line 459
    :cond_b
    instance-of v1, v3, Lne0/c;

    .line 460
    .line 461
    if-eqz v1, :cond_c

    .line 462
    .line 463
    new-instance v1, Lyy0/m;

    .line 464
    .line 465
    const/4 v5, 0x0

    .line 466
    invoke-direct {v1, v3, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 467
    .line 468
    .line 469
    goto :goto_6

    .line 470
    :cond_c
    instance-of v1, v3, Lne0/d;

    .line 471
    .line 472
    if-eqz v1, :cond_d

    .line 473
    .line 474
    new-instance v1, Lyy0/m;

    .line 475
    .line 476
    const/4 v3, 0x0

    .line 477
    sget-object v5, Lne0/d;->a:Lne0/d;

    .line 478
    .line 479
    invoke-direct {v1, v5, v3}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 480
    .line 481
    .line 482
    :goto_6
    iput-object v7, v0, Lk70/c;->f:Ljava/lang/Object;

    .line 483
    .line 484
    iput-object v7, v0, Lk70/c;->h:Ljava/lang/Object;

    .line 485
    .line 486
    iput-object v7, v0, Lk70/c;->g:Ljava/lang/Object;

    .line 487
    .line 488
    iput-object v7, v0, Lk70/c;->j:Ljava/lang/Object;

    .line 489
    .line 490
    iput-object v7, v0, Lk70/c;->k:Ljava/lang/Object;

    .line 491
    .line 492
    iput-object v7, v0, Lk70/c;->l:Ljava/lang/Object;

    .line 493
    .line 494
    iput-object v7, v0, Lk70/c;->m:Ljava/lang/Object;

    .line 495
    .line 496
    const/4 v3, 0x2

    .line 497
    iput v3, v0, Lk70/c;->e:I

    .line 498
    .line 499
    invoke-static {v11, v1, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    if-ne v0, v2, :cond_2

    .line 504
    .line 505
    :goto_7
    return-object v2

    .line 506
    :cond_d
    new-instance v0, La8/r0;

    .line 507
    .line 508
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 509
    .line 510
    .line 511
    throw v0

    .line 512
    nop

    .line 513
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
