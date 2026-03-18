.class public final Lcom/google/android/material/datepicker/c0;
.super Landroid/widget/BaseAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:I

.field public static final g:I


# instance fields
.field public final a:Lcom/google/android/material/datepicker/b0;

.field public final b:Lcom/google/android/material/datepicker/i;

.field public c:Ljava/util/Collection;

.field public d:Lcom/google/android/material/datepicker/d;

.field public final e:Lcom/google/android/material/datepicker/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const/4 v2, 0x4

    .line 7
    invoke-virtual {v1, v2}, Ljava/util/Calendar;->getMaximum(I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    sput v1, Lcom/google/android/material/datepicker/c0;->f:I

    .line 12
    .line 13
    invoke-static {v0}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x5

    .line 18
    invoke-virtual {v1, v2}, Ljava/util/Calendar;->getMaximum(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-static {v0}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const/4 v2, 0x7

    .line 27
    invoke-virtual {v0, v2}, Ljava/util/Calendar;->getMaximum(I)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    add-int/2addr v0, v1

    .line 32
    add-int/lit8 v0, v0, -0x1

    .line 33
    .line 34
    sput v0, Lcom/google/android/material/datepicker/c0;->g:I

    .line 35
    .line 36
    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/i;Lcom/google/android/material/datepicker/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/widget/BaseAdapter;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/material/datepicker/c0;->b:Lcom/google/android/material/datepicker/i;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/android/material/datepicker/c0;->e:Lcom/google/android/material/datepicker/c;

    .line 9
    .line 10
    invoke-interface {p2}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lcom/google/android/material/datepicker/c0;->c:Ljava/util/Collection;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/c0;->e:Lcom/google/android/material/datepicker/c;

    .line 2
    .line 3
    iget v0, v0, Lcom/google/android/material/datepicker/c;->h:I

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 6
    .line 7
    iget-object v1, p0, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 8
    .line 9
    const/4 v2, 0x7

    .line 10
    invoke-virtual {v1, v2}, Ljava/util/Calendar;->get(I)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-lez v0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v1}, Ljava/util/Calendar;->getFirstDayOfWeek()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    :goto_0
    sub-int/2addr v2, v0

    .line 22
    if-gez v2, :cond_1

    .line 23
    .line 24
    iget p0, p0, Lcom/google/android/material/datepicker/b0;->g:I

    .line 25
    .line 26
    add-int/2addr v2, p0

    .line 27
    :cond_1
    return v2
.end method

.method public final b(I)Ljava/lang/Long;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lt p1, v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/c0;->c()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-le p1, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    sub-int/2addr p1, v0

    .line 19
    add-int/lit8 p1, p1, 0x1

    .line 20
    .line 21
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 22
    .line 23
    iget-object p0, p0, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 24
    .line 25
    invoke-static {p0}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const/4 v0, 0x5

    .line 30
    invoke-virtual {p0, v0, p1}, Ljava/util/Calendar;->set(II)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 34
    .line 35
    .line 36
    move-result-wide p0

    .line 37
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 43
    return-object p0
.end method

.method public final c()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 6
    .line 7
    iget p0, p0, Lcom/google/android/material/datepicker/b0;->h:I

    .line 8
    .line 9
    add-int/2addr v0, p0

    .line 10
    add-int/lit8 v0, v0, -0x1

    .line 11
    .line 12
    return v0
.end method

.method public final d(Landroid/widget/TextView;J)V
    .locals 9

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v1}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    cmp-long v1, v1, p2

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    const/4 v3, 0x0

    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    move v1, v2

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    move v1, v3

    .line 25
    :goto_0
    iget-object v4, p0, Lcom/google/android/material/datepicker/c0;->b:Lcom/google/android/material/datepicker/i;

    .line 26
    .line 27
    invoke-interface {v4}, Lcom/google/android/material/datepicker/i;->V()Ljava/util/ArrayList;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    :cond_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    if-eqz v6, :cond_3

    .line 40
    .line 41
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    check-cast v6, Lc6/b;

    .line 46
    .line 47
    iget-object v6, v6, Lc6/b;->a:Ljava/lang/Object;

    .line 48
    .line 49
    if-eqz v6, :cond_2

    .line 50
    .line 51
    check-cast v6, Ljava/lang/Long;

    .line 52
    .line 53
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 54
    .line 55
    .line 56
    move-result-wide v6

    .line 57
    cmp-long v6, v6, p2

    .line 58
    .line 59
    if-nez v6, :cond_2

    .line 60
    .line 61
    move v5, v2

    .line 62
    goto :goto_1

    .line 63
    :cond_3
    move v5, v3

    .line 64
    :goto_1
    invoke-interface {v4}, Lcom/google/android/material/datepicker/i;->V()Ljava/util/ArrayList;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    :cond_4
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    if-eqz v7, :cond_5

    .line 77
    .line 78
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    check-cast v7, Lc6/b;

    .line 83
    .line 84
    iget-object v7, v7, Lc6/b;->b:Ljava/lang/Object;

    .line 85
    .line 86
    if-eqz v7, :cond_4

    .line 87
    .line 88
    check-cast v7, Ljava/lang/Long;

    .line 89
    .line 90
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 91
    .line 92
    .line 93
    move-result-wide v7

    .line 94
    cmp-long v7, v7, p2

    .line 95
    .line 96
    if-nez v7, :cond_4

    .line 97
    .line 98
    move v6, v2

    .line 99
    goto :goto_2

    .line 100
    :cond_5
    move v6, v3

    .line 101
    :goto_2
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    const/4 v8, 0x0

    .line 106
    invoke-static {v8}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    invoke-virtual {v8, p2, p3}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v7, v2}, Ljava/util/Calendar;->get(I)I

    .line 114
    .line 115
    .line 116
    move-result v7

    .line 117
    invoke-virtual {v8, v2}, Ljava/util/Calendar;->get(I)I

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-ne v7, v8, :cond_6

    .line 122
    .line 123
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    const-string v8, "MMMMEEEEd"

    .line 128
    .line 129
    invoke-static {v8, v7}, Lcom/google/android/material/datepicker/n0;->b(Ljava/lang/String;Ljava/util/Locale;)Landroid/icu/text/DateFormat;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    new-instance v8, Ljava/util/Date;

    .line 134
    .line 135
    invoke-direct {v8, p2, p3}, Ljava/util/Date;-><init>(J)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v7, v8}, Landroid/icu/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    goto :goto_3

    .line 143
    :cond_6
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    const-string v8, "yMMMMEEEEd"

    .line 148
    .line 149
    invoke-static {v8, v7}, Lcom/google/android/material/datepicker/n0;->b(Ljava/lang/String;Ljava/util/Locale;)Landroid/icu/text/DateFormat;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    new-instance v8, Ljava/util/Date;

    .line 154
    .line 155
    invoke-direct {v8, p2, p3}, Ljava/util/Date;-><init>(J)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v7, v8}, Landroid/icu/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    :goto_3
    if-eqz v1, :cond_7

    .line 163
    .line 164
    const v1, 0x7f1207ed

    .line 165
    .line 166
    .line 167
    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    invoke-static {v1, v7}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    :cond_7
    if-eqz v5, :cond_8

    .line 180
    .line 181
    const v1, 0x7f1207e6

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    invoke-static {v0, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    goto :goto_4

    .line 197
    :cond_8
    if-eqz v6, :cond_9

    .line 198
    .line 199
    const v1, 0x7f1207d8

    .line 200
    .line 201
    .line 202
    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    invoke-static {v0, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v7

    .line 214
    :cond_9
    :goto_4
    invoke-virtual {p1, v7}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 215
    .line 216
    .line 217
    iget-object v0, p0, Lcom/google/android/material/datepicker/c0;->e:Lcom/google/android/material/datepicker/c;

    .line 218
    .line 219
    iget-object v0, v0, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 220
    .line 221
    invoke-interface {v0, p2, p3}, Lcom/google/android/material/datepicker/b;->g(J)Z

    .line 222
    .line 223
    .line 224
    move-result v0

    .line 225
    if-eqz v0, :cond_e

    .line 226
    .line 227
    invoke-virtual {p1, v2}, Landroid/widget/TextView;->setEnabled(Z)V

    .line 228
    .line 229
    .line 230
    invoke-interface {v4}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    :cond_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    if-eqz v1, :cond_b

    .line 243
    .line 244
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    check-cast v1, Ljava/lang/Long;

    .line 249
    .line 250
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 251
    .line 252
    .line 253
    move-result-wide v4

    .line 254
    invoke-static {p2, p3}, Lcom/google/android/material/datepicker/n0;->a(J)J

    .line 255
    .line 256
    .line 257
    move-result-wide v6

    .line 258
    invoke-static {v4, v5}, Lcom/google/android/material/datepicker/n0;->a(J)J

    .line 259
    .line 260
    .line 261
    move-result-wide v4

    .line 262
    cmp-long v1, v6, v4

    .line 263
    .line 264
    if-nez v1, :cond_a

    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_b
    move v2, v3

    .line 268
    :goto_5
    invoke-virtual {p1, v2}, Landroid/widget/TextView;->setSelected(Z)V

    .line 269
    .line 270
    .line 271
    if-eqz v2, :cond_c

    .line 272
    .line 273
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 274
    .line 275
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast p0, Lca/j;

    .line 278
    .line 279
    goto :goto_6

    .line 280
    :cond_c
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    invoke-virtual {v0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 285
    .line 286
    .line 287
    move-result-wide v0

    .line 288
    cmp-long p2, v0, p2

    .line 289
    .line 290
    if-nez p2, :cond_d

    .line 291
    .line 292
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 293
    .line 294
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast p0, Lca/j;

    .line 297
    .line 298
    goto :goto_6

    .line 299
    :cond_d
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 300
    .line 301
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast p0, Lca/j;

    .line 304
    .line 305
    goto :goto_6

    .line 306
    :cond_e
    invoke-virtual {p1, v3}, Landroid/widget/TextView;->setEnabled(Z)V

    .line 307
    .line 308
    .line 309
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 310
    .line 311
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast p0, Lca/j;

    .line 314
    .line 315
    :goto_6
    invoke-virtual {p0, p1}, Lca/j;->p(Landroid/widget/TextView;)V

    .line 316
    .line 317
    .line 318
    return-void
.end method

.method public final e(Lcom/google/android/material/datepicker/MaterialCalendarGridView;J)V
    .locals 2

    .line 1
    invoke-static {p2, p3}, Lcom/google/android/material/datepicker/b0;->c(J)Lcom/google/android/material/datepicker/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Lcom/google/android/material/datepicker/b0;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, v1, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 14
    .line 15
    invoke-static {v0}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, p2, p3}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x5

    .line 23
    invoke-virtual {v0, v1}, Ljava/util/Calendar;->get(I)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    add-int/lit8 v0, v0, -0x1

    .line 32
    .line 33
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-int/2addr v1, v0

    .line 38
    invoke-virtual {p1}, Landroid/widget/AdapterView;->getFirstVisiblePosition()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    sub-int/2addr v1, v0

    .line 43
    invoke-virtual {p1, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroid/widget/TextView;

    .line 48
    .line 49
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/material/datepicker/c0;->d(Landroid/widget/TextView;J)V

    .line 50
    .line 51
    .line 52
    :cond_0
    return-void
.end method

.method public final getCount()I
    .locals 0

    .line 1
    sget p0, Lcom/google/android/material/datepicker/c0;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final bridge synthetic getItem(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/c0;->b(I)Ljava/lang/Long;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getItemId(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/material/datepicker/b0;->g:I

    .line 4
    .line 5
    div-int/2addr p1, p0

    .line 6
    int-to-long p0, p1

    .line 7
    return-wide p0
.end method

.method public final getView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 4

    .line 1
    invoke-virtual {p3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    new-instance v1, Lcom/google/android/material/datepicker/d;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-direct {v1, v0, v2}, Lcom/google/android/material/datepicker/d;-><init>(Landroid/content/Context;I)V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 16
    .line 17
    :cond_0
    move-object v0, p2

    .line 18
    check-cast v0, Landroid/widget/TextView;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    if-nez p2, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-static {p2}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    const v0, 0x7f0d02c4

    .line 32
    .line 33
    .line 34
    invoke-virtual {p2, v0, p3, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    move-object v0, p2

    .line 39
    check-cast v0, Landroid/widget/TextView;

    .line 40
    .line 41
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    sub-int p2, p1, p2

    .line 46
    .line 47
    if-ltz p2, :cond_3

    .line 48
    .line 49
    iget-object p3, p0, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 50
    .line 51
    iget v2, p3, Lcom/google/android/material/datepicker/b0;->h:I

    .line 52
    .line 53
    if-lt p2, v2, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    const/4 v2, 0x1

    .line 57
    add-int/2addr p2, v2

    .line 58
    invoke-virtual {v0, p3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 62
    .line 63
    .line 64
    move-result-object p3

    .line 65
    invoke-virtual {p3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 66
    .line 67
    .line 68
    move-result-object p3

    .line 69
    iget-object p3, p3, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 70
    .line 71
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    const-string v3, "%d"

    .line 80
    .line 81
    invoke-static {p3, v3, p2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    invoke-virtual {v0, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0, v2}, Landroid/widget/TextView;->setEnabled(Z)V

    .line 92
    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_3
    :goto_0
    const/16 p2, 0x8

    .line 96
    .line 97
    invoke-virtual {v0, p2}, Landroid/view/View;->setVisibility(I)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setEnabled(Z)V

    .line 101
    .line 102
    .line 103
    :goto_1
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/c0;->b(I)Ljava/lang/Long;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    if-nez p1, :cond_4

    .line 108
    .line 109
    return-object v0

    .line 110
    :cond_4
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 111
    .line 112
    .line 113
    move-result-wide p1

    .line 114
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/android/material/datepicker/c0;->d(Landroid/widget/TextView;J)V

    .line 115
    .line 116
    .line 117
    return-object v0
.end method

.method public final hasStableIds()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
