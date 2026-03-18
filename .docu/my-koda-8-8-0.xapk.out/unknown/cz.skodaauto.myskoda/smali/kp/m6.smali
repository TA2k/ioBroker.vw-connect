.class public abstract Lkp/m6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lqr0/m;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {v0, v1}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "getDefault(...)"

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    sget-object v1, Landroid/icu/text/MeasureFormat$FormatWidth;->NARROW:Landroid/icu/text/MeasureFormat$FormatWidth;

    .line 27
    .line 28
    invoke-static {v0, v1}, Landroid/icu/text/MeasureFormat;->getInstance(Ljava/util/Locale;Landroid/icu/text/MeasureFormat$FormatWidth;)Landroid/icu/text/MeasureFormat;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const-string v1, "getInstance(...)"

    .line 33
    .line 34
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    sget-object v1, Lqr0/f;->d:Lqr0/f;

    .line 38
    .line 39
    if-ne p0, v1, :cond_1

    .line 40
    .line 41
    sget-object p0, Landroid/icu/util/MeasureUnit;->FOOT:Landroid/icu/util/MeasureUnit;

    .line 42
    .line 43
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_1
    sget-object v1, Lqr0/f;->e:Lqr0/f;

    .line 50
    .line 51
    if-ne p0, v1, :cond_2

    .line 52
    .line 53
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOMETER:Landroid/icu/util/MeasureUnit;

    .line 54
    .line 55
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :cond_2
    sget-object v1, Lqr0/f;->f:Lqr0/f;

    .line 62
    .line 63
    if-ne p0, v1, :cond_3

    .line 64
    .line 65
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOMETER_PER_HOUR:Landroid/icu/util/MeasureUnit;

    .line 66
    .line 67
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    goto/16 :goto_0

    .line 72
    .line 73
    :cond_3
    sget-object v1, Lqr0/f;->g:Lqr0/f;

    .line 74
    .line 75
    if-ne p0, v1, :cond_4

    .line 76
    .line 77
    sget-object p0, Landroid/icu/util/MeasureUnit;->METER:Landroid/icu/util/MeasureUnit;

    .line 78
    .line 79
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    goto/16 :goto_0

    .line 84
    .line 85
    :cond_4
    sget-object v1, Lqr0/f;->h:Lqr0/f;

    .line 86
    .line 87
    if-ne p0, v1, :cond_5

    .line 88
    .line 89
    sget-object p0, Landroid/icu/util/MeasureUnit;->MILE:Landroid/icu/util/MeasureUnit;

    .line 90
    .line 91
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    goto/16 :goto_0

    .line 96
    .line 97
    :cond_5
    sget-object v1, Lqr0/f;->i:Lqr0/f;

    .line 98
    .line 99
    if-ne p0, v1, :cond_6

    .line 100
    .line 101
    sget-object p0, Landroid/icu/util/MeasureUnit;->MILE_PER_GALLON:Landroid/icu/util/MeasureUnit;

    .line 102
    .line 103
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    const-string v0, "mpg"

    .line 108
    .line 109
    const/4 v1, 0x1

    .line 110
    const-string v2, "mpgUS"

    .line 111
    .line 112
    invoke-static {v1, p0, v2, v0}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    goto/16 :goto_0

    .line 117
    .line 118
    :cond_6
    sget-object v1, Lqr0/f;->j:Lqr0/f;

    .line 119
    .line 120
    if-ne p0, v1, :cond_7

    .line 121
    .line 122
    sget-object p0, Landroid/icu/util/MeasureUnit;->MILE_PER_HOUR:Landroid/icu/util/MeasureUnit;

    .line 123
    .line 124
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    goto/16 :goto_0

    .line 129
    .line 130
    :cond_7
    sget-object v1, Lqr0/f;->k:Lqr0/f;

    .line 131
    .line 132
    if-ne p0, v1, :cond_8

    .line 133
    .line 134
    sget-object p0, Landroid/icu/util/MeasureUnit;->MILE:Landroid/icu/util/MeasureUnit;

    .line 135
    .line 136
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    sget-object v1, Landroid/icu/util/MeasureUnit;->KILOWATT_HOUR:Landroid/icu/util/MeasureUnit;

    .line 141
    .line 142
    invoke-static {v0, v1}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    const-string v1, "/"

    .line 147
    .line 148
    invoke-static {p0, v1, v0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    goto/16 :goto_0

    .line 153
    .line 154
    :cond_8
    sget-object v1, Lqr0/c;->e:Lqr0/c;

    .line 155
    .line 156
    if-ne p0, v1, :cond_9

    .line 157
    .line 158
    sget-object p0, Landroid/icu/util/MeasureUnit;->MILLIMETER:Landroid/icu/util/MeasureUnit;

    .line 159
    .line 160
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :cond_9
    sget-object v1, Lqr0/c;->d:Lqr0/c;

    .line 167
    .line 168
    if-ne p0, v1, :cond_a

    .line 169
    .line 170
    sget-object p0, Landroid/icu/util/MeasureUnit;->INCH:Landroid/icu/util/MeasureUnit;

    .line 171
    .line 172
    invoke-virtual {v0, p0}, Landroid/icu/text/MeasureFormat;->getUnitDisplayName(Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    goto/16 :goto_0

    .line 177
    .line 178
    :cond_a
    sget-object v1, Lqr0/k;->d:Lqr0/k;

    .line 179
    .line 180
    if-ne p0, v1, :cond_b

    .line 181
    .line 182
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOGRAM:Landroid/icu/util/MeasureUnit;

    .line 183
    .line 184
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    goto/16 :goto_0

    .line 189
    .line 190
    :cond_b
    sget-object v1, Lqr0/k;->e:Lqr0/k;

    .line 191
    .line 192
    const-string v2, "/100 "

    .line 193
    .line 194
    if-ne p0, v1, :cond_c

    .line 195
    .line 196
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOGRAM:Landroid/icu/util/MeasureUnit;

    .line 197
    .line 198
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    sget-object v1, Landroid/icu/util/MeasureUnit;->KILOMETER:Landroid/icu/util/MeasureUnit;

    .line 203
    .line 204
    invoke-static {v0, v1}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-static {p0, v2, v0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    goto/16 :goto_0

    .line 213
    .line 214
    :cond_c
    sget-object v1, Lqr0/o;->d:Lqr0/o;

    .line 215
    .line 216
    if-ne p0, v1, :cond_d

    .line 217
    .line 218
    sget-object p0, Landroid/icu/util/MeasureUnit;->HORSEPOWER:Landroid/icu/util/MeasureUnit;

    .line 219
    .line 220
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    goto/16 :goto_0

    .line 225
    .line 226
    :cond_d
    sget-object v1, Lqr0/o;->e:Lqr0/o;

    .line 227
    .line 228
    if-ne p0, v1, :cond_e

    .line 229
    .line 230
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOWATT:Landroid/icu/util/MeasureUnit;

    .line 231
    .line 232
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    goto :goto_0

    .line 237
    :cond_e
    sget-object v1, Lqr0/o;->f:Lqr0/o;

    .line 238
    .line 239
    if-ne p0, v1, :cond_f

    .line 240
    .line 241
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOWATT_HOUR:Landroid/icu/util/MeasureUnit;

    .line 242
    .line 243
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    goto :goto_0

    .line 248
    :cond_f
    sget-object v1, Lqr0/o;->g:Lqr0/o;

    .line 249
    .line 250
    if-ne p0, v1, :cond_10

    .line 251
    .line 252
    sget-object p0, Landroid/icu/util/MeasureUnit;->KILOWATT_HOUR:Landroid/icu/util/MeasureUnit;

    .line 253
    .line 254
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    sget-object v1, Landroid/icu/util/MeasureUnit;->KILOMETER:Landroid/icu/util/MeasureUnit;

    .line 259
    .line 260
    invoke-static {v0, v1}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-static {p0, v2, v0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    goto :goto_0

    .line 269
    :cond_10
    sget-object v1, Lqr0/r;->d:Lqr0/r;

    .line 270
    .line 271
    if-ne p0, v1, :cond_11

    .line 272
    .line 273
    sget-object p0, Landroid/icu/util/MeasureUnit;->CELSIUS:Landroid/icu/util/MeasureUnit;

    .line 274
    .line 275
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    goto :goto_0

    .line 280
    :cond_11
    sget-object v1, Lqr0/r;->e:Lqr0/r;

    .line 281
    .line 282
    if-ne p0, v1, :cond_12

    .line 283
    .line 284
    sget-object p0, Landroid/icu/util/MeasureUnit;->FAHRENHEIT:Landroid/icu/util/MeasureUnit;

    .line 285
    .line 286
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    goto :goto_0

    .line 291
    :cond_12
    sget-object v1, Lqr0/t;->d:Lqr0/t;

    .line 292
    .line 293
    if-ne p0, v1, :cond_13

    .line 294
    .line 295
    sget-object p0, Landroid/icu/util/MeasureUnit;->GALLON:Landroid/icu/util/MeasureUnit;

    .line 296
    .line 297
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object p0

    .line 301
    goto :goto_0

    .line 302
    :cond_13
    sget-object v1, Lqr0/t;->e:Lqr0/t;

    .line 303
    .line 304
    if-ne p0, v1, :cond_14

    .line 305
    .line 306
    sget-object p0, Landroid/icu/util/MeasureUnit;->LITER:Landroid/icu/util/MeasureUnit;

    .line 307
    .line 308
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    goto :goto_0

    .line 313
    :cond_14
    sget-object v1, Lqr0/t;->f:Lqr0/t;

    .line 314
    .line 315
    if-ne p0, v1, :cond_15

    .line 316
    .line 317
    sget-object p0, Landroid/icu/util/MeasureUnit;->LITER:Landroid/icu/util/MeasureUnit;

    .line 318
    .line 319
    invoke-static {v0, p0}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object p0

    .line 323
    sget-object v1, Landroid/icu/util/MeasureUnit;->KILOMETER:Landroid/icu/util/MeasureUnit;

    .line 324
    .line 325
    invoke-static {v0, v1}, Lkp/m6;->b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    invoke-static {p0, v2, v0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    :goto_0
    const-string v0, "let(...)"

    .line 334
    .line 335
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    return-object p0

    .line 339
    :cond_15
    new-instance p0, La8/r0;

    .line 340
    .line 341
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 342
    .line 343
    .line 344
    throw p0
.end method

.method public static final b(Landroid/icu/text/MeasureFormat;Landroid/icu/util/MeasureUnit;)Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Landroid/icu/util/Measure;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {v0, v1, p1}, Landroid/icu/util/Measure;-><init>(Ljava/lang/Number;Landroid/icu/util/MeasureUnit;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0}, Landroid/icu/text/MeasureFormat;->getNumberFormat()Landroid/icu/text/NumberFormat;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v2, v1}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    const-string v3, ""

    .line 32
    .line 33
    invoke-static {v2, v0, v1, v3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-static {v1}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-nez v0, :cond_0

    .line 50
    .line 51
    return-object v1

    .line 52
    :cond_0
    const-string v0, "^[\\d\\s,.-]*"

    .line 53
    .line 54
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    const-string v2, "compile(...)"

    .line 59
    .line 60
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string v2, "input"

    .line 64
    .line 65
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-virtual {v0, v3}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    const-string v1, "replaceAll(...)"

    .line 77
    .line 78
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    new-instance v2, Ljava/lang/StringBuilder;

    .line 84
    .line 85
    const-string v3, "Cannot resolve raw unit name for "

    .line 86
    .line 87
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string p1, ", fallback to "

    .line 94
    .line 95
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {v1, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-static {p0, v1}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 109
    .line 110
    .line 111
    return-object v0
.end method

.method public static c(Lfn/b;Lum/a;)Lbn/a;
    .locals 4

    .line 1
    new-instance v0, Lbn/a;

    .line 2
    .line 3
    sget-object v1, Len/f;->e:Len/f;

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-static {p0, p1, v2, v1, v3}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-direct {v0, p0, p1}, Lbn/a;-><init>(Ljava/util/List;I)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static d(Lfn/a;Lum/a;Z)Lbn/b;
    .locals 3

    .line 1
    new-instance v0, Lbn/b;

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lgn/h;->c()F

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/high16 p2, 0x3f800000    # 1.0f

    .line 11
    .line 12
    :goto_0
    sget-object v1, Len/f;->f:Len/f;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-static {p0, p1, p2, v1, v2}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-direct {v0, p0, p1}, Lap0/o;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public static e(Lfn/b;Lum/a;I)Lbn/a;
    .locals 10

    .line 1
    new-instance v0, Lbn/a;

    .line 2
    .line 3
    new-instance v1, Lc1/l2;

    .line 4
    .line 5
    invoke-direct {v1}, Lc1/l2;-><init>()V

    .line 6
    .line 7
    .line 8
    iput p2, v1, Lc1/l2;->e:I

    .line 9
    .line 10
    const/high16 p2, 0x3f800000    # 1.0f

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-static {p0, p1, p2, v1, v2}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    move p1, v2

    .line 18
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    if-ge p1, p2, :cond_4

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    check-cast p2, Lhn/a;

    .line 29
    .line 30
    iget-object v1, p2, Lhn/a;->b:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Lcn/c;

    .line 33
    .line 34
    iget-object v3, p2, Lhn/a;->c:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v3, Lcn/c;

    .line 37
    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    if-eqz v3, :cond_3

    .line 41
    .line 42
    iget-object v4, v1, Lcn/c;->a:[F

    .line 43
    .line 44
    array-length v5, v4

    .line 45
    iget-object v6, v3, Lcn/c;->a:[F

    .line 46
    .line 47
    array-length v7, v6

    .line 48
    if-ne v5, v7, :cond_0

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_0
    array-length p2, v4

    .line 52
    array-length v5, v6

    .line 53
    add-int/2addr p2, v5

    .line 54
    new-array v5, p2, [F

    .line 55
    .line 56
    array-length v7, v4

    .line 57
    invoke-static {v4, v2, v5, v2, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 58
    .line 59
    .line 60
    array-length v4, v4

    .line 61
    array-length v7, v6

    .line 62
    invoke-static {v6, v2, v5, v4, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 63
    .line 64
    .line 65
    invoke-static {v5}, Ljava/util/Arrays;->sort([F)V

    .line 66
    .line 67
    .line 68
    const/high16 v4, 0x7fc00000    # Float.NaN

    .line 69
    .line 70
    move v6, v2

    .line 71
    move v7, v6

    .line 72
    :goto_1
    if-ge v6, p2, :cond_2

    .line 73
    .line 74
    aget v8, v5, v6

    .line 75
    .line 76
    cmpl-float v9, v8, v4

    .line 77
    .line 78
    if-eqz v9, :cond_1

    .line 79
    .line 80
    aput v8, v5, v7

    .line 81
    .line 82
    add-int/lit8 v7, v7, 0x1

    .line 83
    .line 84
    aget v4, v5, v6

    .line 85
    .line 86
    :cond_1
    add-int/lit8 v6, v6, 0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_2
    invoke-static {v5, v2, v7}, Ljava/util/Arrays;->copyOfRange([FII)[F

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    invoke-virtual {v1, p2}, Lcn/c;->b([F)Lcn/c;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-virtual {v3, p2}, Lcn/c;->b([F)Lcn/c;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    new-instance v3, Lhn/a;

    .line 102
    .line 103
    invoke-direct {v3, v1, p2}, Lhn/a;-><init>(Lcn/c;Lcn/c;)V

    .line 104
    .line 105
    .line 106
    move-object p2, v3

    .line 107
    :cond_3
    :goto_2
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    add-int/lit8 p1, p1, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_4
    const/4 p1, 0x1

    .line 114
    invoke-direct {v0, p0, p1}, Lbn/a;-><init>(Ljava/util/List;I)V

    .line 115
    .line 116
    .line 117
    return-object v0
.end method

.method public static f(Lfn/a;Lum/a;)Lbn/a;
    .locals 4

    .line 1
    new-instance v0, Lbn/a;

    .line 2
    .line 3
    sget-object v1, Len/f;->g:Len/f;

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-static {p0, p1, v2, v1, v3}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 p1, 0x2

    .line 13
    invoke-direct {v0, p0, p1}, Lbn/a;-><init>(Ljava/util/List;I)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static g(Lfn/b;Lum/a;)Lbn/a;
    .locals 4

    .line 1
    new-instance v0, Lbn/a;

    .line 2
    .line 3
    invoke-static {}, Lgn/h;->c()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    sget-object v2, Len/f;->i:Len/f;

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    invoke-static {p0, p1, v1, v2, v3}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 p1, 0x3

    .line 15
    invoke-direct {v0, p0, p1}, Lbn/a;-><init>(Ljava/util/List;I)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
