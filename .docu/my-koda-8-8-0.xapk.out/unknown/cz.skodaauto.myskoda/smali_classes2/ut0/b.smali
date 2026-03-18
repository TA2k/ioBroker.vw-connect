.class public final Lut0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;


# direct methods
.method public constructor <init>(Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lut0/a;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lut0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lut0/b;->h:Lij0/a;

    .line 11
    .line 12
    new-instance p1, Lrp0/a;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    const/16 v1, 0x1a

    .line 16
    .line 17
    invoke-direct {p1, p0, v0, v1}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final h(Ljava/time/OffsetDateTime;Z)V
    .locals 11

    .line 1
    const-string v0, "timestamp"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p1}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1}, Ljava/time/Instant;->toEpochMilli()J

    .line 15
    .line 16
    .line 17
    move-result-wide v1

    .line 18
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-virtual {v3}, Ljava/time/Instant;->toEpochMilli()J

    .line 23
    .line 24
    .line 25
    move-result-wide v3

    .line 26
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-virtual {p1, v5}, Ljava/time/OffsetDateTime;->atZoneSameInstant(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    invoke-virtual {v5}, Ljava/time/ZonedDateTime;->toLocalDateTime()Ljava/time/LocalDateTime;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    sub-long/2addr v3, v1

    .line 39
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lut0/a;

    .line 44
    .line 45
    sget v2, Lmy0/c;->g:I

    .line 46
    .line 47
    sget-object v2, Lmy0/e;->i:Lmy0/e;

    .line 48
    .line 49
    const/4 v6, 0x1

    .line 50
    invoke-static {v6, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 51
    .line 52
    .line 53
    move-result-wide v7

    .line 54
    invoke-static {v7, v8}, Lmy0/c;->e(J)J

    .line 55
    .line 56
    .line 57
    move-result-wide v7

    .line 58
    cmp-long v7, v3, v7

    .line 59
    .line 60
    iget-object v8, p0, Lut0/b;->h:Lij0/a;

    .line 61
    .line 62
    if-gez v7, :cond_1

    .line 63
    .line 64
    if-eqz p2, :cond_0

    .line 65
    .line 66
    const v0, 0x7f1203bf

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    const v0, 0x7f1203c3

    .line 71
    .line 72
    .line 73
    :goto_0
    const/4 v2, 0x0

    .line 74
    new-array v2, v2, [Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v8, Ljj0/f;

    .line 77
    .line 78
    invoke-virtual {v8, v0, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    goto/16 :goto_4

    .line 83
    .line 84
    :cond_1
    sget-object v7, Lmy0/e;->j:Lmy0/e;

    .line 85
    .line 86
    invoke-static {v6, v7}, Lmy0/h;->s(ILmy0/e;)J

    .line 87
    .line 88
    .line 89
    move-result-wide v9

    .line 90
    invoke-static {v9, v10}, Lmy0/c;->e(J)J

    .line 91
    .line 92
    .line 93
    move-result-wide v9

    .line 94
    cmp-long v7, v3, v9

    .line 95
    .line 96
    if-gez v7, :cond_3

    .line 97
    .line 98
    invoke-static {v6, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 99
    .line 100
    .line 101
    move-result-wide v5

    .line 102
    invoke-static {v5, v6}, Lmy0/c;->e(J)J

    .line 103
    .line 104
    .line 105
    move-result-wide v5

    .line 106
    div-long/2addr v3, v5

    .line 107
    long-to-int v0, v3

    .line 108
    if-eqz p2, :cond_2

    .line 109
    .line 110
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    check-cast v8, Ljj0/f;

    .line 119
    .line 120
    const v3, 0x7f10000a

    .line 121
    .line 122
    .line 123
    invoke-virtual {v8, v3, v0, v2}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    goto/16 :goto_4

    .line 128
    .line 129
    :cond_2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    check-cast v8, Ljj0/f;

    .line 138
    .line 139
    const v3, 0x7f10000b

    .line 140
    .line 141
    .line 142
    invoke-virtual {v8, v3, v0, v2}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    goto/16 :goto_4

    .line 147
    .line 148
    :cond_3
    invoke-static {v0}, Lvo/a;->m(Ljava/time/OffsetDateTime;)Ljava/time/OffsetDateTime;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    invoke-virtual {v2, p1}, Ljava/time/OffsetDateTime;->isAfter(Ljava/time/OffsetDateTime;)Z

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    const-string v3, "format(...)"

    .line 157
    .line 158
    if-nez v2, :cond_5

    .line 159
    .line 160
    if-eqz p2, :cond_4

    .line 161
    .line 162
    const v0, 0x7f1203c1

    .line 163
    .line 164
    .line 165
    goto :goto_1

    .line 166
    :cond_4
    const v0, 0x7f1203c4

    .line 167
    .line 168
    .line 169
    :goto_1
    sget-object v2, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 170
    .line 171
    invoke-static {v2}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    invoke-virtual {v5, v2}, Ljava/time/LocalDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    check-cast v8, Ljj0/f;

    .line 187
    .line 188
    invoke-virtual {v8, v0, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    goto :goto_4

    .line 193
    :cond_5
    invoke-static {v0}, Lvo/a;->m(Ljava/time/OffsetDateTime;)Ljava/time/OffsetDateTime;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    const-wide/16 v6, 0x1

    .line 198
    .line 199
    invoke-virtual {v0, v6, v7}, Ljava/time/OffsetDateTime;->minusDays(J)Ljava/time/OffsetDateTime;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-virtual {v0, p1}, Ljava/time/OffsetDateTime;->isAfter(Ljava/time/OffsetDateTime;)Z

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    if-nez v0, :cond_7

    .line 208
    .line 209
    if-eqz p2, :cond_6

    .line 210
    .line 211
    const v0, 0x7f1203c2

    .line 212
    .line 213
    .line 214
    goto :goto_2

    .line 215
    :cond_6
    const v0, 0x7f1203c5

    .line 216
    .line 217
    .line 218
    :goto_2
    sget-object v2, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 219
    .line 220
    invoke-static {v2}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    invoke-virtual {v5, v2}, Ljava/time/LocalDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    check-cast v8, Ljj0/f;

    .line 236
    .line 237
    invoke-virtual {v8, v0, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    goto :goto_4

    .line 242
    :cond_7
    if-eqz p2, :cond_8

    .line 243
    .line 244
    const v0, 0x7f1203be

    .line 245
    .line 246
    .line 247
    goto :goto_3

    .line 248
    :cond_8
    const v0, 0x7f1203c0

    .line 249
    .line 250
    .line 251
    :goto_3
    invoke-virtual {p1}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    const-string v4, "toLocalDate(...)"

    .line 256
    .line 257
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    invoke-static {v2}, Lu7/b;->e(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    sget-object v4, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 265
    .line 266
    invoke-static {v4}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    invoke-virtual {v5, v4}, Ljava/time/LocalDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    filled-new-array {v2, v4}, [Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    check-cast v8, Ljj0/f;

    .line 282
    .line 283
    invoke-virtual {v8, v0, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    :goto_4
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 288
    .line 289
    .line 290
    new-instance v1, Lut0/a;

    .line 291
    .line 292
    invoke-direct {v1, v0, p1, p2}, Lut0/a;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Z)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {p0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 296
    .line 297
    .line 298
    return-void
.end method
