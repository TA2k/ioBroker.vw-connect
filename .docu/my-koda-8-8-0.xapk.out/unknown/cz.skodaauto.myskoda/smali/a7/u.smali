.class public final La7/u;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lkotlin/jvm/internal/f0;

.field public final synthetic g:Lkotlin/jvm/internal/f0;

.field public final synthetic h:Lkotlin/jvm/internal/f0;

.field public final synthetic i:Landroid/content/Context;

.field public final synthetic j:Landroid/widget/RemoteViews;

.field public final synthetic k:La7/d1;

.field public final synthetic l:Lkotlin/jvm/internal/f0;

.field public final synthetic m:Lkotlin/jvm/internal/f0;

.field public final synthetic n:Lkotlin/jvm/internal/f0;

.field public final synthetic o:Lkotlin/jvm/internal/f0;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Landroid/content/Context;Landroid/widget/RemoteViews;La7/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;La7/e2;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V
    .locals 0

    .line 1
    iput-object p1, p0, La7/u;->f:Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    iput-object p2, p0, La7/u;->g:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    iput-object p3, p0, La7/u;->h:Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    iput-object p4, p0, La7/u;->i:Landroid/content/Context;

    .line 8
    .line 9
    iput-object p5, p0, La7/u;->j:Landroid/widget/RemoteViews;

    .line 10
    .line 11
    iput-object p6, p0, La7/u;->k:La7/d1;

    .line 12
    .line 13
    iput-object p7, p0, La7/u;->l:Lkotlin/jvm/internal/f0;

    .line 14
    .line 15
    iput-object p9, p0, La7/u;->m:Lkotlin/jvm/internal/f0;

    .line 16
    .line 17
    iput-object p12, p0, La7/u;->n:Lkotlin/jvm/internal/f0;

    .line 18
    .line 19
    iput-object p13, p0, La7/u;->o:Lkotlin/jvm/internal/f0;

    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    check-cast p2, Ly6/p;

    .line 4
    .line 5
    instance-of p1, p2, Lz6/b;

    .line 6
    .line 7
    const-string v0, "GlanceAppWidget"

    .line 8
    .line 9
    if-eqz p1, :cond_1

    .line 10
    .line 11
    iget-object p0, p0, La7/u;->f:Lkotlin/jvm/internal/f0;

    .line 12
    .line 13
    iget-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const-string p1, "More than one clickable defined on the same GlanceModifier, only the last one will be used."

    .line 18
    .line 19
    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    :cond_0
    iput-object p2, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 23
    .line 24
    goto/16 :goto_1

    .line 25
    .line 26
    :cond_1
    instance-of p1, p2, Lf7/t;

    .line 27
    .line 28
    if-eqz p1, :cond_2

    .line 29
    .line 30
    iget-object p0, p0, La7/u;->g:Lkotlin/jvm/internal/f0;

    .line 31
    .line 32
    iput-object p2, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 33
    .line 34
    goto/16 :goto_1

    .line 35
    .line 36
    :cond_2
    instance-of p1, p2, Lf7/n;

    .line 37
    .line 38
    if-eqz p1, :cond_3

    .line 39
    .line 40
    iget-object p0, p0, La7/u;->h:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    iput-object p2, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 43
    .line 44
    goto/16 :goto_1

    .line 45
    .line 46
    :cond_3
    instance-of p1, p2, Ly6/e;

    .line 47
    .line 48
    if-eqz p1, :cond_a

    .line 49
    .line 50
    check-cast p2, Ly6/e;

    .line 51
    .line 52
    iget-object p1, p0, La7/u;->k:La7/d1;

    .line 53
    .line 54
    iget p1, p1, La7/d1;->a:I

    .line 55
    .line 56
    instance-of v1, p2, Ly6/d;

    .line 57
    .line 58
    iget-object v2, p0, La7/u;->j:Landroid/widget/RemoteViews;

    .line 59
    .line 60
    const-string v3, "setBackgroundResource"

    .line 61
    .line 62
    if-eqz v1, :cond_4

    .line 63
    .line 64
    check-cast p2, Ly6/d;

    .line 65
    .line 66
    iget-object p0, p2, Ly6/d;->a:Ly6/a;

    .line 67
    .line 68
    iget p0, p0, Ly6/a;->a:I

    .line 69
    .line 70
    invoke-virtual {v2, p1, v3, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_1

    .line 74
    .line 75
    :cond_4
    instance-of v1, p2, Ly6/c;

    .line 76
    .line 77
    if-eqz v1, :cond_10

    .line 78
    .line 79
    check-cast p2, Ly6/c;

    .line 80
    .line 81
    iget-object p2, p2, Ly6/c;->a:Lk7/a;

    .line 82
    .line 83
    instance-of v1, p2, Lk7/h;

    .line 84
    .line 85
    const-string v4, "setBackgroundColor"

    .line 86
    .line 87
    if-eqz v1, :cond_5

    .line 88
    .line 89
    const-wide/16 v0, 0x0

    .line 90
    .line 91
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    invoke-virtual {v2, p1, v4, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 96
    .line 97
    .line 98
    goto/16 :goto_1

    .line 99
    .line 100
    :cond_5
    instance-of v1, p2, Lk7/i;

    .line 101
    .line 102
    const/16 v5, 0x1f

    .line 103
    .line 104
    if-eqz v1, :cond_7

    .line 105
    .line 106
    check-cast p2, Lk7/i;

    .line 107
    .line 108
    iget p0, p2, Lk7/i;->a:I

    .line 109
    .line 110
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 111
    .line 112
    if-lt p2, v5, :cond_6

    .line 113
    .line 114
    invoke-static {v2, p1, v4, p0}, Lh6/h;->d(Landroid/widget/RemoteViews;ILjava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    goto/16 :goto_1

    .line 118
    .line 119
    :cond_6
    invoke-virtual {v2, p1, v3, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 120
    .line 121
    .line 122
    goto/16 :goto_1

    .line 123
    .line 124
    :cond_7
    instance-of v1, p2, Le7/a;

    .line 125
    .line 126
    if-eqz v1, :cond_9

    .line 127
    .line 128
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 129
    .line 130
    if-lt v0, v5, :cond_8

    .line 131
    .line 132
    check-cast p2, Le7/a;

    .line 133
    .line 134
    iget-wide v0, p2, Le7/a;->a:J

    .line 135
    .line 136
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    iget-wide v0, p2, Le7/a;->b:J

    .line 141
    .line 142
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 143
    .line 144
    .line 145
    move-result p2

    .line 146
    invoke-static {v2, p1, v4, p0, p2}, Lh6/h;->f(Landroid/widget/RemoteViews;ILjava/lang/String;II)V

    .line 147
    .line 148
    .line 149
    goto/16 :goto_1

    .line 150
    .line 151
    :cond_8
    check-cast p2, Le7/a;

    .line 152
    .line 153
    iget-object p0, p0, La7/u;->i:Landroid/content/Context;

    .line 154
    .line 155
    invoke-virtual {p2, p0}, Le7/a;->a(Landroid/content/Context;)J

    .line 156
    .line 157
    .line 158
    move-result-wide v0

    .line 159
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    invoke-virtual {v2, p1, v4, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 164
    .line 165
    .line 166
    goto/16 :goto_1

    .line 167
    .line 168
    :cond_9
    new-instance p0, Ljava/lang/StringBuilder;

    .line 169
    .line 170
    const-string p1, "Unexpected background color modifier: "

    .line 171
    .line 172
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 183
    .line 184
    .line 185
    goto/16 :goto_1

    .line 186
    .line 187
    :cond_a
    instance-of p1, p2, Lf7/p;

    .line 188
    .line 189
    if-eqz p1, :cond_c

    .line 190
    .line 191
    iget-object p0, p0, La7/u;->l:Lkotlin/jvm/internal/f0;

    .line 192
    .line 193
    iget-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast p1, Lf7/p;

    .line 196
    .line 197
    if-eqz p1, :cond_b

    .line 198
    .line 199
    check-cast p2, Lf7/p;

    .line 200
    .line 201
    new-instance v0, Lf7/p;

    .line 202
    .line 203
    iget-object v1, p1, Lf7/p;->a:Lf7/o;

    .line 204
    .line 205
    iget-object v2, p2, Lf7/p;->a:Lf7/o;

    .line 206
    .line 207
    invoke-virtual {v1, v2}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    iget-object v2, p1, Lf7/p;->b:Lf7/o;

    .line 212
    .line 213
    iget-object v3, p2, Lf7/p;->b:Lf7/o;

    .line 214
    .line 215
    invoke-virtual {v2, v3}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    iget-object v3, p1, Lf7/p;->c:Lf7/o;

    .line 220
    .line 221
    iget-object v4, p2, Lf7/p;->c:Lf7/o;

    .line 222
    .line 223
    invoke-virtual {v3, v4}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    iget-object v4, p1, Lf7/p;->d:Lf7/o;

    .line 228
    .line 229
    iget-object v5, p2, Lf7/p;->d:Lf7/o;

    .line 230
    .line 231
    invoke-virtual {v4, v5}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 232
    .line 233
    .line 234
    move-result-object v4

    .line 235
    iget-object v5, p1, Lf7/p;->e:Lf7/o;

    .line 236
    .line 237
    iget-object v6, p2, Lf7/p;->e:Lf7/o;

    .line 238
    .line 239
    invoke-virtual {v5, v6}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 240
    .line 241
    .line 242
    move-result-object v5

    .line 243
    iget-object p1, p1, Lf7/p;->f:Lf7/o;

    .line 244
    .line 245
    iget-object p2, p2, Lf7/p;->f:Lf7/o;

    .line 246
    .line 247
    invoke-virtual {p1, p2}, Lf7/o;->a(Lf7/o;)Lf7/o;

    .line 248
    .line 249
    .line 250
    move-result-object v6

    .line 251
    invoke-direct/range {v0 .. v6}, Lf7/p;-><init>(Lf7/o;Lf7/o;Lf7/o;Lf7/o;Lf7/o;Lf7/o;)V

    .line 252
    .line 253
    .line 254
    goto :goto_0

    .line 255
    :cond_b
    move-object v0, p2

    .line 256
    check-cast v0, Lf7/p;

    .line 257
    .line 258
    :goto_0
    iput-object v0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 259
    .line 260
    goto :goto_1

    .line 261
    :cond_c
    instance-of p1, p2, La7/b0;

    .line 262
    .line 263
    if-eqz p1, :cond_d

    .line 264
    .line 265
    check-cast p2, La7/b0;

    .line 266
    .line 267
    iget-object p1, p2, La7/b0;->a:Lk7/c;

    .line 268
    .line 269
    iget-object p0, p0, La7/u;->m:Lkotlin/jvm/internal/f0;

    .line 270
    .line 271
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 272
    .line 273
    goto :goto_1

    .line 274
    :cond_d
    instance-of p1, p2, La7/a;

    .line 275
    .line 276
    if-nez p1, :cond_10

    .line 277
    .line 278
    instance-of p1, p2, La7/e0;

    .line 279
    .line 280
    if-eqz p1, :cond_e

    .line 281
    .line 282
    iget-object p0, p0, La7/u;->n:Lkotlin/jvm/internal/f0;

    .line 283
    .line 284
    iput-object p2, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 285
    .line 286
    goto :goto_1

    .line 287
    :cond_e
    instance-of p1, p2, Lg7/a;

    .line 288
    .line 289
    if-eqz p1, :cond_f

    .line 290
    .line 291
    iget-object p0, p0, La7/u;->o:Lkotlin/jvm/internal/f0;

    .line 292
    .line 293
    iput-object p2, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 294
    .line 295
    goto :goto_1

    .line 296
    :cond_f
    new-instance p0, Ljava/lang/StringBuilder;

    .line 297
    .line 298
    const-string p1, "Unknown modifier \'"

    .line 299
    .line 300
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    const-string p1, "\', nothing done."

    .line 307
    .line 308
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object p0

    .line 315
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 316
    .line 317
    .line 318
    :cond_10
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 319
    .line 320
    return-object p0
.end method
