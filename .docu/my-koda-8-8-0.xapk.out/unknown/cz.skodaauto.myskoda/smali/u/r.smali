.class public final synthetic Lu/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/y;

.field public final synthetic f:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Lu/y;Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    iput p3, p0, Lu/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/r;->e:Lu/y;

    .line 4
    .line 5
    iput-object p2, p0, Lu/r;->f:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget v0, p0, Lu/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu/r;->e:Lu/y;

    .line 7
    .line 8
    iget-object p0, p0, Lu/r;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    new-instance v1, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/4 v2, 0x0

    .line 20
    move v3, v2

    .line 21
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/4 v5, 0x1

    .line 26
    if-eqz v4, :cond_1

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    check-cast v4, Lu/b;

    .line 33
    .line 34
    iget-object v6, v0, Lu/y;->d:Lb81/c;

    .line 35
    .line 36
    iget-object v7, v4, Lu/b;->a:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v6, v7}, Lb81/c;->s(Ljava/lang/String;)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-eqz v6, :cond_0

    .line 43
    .line 44
    iget-object v6, v0, Lu/y;->d:Lb81/c;

    .line 45
    .line 46
    iget-object v7, v4, Lu/b;->a:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v6, v6, Lb81/c;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v6, Ljava/util/LinkedHashMap;

    .line 51
    .line 52
    invoke-interface {v6, v7}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    iget-object v6, v4, Lu/b;->a:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    iget-object v4, v4, Lu/b;->b:Ljava/lang/Class;

    .line 61
    .line 62
    const-class v6, Lb0/k1;

    .line 63
    .line 64
    if-ne v4, v6, :cond_0

    .line 65
    .line 66
    move v3, v5

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    goto/16 :goto_2

    .line 75
    .line 76
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v4, "Use cases ["

    .line 79
    .line 80
    invoke-direct {p0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const-string v4, ", "

    .line 84
    .line 85
    invoke-static {v4, v1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, "] now DETACHED for camera"

    .line 93
    .line 94
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const/4 v1, 0x0

    .line 102
    invoke-virtual {v0, p0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 103
    .line 104
    .line 105
    if-eqz v3, :cond_3

    .line 106
    .line 107
    iget-object p0, v0, Lu/y;->j:Lu/m;

    .line 108
    .line 109
    iget-object p0, p0, Lu/m;->h:Lu/r0;

    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    :cond_3
    invoke-virtual {v0}, Lu/y;->s()V

    .line 115
    .line 116
    .line 117
    iget-object p0, v0, Lu/y;->d:Lb81/c;

    .line 118
    .line 119
    invoke-virtual {p0}, Lb81/c;->r()Ljava/util/Collection;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-eqz p0, :cond_4

    .line 128
    .line 129
    iget-object p0, v0, Lu/y;->j:Lu/m;

    .line 130
    .line 131
    iget-object v3, p0, Lu/m;->m:Lu/l1;

    .line 132
    .line 133
    iget-boolean v4, v3, Lu/l1;->d:Z

    .line 134
    .line 135
    iput-boolean v2, v3, Lu/l1;->d:Z

    .line 136
    .line 137
    invoke-virtual {p0, v2}, Lu/m;->n(Z)V

    .line 138
    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_4
    invoke-virtual {v0}, Lu/y;->O()V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0}, Lu/y;->N()V

    .line 145
    .line 146
    .line 147
    :goto_1
    iget-object p0, v0, Lu/y;->d:Lb81/c;

    .line 148
    .line 149
    invoke-virtual {p0}, Lb81/c;->p()Ljava/util/Collection;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    if-eqz p0, :cond_8

    .line 158
    .line 159
    iget-object p0, v0, Lu/y;->j:Lu/m;

    .line 160
    .line 161
    invoke-virtual {p0}, Lu/m;->i()V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0}, Lu/y;->F()V

    .line 165
    .line 166
    .line 167
    iget-object p0, v0, Lu/y;->j:Lu/m;

    .line 168
    .line 169
    invoke-virtual {p0, v2}, Lu/m;->m(Z)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v0}, Lu/y;->C()Lu/p0;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    iput-object p0, v0, Lu/y;->o:Lu/p0;

    .line 177
    .line 178
    const-string p0, "Closing camera."

    .line 179
    .line 180
    invoke-virtual {v0, p0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 181
    .line 182
    .line 183
    iget p0, v0, Lu/y;->O:I

    .line 184
    .line 185
    invoke-static {p0}, Lu/w;->o(I)I

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    const/4 v3, 0x6

    .line 190
    packed-switch p0, :pswitch_data_1

    .line 191
    .line 192
    .line 193
    :pswitch_0
    iget p0, v0, Lu/y;->O:I

    .line 194
    .line 195
    invoke-static {p0}, Lu/w;->p(I)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    const-string v2, "close() ignored due to being in state: "

    .line 200
    .line 201
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    invoke-virtual {v0, p0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 206
    .line 207
    .line 208
    goto :goto_2

    .line 209
    :pswitch_1
    invoke-virtual {v0, v3}, Lu/y;->G(I)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v0}, Lu/y;->t()V

    .line 213
    .line 214
    .line 215
    goto :goto_2

    .line 216
    :pswitch_2
    iget-object p0, v0, Lu/y;->k:Lu/x;

    .line 217
    .line 218
    invoke-virtual {p0}, Lu/x;->a()Z

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    if-nez p0, :cond_5

    .line 223
    .line 224
    iget-object p0, v0, Lu/y;->N:Lb81/b;

    .line 225
    .line 226
    iget-object p0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p0, Lrn/i;

    .line 229
    .line 230
    if-eqz p0, :cond_6

    .line 231
    .line 232
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 235
    .line 236
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    if-nez p0, :cond_6

    .line 241
    .line 242
    :cond_5
    move v2, v5

    .line 243
    :cond_6
    iget-object p0, v0, Lu/y;->N:Lb81/b;

    .line 244
    .line 245
    invoke-virtual {p0}, Lb81/b;->j()V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v0, v3}, Lu/y;->G(I)V

    .line 249
    .line 250
    .line 251
    if-eqz v2, :cond_9

    .line 252
    .line 253
    iget-object p0, v0, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 254
    .line 255
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 256
    .line 257
    .line 258
    move-result p0

    .line 259
    invoke-static {v1, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v0}, Lu/y;->u()V

    .line 263
    .line 264
    .line 265
    goto :goto_2

    .line 266
    :pswitch_3
    iget-object p0, v0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 267
    .line 268
    if-nez p0, :cond_7

    .line 269
    .line 270
    move v2, v5

    .line 271
    :cond_7
    invoke-static {v1, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 272
    .line 273
    .line 274
    const/4 p0, 0x3

    .line 275
    invoke-virtual {v0, p0}, Lu/y;->G(I)V

    .line 276
    .line 277
    .line 278
    goto :goto_2

    .line 279
    :cond_8
    invoke-virtual {v0}, Lu/y;->M()V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0}, Lu/y;->F()V

    .line 283
    .line 284
    .line 285
    iget p0, v0, Lu/y;->O:I

    .line 286
    .line 287
    const/16 v1, 0xa

    .line 288
    .line 289
    if-ne p0, v1, :cond_9

    .line 290
    .line 291
    invoke-virtual {v0}, Lu/y;->E()V

    .line 292
    .line 293
    .line 294
    :cond_9
    :goto_2
    return-void

    .line 295
    :pswitch_4
    iget-object v0, p0, Lu/r;->e:Lu/y;

    .line 296
    .line 297
    iget-object p0, p0, Lu/r;->f:Ljava/util/ArrayList;

    .line 298
    .line 299
    iget-object v1, v0, Lu/y;->j:Lu/m;

    .line 300
    .line 301
    :try_start_0
    invoke-virtual {v0, p0}, Lu/y;->J(Ljava/util/ArrayList;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 302
    .line 303
    .line 304
    invoke-virtual {v1}, Lu/m;->i()V

    .line 305
    .line 306
    .line 307
    return-void

    .line 308
    :catchall_0
    move-exception p0

    .line 309
    invoke-virtual {v1}, Lu/m;->i()V

    .line 310
    .line 311
    .line 312
    throw p0

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
    .end packed-switch

    .line 314
    .line 315
    .line 316
    .line 317
    .line 318
    .line 319
    :pswitch_data_1
    .packed-switch 0x3
        :pswitch_3
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
    .end packed-switch
.end method
