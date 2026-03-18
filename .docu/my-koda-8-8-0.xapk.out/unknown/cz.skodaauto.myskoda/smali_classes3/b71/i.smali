.class public final synthetic Lb71/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb71/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb71/i;->e:Lay0/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lb71/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 7
    .line 8
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_0
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 15
    .line 16
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 23
    .line 24
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_2
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 31
    .line 32
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/lang/Number;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    const/4 v0, 0x0

    .line 43
    cmpg-float v1, p0, v0

    .line 44
    .line 45
    if-gez v1, :cond_0

    .line 46
    .line 47
    move p0, v0

    .line 48
    :cond_0
    const/high16 v0, 0x3f800000    # 1.0f

    .line 49
    .line 50
    cmpl-float v1, p0, v0

    .line 51
    .line 52
    if-lez v1, :cond_1

    .line 53
    .line 54
    move p0, v0

    .line 55
    :cond_1
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_3
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 61
    .line 62
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ljava/lang/Number;

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    const/4 v0, 0x0

    .line 73
    cmpg-float v1, p0, v0

    .line 74
    .line 75
    if-gez v1, :cond_2

    .line 76
    .line 77
    move p0, v0

    .line 78
    :cond_2
    const/high16 v0, 0x3f800000    # 1.0f

    .line 79
    .line 80
    cmpl-float v1, p0, v0

    .line 81
    .line 82
    if-lez v1, :cond_3

    .line 83
    .line 84
    move p0, v0

    .line 85
    :cond_3
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_4
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 91
    .line 92
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_5
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 99
    .line 100
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_6
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 107
    .line 108
    if-eqz p0, :cond_4

    .line 109
    .line 110
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_7
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 117
    .line 118
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object p0

    .line 124
    :pswitch_8
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 125
    .line 126
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_9
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 133
    .line 134
    if-eqz p0, :cond_5

    .line 135
    .line 136
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_a
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 143
    .line 144
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object p0

    .line 150
    :pswitch_b
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 151
    .line 152
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_c
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 159
    .line 160
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    :pswitch_d
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 167
    .line 168
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 172
    .line 173
    return-object p0

    .line 174
    :pswitch_e
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 175
    .line 176
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    return-object p0

    .line 182
    :pswitch_f
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 183
    .line 184
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    return-object p0

    .line 190
    :pswitch_10
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 191
    .line 192
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object p0

    .line 198
    :pswitch_11
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 199
    .line 200
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_12
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 207
    .line 208
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 212
    .line 213
    return-object p0

    .line 214
    :pswitch_13
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 215
    .line 216
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    return-object p0

    .line 222
    :pswitch_14
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 223
    .line 224
    :try_start_0
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    check-cast p0, Ljava/util/List;
    :try_end_0
    .catch Ljavax/net/ssl/SSLPeerUnverifiedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 229
    .line 230
    goto :goto_0

    .line 231
    :catch_0
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 232
    .line 233
    :goto_0
    return-object p0

    .line 234
    :pswitch_15
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 235
    .line 236
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    return-object p0

    .line 242
    :pswitch_16
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 243
    .line 244
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_17
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 251
    .line 252
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 256
    .line 257
    return-object p0

    .line 258
    :pswitch_18
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 259
    .line 260
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 264
    .line 265
    return-object p0

    .line 266
    :pswitch_19
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 267
    .line 268
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object p0

    .line 274
    :pswitch_1a
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 275
    .line 276
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 280
    .line 281
    return-object p0

    .line 282
    :pswitch_1b
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 283
    .line 284
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    return-object p0

    .line 290
    :pswitch_1c
    iget-object p0, p0, Lb71/i;->e:Lay0/a;

    .line 291
    .line 292
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object p0

    .line 298
    nop

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
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
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
