.class public final synthetic Lh2/w4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/w4;->d:I

    iput-object p3, p0, Lh2/w4;->f:Ljava/lang/Object;

    iput-object p4, p0, Lh2/w4;->g:Ljava/lang/Object;

    iput p1, p0, Lh2/w4;->e:I

    iput-object p5, p0, Lh2/w4;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lkh/i;ILl2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x5

    iput v0, p0, Lh2/w4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/w4;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/w4;->h:Ljava/lang/Object;

    iput p3, p0, Lh2/w4;->e:I

    iput-object p4, p0, Lh2/w4;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lh2/fc;ILl2/b1;Ll2/g1;)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Lh2/w4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/w4;->f:Ljava/lang/Object;

    iput p2, p0, Lh2/w4;->e:I

    iput-object p3, p0, Lh2/w4;->g:Ljava/lang/Object;

    iput-object p4, p0, Lh2/w4;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V
    .locals 1

    .line 4
    const/4 v0, 0x4

    iput v0, p0, Lh2/w4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/w4;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/w4;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/w4;->h:Ljava/lang/Object;

    iput p4, p0, Lh2/w4;->e:I

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lh2/w4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lay0/k;

    .line 9
    .line 10
    iget-object v1, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lkh/i;

    .line 13
    .line 14
    iget-object v2, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ll2/b1;

    .line 17
    .line 18
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 19
    .line 20
    invoke-interface {v2, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lkh/d;

    .line 24
    .line 25
    iget-object v1, v1, Lkh/i;->i:Ljava/util/List;

    .line 26
    .line 27
    iget p0, p0, Lh2/w4;->e:I

    .line 28
    .line 29
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lac/a0;

    .line 34
    .line 35
    iget-object p0, p0, Lac/a0;->d:Ljava/lang/String;

    .line 36
    .line 37
    invoke-direct {v2, p0}, Lkh/d;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-interface {v0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 49
    .line 50
    iget-object v1, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Ltechnology/cariad/cat/genx/Channel;

    .line 53
    .line 54
    iget-object v2, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 57
    .line 58
    iget p0, p0, Lh2/w4;->e:I

    .line 59
    .line 60
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->K0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Llx0/b0;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_1
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 68
    .line 69
    iget-object v1, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Landroid/bluetooth/BluetoothDevice;

    .line 72
    .line 73
    iget-object v2, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v2, Ljava/util/UUID;

    .line 76
    .line 77
    iget p0, p0, Lh2/w4;->e:I

    .line 78
    .line 79
    invoke-static {v0, v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->r0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;ILjava/util/UUID;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_2
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v0, Llz0/s;

    .line 87
    .line 88
    iget-object v1, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v1, Ljava/lang/CharSequence;

    .line 91
    .line 92
    iget-object v2, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v2, Lkotlin/jvm/internal/d0;

    .line 95
    .line 96
    new-instance v3, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    const-string v4, "Expected "

    .line 99
    .line 100
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object v0, v0, Llz0/s;->b:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v0, " but got "

    .line 109
    .line 110
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    iget v0, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 114
    .line 115
    iget p0, p0, Lh2/w4;->e:I

    .line 116
    .line 117
    invoke-interface {v1, p0, v0}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0

    .line 133
    :pswitch_3
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Ljava/lang/String;

    .line 136
    .line 137
    iget-object v1, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v1, Llz0/g;

    .line 140
    .line 141
    iget-object v2, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v2, Llz0/f;

    .line 144
    .line 145
    const-string v3, "Can not interpret the string \'"

    .line 146
    .line 147
    const-string v4, "\' as "

    .line 148
    .line 149
    invoke-static {v3, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    iget-object v1, v1, Llz0/g;->a:Ljava/util/List;

    .line 154
    .line 155
    iget p0, p0, Lh2/w4;->e:I

    .line 156
    .line 157
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Llz0/d;

    .line 162
    .line 163
    iget-object p0, p0, Llz0/d;->b:Ljava/lang/String;

    .line 164
    .line 165
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    const-string p0, ": "

    .line 169
    .line 170
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    invoke-interface {v2}, Llz0/f;->e()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    return-object p0

    .line 185
    :pswitch_4
    iget-object v0, p0, Lh2/w4;->f:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v0, Lh2/fc;

    .line 188
    .line 189
    iget-object v1, p0, Lh2/w4;->g:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v1, Ll2/b1;

    .line 192
    .line 193
    iget-object v2, p0, Lh2/w4;->h:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v2, Ll2/g1;

    .line 196
    .line 197
    iget-object v0, v0, Lh2/fc;->a:Landroid/view/View;

    .line 198
    .line 199
    new-instance v3, Landroid/graphics/Rect;

    .line 200
    .line 201
    invoke-direct {v3}, Landroid/graphics/Rect;-><init>()V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0, v3}, Landroid/view/View;->getWindowVisibleDisplayFrame(Landroid/graphics/Rect;)V

    .line 205
    .line 206
    .line 207
    iget v0, v3, Landroid/graphics/Rect;->top:I

    .line 208
    .line 209
    iget v3, v3, Landroid/graphics/Rect;->bottom:I

    .line 210
    .line 211
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Lt3/y;

    .line 216
    .line 217
    if-eqz v1, :cond_1

    .line 218
    .line 219
    invoke-interface {v1}, Lt3/y;->g()Z

    .line 220
    .line 221
    .line 222
    move-result v4

    .line 223
    if-nez v4, :cond_0

    .line 224
    .line 225
    goto :goto_0

    .line 226
    :cond_0
    const-wide/16 v4, 0x0

    .line 227
    .line 228
    invoke-interface {v1, v4, v5}, Lt3/y;->B(J)J

    .line 229
    .line 230
    .line 231
    move-result-wide v4

    .line 232
    invoke-interface {v1}, Lt3/y;->h()J

    .line 233
    .line 234
    .line 235
    move-result-wide v6

    .line 236
    invoke-static {v6, v7}, Lkp/f9;->c(J)J

    .line 237
    .line 238
    .line 239
    move-result-wide v6

    .line 240
    invoke-static {v4, v5, v6, v7}, Ljp/cf;->c(JJ)Ld3/c;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    goto :goto_1

    .line 245
    :cond_1
    :goto_0
    sget-object v1, Ld3/c;->e:Ld3/c;

    .line 246
    .line 247
    :goto_1
    iget p0, p0, Lh2/w4;->e:I

    .line 248
    .line 249
    add-int v4, v0, p0

    .line 250
    .line 251
    sub-int p0, v3, p0

    .line 252
    .line 253
    iget v5, v1, Ld3/c;->b:F

    .line 254
    .line 255
    int-to-float v3, v3

    .line 256
    cmpl-float v3, v5, v3

    .line 257
    .line 258
    if-gtz v3, :cond_3

    .line 259
    .line 260
    iget v1, v1, Ld3/c;->d:F

    .line 261
    .line 262
    int-to-float v0, v0

    .line 263
    cmpg-float v0, v1, v0

    .line 264
    .line 265
    if-gez v0, :cond_2

    .line 266
    .line 267
    goto :goto_2

    .line 268
    :cond_2
    int-to-float v0, v4

    .line 269
    sub-float/2addr v5, v0

    .line 270
    int-to-float p0, p0

    .line 271
    sub-float/2addr p0, v1

    .line 272
    invoke-static {v5, p0}, Ljava/lang/Math;->max(FF)F

    .line 273
    .line 274
    .line 275
    move-result p0

    .line 276
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 277
    .line 278
    .line 279
    move-result p0

    .line 280
    goto :goto_3

    .line 281
    :cond_3
    :goto_2
    sub-int/2addr p0, v4

    .line 282
    :goto_3
    const/4 v0, 0x0

    .line 283
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 284
    .line 285
    .line 286
    move-result p0

    .line 287
    invoke-virtual {v2, p0}, Ll2/g1;->p(I)V

    .line 288
    .line 289
    .line 290
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 291
    .line 292
    return-object p0

    .line 293
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
