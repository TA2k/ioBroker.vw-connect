.class public final synthetic Ly9/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly9/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly9/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 3

    .line 1
    iget v0, p0, Ly9/e;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ly9/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lzq/s;

    .line 9
    .line 10
    iget-object p1, p0, Lzq/s;->f:Landroid/widget/EditText;

    .line 11
    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    invoke-virtual {p1}, Landroid/widget/TextView;->getSelectionEnd()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    iget-object v0, p0, Lzq/s;->f:Landroid/widget/EditText;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v0}, Landroid/widget/TextView;->getTransformationMethod()Landroid/text/method/TransformationMethod;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    instance-of v0, v0, Landroid/text/method/PasswordTransformationMethod;

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    iget-object v0, p0, Lzq/s;->f:Landroid/widget/EditText;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setTransformationMethod(Landroid/text/method/TransformationMethod;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    iget-object v0, p0, Lzq/s;->f:Landroid/widget/EditText;

    .line 39
    .line 40
    invoke-static {}, Landroid/text/method/PasswordTransformationMethod;->getInstance()Landroid/text/method/PasswordTransformationMethod;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setTransformationMethod(Landroid/text/method/TransformationMethod;)V

    .line 45
    .line 46
    .line 47
    :goto_0
    if-ltz p1, :cond_2

    .line 48
    .line 49
    iget-object v0, p0, Lzq/s;->f:Landroid/widget/EditText;

    .line 50
    .line 51
    invoke-virtual {v0, p1}, Landroid/widget/EditText;->setSelection(I)V

    .line 52
    .line 53
    .line 54
    :cond_2
    invoke-virtual {p0}, Lzq/m;->p()V

    .line 55
    .line 56
    .line 57
    :goto_1
    return-void

    .line 58
    :pswitch_0
    check-cast p0, Lzq/i;

    .line 59
    .line 60
    invoke-virtual {p0}, Lzq/i;->t()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_1
    check-cast p0, Lzq/c;

    .line 65
    .line 66
    iget-object p1, p0, Lzq/c;->i:Landroid/widget/EditText;

    .line 67
    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-eqz p1, :cond_4

    .line 76
    .line 77
    invoke-interface {p1}, Landroid/text/Editable;->clear()V

    .line 78
    .line 79
    .line 80
    :cond_4
    invoke-virtual {p0}, Lzq/m;->p()V

    .line 81
    .line 82
    .line 83
    :goto_2
    return-void

    .line 84
    :pswitch_2
    check-cast p0, Ly9/w;

    .line 85
    .line 86
    invoke-virtual {p0}, Ly9/w;->g()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    const v1, 0x7f0a0147

    .line 94
    .line 95
    .line 96
    if-ne v0, v1, :cond_5

    .line 97
    .line 98
    iget-object p0, p0, Ly9/w;->q:Landroid/animation/ValueAnimator;

    .line 99
    .line 100
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->start()V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    const v0, 0x7f0a0146

    .line 109
    .line 110
    .line 111
    if-ne p1, v0, :cond_6

    .line 112
    .line 113
    iget-object p0, p0, Ly9/w;->r:Landroid/animation/ValueAnimator;

    .line 114
    .line 115
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->start()V

    .line 116
    .line 117
    .line 118
    :cond_6
    :goto_3
    return-void

    .line 119
    :pswitch_3
    check-cast p0, Ly9/f;

    .line 120
    .line 121
    iget-object p0, p0, Ly9/f;->g:Ly9/r;

    .line 122
    .line 123
    iget-object p1, p0, Ly9/r;->B1:Lt7/l0;

    .line 124
    .line 125
    if-eqz p1, :cond_7

    .line 126
    .line 127
    const/16 v0, 0x1d

    .line 128
    .line 129
    check-cast p1, Lap0/o;

    .line 130
    .line 131
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 132
    .line 133
    .line 134
    move-result p1

    .line 135
    if-eqz p1, :cond_7

    .line 136
    .line 137
    iget-object p1, p0, Ly9/r;->B1:Lt7/l0;

    .line 138
    .line 139
    check-cast p1, La8/i0;

    .line 140
    .line 141
    invoke-virtual {p1}, La8/i0;->q0()Lt7/u0;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 146
    .line 147
    check-cast p1, Lj8/i;

    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    new-instance v1, Lj8/h;

    .line 153
    .line 154
    invoke-direct {v1, p1}, Lj8/h;-><init>(Lj8/i;)V

    .line 155
    .line 156
    .line 157
    const/4 p1, 0x3

    .line 158
    invoke-virtual {v1, p1}, Lj8/h;->b(I)Lt7/t0;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1}, Lt7/t0;->d()Lt7/t0;

    .line 162
    .line 163
    .line 164
    invoke-virtual {v1}, Lt7/t0;->f()Lt7/t0;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1}, Lt7/t0;->h()Lt7/t0;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1}, Lt7/t0;->a()Lt7/u0;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    check-cast v0, La8/i0;

    .line 175
    .line 176
    invoke-virtual {v0, p1}, La8/i0;->D0(Lt7/u0;)V

    .line 177
    .line 178
    .line 179
    iget-object p0, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 180
    .line 181
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 182
    .line 183
    .line 184
    :cond_7
    return-void

    .line 185
    :pswitch_4
    check-cast p0, Ly9/l;

    .line 186
    .line 187
    iget-object p1, p0, Ly9/l;->x:Ly9/r;

    .line 188
    .line 189
    iget-object v0, p0, Lka/v0;->s:Lka/y;

    .line 190
    .line 191
    const/4 v1, -0x1

    .line 192
    if-nez v0, :cond_8

    .line 193
    .line 194
    goto :goto_4

    .line 195
    :cond_8
    iget-object v0, p0, Lka/v0;->r:Landroidx/recyclerview/widget/RecyclerView;

    .line 196
    .line 197
    if-nez v0, :cond_9

    .line 198
    .line 199
    goto :goto_4

    .line 200
    :cond_9
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    if-nez v0, :cond_a

    .line 205
    .line 206
    goto :goto_4

    .line 207
    :cond_a
    iget-object v2, p0, Lka/v0;->r:Landroidx/recyclerview/widget/RecyclerView;

    .line 208
    .line 209
    invoke-virtual {v2, p0}, Landroidx/recyclerview/widget/RecyclerView;->G(Lka/v0;)I

    .line 210
    .line 211
    .line 212
    move-result v2

    .line 213
    if-ne v2, v1, :cond_b

    .line 214
    .line 215
    goto :goto_4

    .line 216
    :cond_b
    iget-object p0, p0, Lka/v0;->s:Lka/y;

    .line 217
    .line 218
    if-ne p0, v0, :cond_c

    .line 219
    .line 220
    move v1, v2

    .line 221
    :cond_c
    :goto_4
    iget-object p0, p1, Ly9/r;->I:Landroid/view/View;

    .line 222
    .line 223
    if-nez v1, :cond_d

    .line 224
    .line 225
    iget-object v0, p1, Ly9/r;->p:Ly9/j;

    .line 226
    .line 227
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    invoke-virtual {p1, v0, p0}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 231
    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_d
    const/4 v0, 0x1

    .line 235
    if-ne v1, v0, :cond_e

    .line 236
    .line 237
    iget-object v0, p1, Ly9/r;->r:Ly9/f;

    .line 238
    .line 239
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    invoke-virtual {p1, v0, p0}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 243
    .line 244
    .line 245
    goto :goto_5

    .line 246
    :cond_e
    iget-object p0, p1, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 247
    .line 248
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 249
    .line 250
    .line 251
    :goto_5
    return-void

    .line 252
    :pswitch_5
    check-cast p0, Ly9/f;

    .line 253
    .line 254
    iget-object p0, p0, Ly9/f;->g:Ly9/r;

    .line 255
    .line 256
    iget-object p1, p0, Ly9/r;->B1:Lt7/l0;

    .line 257
    .line 258
    if-eqz p1, :cond_10

    .line 259
    .line 260
    const/16 v0, 0x1d

    .line 261
    .line 262
    check-cast p1, Lap0/o;

    .line 263
    .line 264
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 265
    .line 266
    .line 267
    move-result p1

    .line 268
    if-nez p1, :cond_f

    .line 269
    .line 270
    goto :goto_6

    .line 271
    :cond_f
    iget-object p1, p0, Ly9/r;->B1:Lt7/l0;

    .line 272
    .line 273
    check-cast p1, La8/i0;

    .line 274
    .line 275
    invoke-virtual {p1}, La8/i0;->q0()Lt7/u0;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 280
    .line 281
    check-cast p1, Lj8/i;

    .line 282
    .line 283
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 284
    .line 285
    .line 286
    new-instance v1, Lj8/h;

    .line 287
    .line 288
    invoke-direct {v1, p1}, Lj8/h;-><init>(Lj8/i;)V

    .line 289
    .line 290
    .line 291
    const/4 p1, 0x1

    .line 292
    invoke-virtual {v1, p1}, Lj8/h;->b(I)Lt7/t0;

    .line 293
    .line 294
    .line 295
    const/4 v2, 0x0

    .line 296
    invoke-virtual {v1, p1, v2}, Lt7/t0;->i(IZ)Lt7/t0;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1}, Lt7/t0;->a()Lt7/u0;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    check-cast v0, La8/i0;

    .line 304
    .line 305
    invoke-virtual {v0, v1}, La8/i0;->D0(Lt7/u0;)V

    .line 306
    .line 307
    .line 308
    iget-object v0, p0, Ly9/r;->o:Ly9/m;

    .line 309
    .line 310
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    const v2, 0x7f1202f6

    .line 315
    .line 316
    .line 317
    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    iget-object v0, v0, Ly9/m;->e:[Ljava/lang/String;

    .line 322
    .line 323
    aput-object v1, v0, p1

    .line 324
    .line 325
    iget-object p0, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 326
    .line 327
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 328
    .line 329
    .line 330
    :cond_10
    :goto_6
    return-void

    .line 331
    :pswitch_6
    check-cast p0, Ly9/r;

    .line 332
    .line 333
    iget-boolean p1, p0, Ly9/r;->C1:Z

    .line 334
    .line 335
    xor-int/lit8 p1, p1, 0x1

    .line 336
    .line 337
    invoke-virtual {p0, p1}, Ly9/r;->o(Z)V

    .line 338
    .line 339
    .line 340
    return-void

    .line 341
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
