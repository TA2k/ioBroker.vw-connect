.class public final Lcom/google/android/material/datepicker/t;
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
    iput p2, p0, Lcom/google/android/material/datepicker/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroidx/media3/ui/TrackSelectionView;

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/media3/ui/TrackSelectionView;->j:Ljava/util/HashMap;

    .line 11
    .line 12
    iget-object v1, p0, Landroidx/media3/ui/TrackSelectionView;->f:Landroid/widget/CheckedTextView;

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    if-ne p1, v1, :cond_0

    .line 16
    .line 17
    iput-boolean v2, p0, Landroidx/media3/ui/TrackSelectionView;->o:Z

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 20
    .line 21
    .line 22
    goto/16 :goto_2

    .line 23
    .line 24
    :cond_0
    iget-object v1, p0, Landroidx/media3/ui/TrackSelectionView;->g:Landroid/widget/CheckedTextView;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-ne p1, v1, :cond_1

    .line 28
    .line 29
    iput-boolean v3, p0, Landroidx/media3/ui/TrackSelectionView;->o:Z

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 32
    .line 33
    .line 34
    goto/16 :goto_2

    .line 35
    .line 36
    :cond_1
    iput-boolean v3, p0, Landroidx/media3/ui/TrackSelectionView;->o:Z

    .line 37
    .line 38
    invoke-virtual {p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    check-cast v1, Ly9/j0;

    .line 46
    .line 47
    iget-object v4, v1, Ly9/j0;->a:Lt7/v0;

    .line 48
    .line 49
    iget-object v5, v4, Lt7/v0;->b:Lt7/q0;

    .line 50
    .line 51
    iget v1, v1, Ly9/j0;->b:I

    .line 52
    .line 53
    invoke-virtual {v0, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    check-cast v6, Lt7/r0;

    .line 58
    .line 59
    if-nez v6, :cond_3

    .line 60
    .line 61
    iget-boolean p1, p0, Landroidx/media3/ui/TrackSelectionView;->l:Z

    .line 62
    .line 63
    if-nez p1, :cond_2

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/util/HashMap;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-nez p1, :cond_2

    .line 70
    .line 71
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 72
    .line 73
    .line 74
    :cond_2
    new-instance p1, Lt7/r0;

    .line 75
    .line 76
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-direct {p1, v5, v1}, Lt7/r0;-><init>(Lt7/q0;Ljava/util/List;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v5, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    goto/16 :goto_2

    .line 91
    .line 92
    :cond_3
    new-instance v7, Ljava/util/ArrayList;

    .line 93
    .line 94
    iget-object v6, v6, Lt7/r0;->b:Lhr/h0;

    .line 95
    .line 96
    invoke-direct {v7, v6}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 97
    .line 98
    .line 99
    check-cast p1, Landroid/widget/CheckedTextView;

    .line 100
    .line 101
    invoke-virtual {p1}, Landroid/widget/CheckedTextView;->isChecked()Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    iget-boolean v6, p0, Landroidx/media3/ui/TrackSelectionView;->k:Z

    .line 106
    .line 107
    if-eqz v6, :cond_4

    .line 108
    .line 109
    iget-boolean v4, v4, Lt7/v0;->c:Z

    .line 110
    .line 111
    if-eqz v4, :cond_4

    .line 112
    .line 113
    move v4, v2

    .line 114
    goto :goto_0

    .line 115
    :cond_4
    move v4, v3

    .line 116
    :goto_0
    if-nez v4, :cond_6

    .line 117
    .line 118
    iget-boolean v6, p0, Landroidx/media3/ui/TrackSelectionView;->l:Z

    .line 119
    .line 120
    if-eqz v6, :cond_5

    .line 121
    .line 122
    iget-object v6, p0, Landroidx/media3/ui/TrackSelectionView;->i:Ljava/util/ArrayList;

    .line 123
    .line 124
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    if-le v6, v2, :cond_5

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_5
    move v2, v3

    .line 132
    :cond_6
    :goto_1
    if-eqz p1, :cond_8

    .line 133
    .line 134
    if-eqz v2, :cond_8

    .line 135
    .line 136
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {v7, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 144
    .line 145
    .line 146
    move-result p1

    .line 147
    if-eqz p1, :cond_7

    .line 148
    .line 149
    invoke-virtual {v0, v5}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_7
    new-instance p1, Lt7/r0;

    .line 154
    .line 155
    invoke-direct {p1, v5, v7}, Lt7/r0;-><init>(Lt7/q0;Ljava/util/List;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0, v5, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_8
    if-nez p1, :cond_a

    .line 163
    .line 164
    if-eqz v4, :cond_9

    .line 165
    .line 166
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-virtual {v7, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    new-instance p1, Lt7/r0;

    .line 174
    .line 175
    invoke-direct {p1, v5, v7}, Lt7/r0;-><init>(Lt7/q0;Ljava/util/List;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v0, v5, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_9
    new-instance p1, Lt7/r0;

    .line 183
    .line 184
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    invoke-direct {p1, v5, v1}, Lt7/r0;-><init>(Lt7/q0;Ljava/util/List;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v0, v5, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    :cond_a
    :goto_2
    invoke-virtual {p0}, Landroidx/media3/ui/TrackSelectionView;->a()V

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast p0, Landroidx/appcompat/widget/Toolbar;

    .line 205
    .line 206
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->O:Lm/r2;

    .line 207
    .line 208
    if-nez p0, :cond_b

    .line 209
    .line 210
    const/4 p0, 0x0

    .line 211
    goto :goto_3

    .line 212
    :cond_b
    iget-object p0, p0, Lm/r2;->e:Ll/n;

    .line 213
    .line 214
    :goto_3
    if-eqz p0, :cond_c

    .line 215
    .line 216
    invoke-virtual {p0}, Ll/n;->collapseActionView()Z

    .line 217
    .line 218
    .line 219
    :cond_c
    return-void

    .line 220
    :pswitch_1
    iget-object p0, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast p0, Lk/a;

    .line 223
    .line 224
    invoke-virtual {p0}, Lk/a;->a()V

    .line 225
    .line 226
    .line 227
    return-void

    .line 228
    :pswitch_2
    iget-object p0, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p0, Lh/d;

    .line 231
    .line 232
    iget-object v0, p0, Lh/d;->h:Landroid/widget/Button;

    .line 233
    .line 234
    if-ne p1, v0, :cond_d

    .line 235
    .line 236
    iget-object v0, p0, Lh/d;->j:Landroid/os/Message;

    .line 237
    .line 238
    if-eqz v0, :cond_d

    .line 239
    .line 240
    invoke-static {v0}, Landroid/os/Message;->obtain(Landroid/os/Message;)Landroid/os/Message;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    goto :goto_4

    .line 245
    :cond_d
    iget-object v0, p0, Lh/d;->k:Landroid/widget/Button;

    .line 246
    .line 247
    if-ne p1, v0, :cond_e

    .line 248
    .line 249
    iget-object v0, p0, Lh/d;->m:Landroid/os/Message;

    .line 250
    .line 251
    if-eqz v0, :cond_e

    .line 252
    .line 253
    invoke-static {v0}, Landroid/os/Message;->obtain(Landroid/os/Message;)Landroid/os/Message;

    .line 254
    .line 255
    .line 256
    move-result-object p1

    .line 257
    goto :goto_4

    .line 258
    :cond_e
    iget-object v0, p0, Lh/d;->n:Landroid/widget/Button;

    .line 259
    .line 260
    if-ne p1, v0, :cond_f

    .line 261
    .line 262
    iget-object p1, p0, Lh/d;->p:Landroid/os/Message;

    .line 263
    .line 264
    if-eqz p1, :cond_f

    .line 265
    .line 266
    invoke-static {p1}, Landroid/os/Message;->obtain(Landroid/os/Message;)Landroid/os/Message;

    .line 267
    .line 268
    .line 269
    move-result-object p1

    .line 270
    goto :goto_4

    .line 271
    :cond_f
    const/4 p1, 0x0

    .line 272
    :goto_4
    if-eqz p1, :cond_10

    .line 273
    .line 274
    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    .line 275
    .line 276
    .line 277
    :cond_10
    iget-object p1, p0, Lh/d;->D:Lf8/e;

    .line 278
    .line 279
    const/4 v0, 0x1

    .line 280
    iget-object p0, p0, Lh/d;->b:Lh/f;

    .line 281
    .line 282
    invoke-virtual {p1, v0, p0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 287
    .line 288
    .line 289
    return-void

    .line 290
    :pswitch_3
    iget-object p0, p0, Lcom/google/android/material/datepicker/t;->e:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast p0, Lcom/google/android/material/datepicker/u;

    .line 293
    .line 294
    iget p1, p0, Lcom/google/android/material/datepicker/u;->i:I

    .line 295
    .line 296
    const/4 v0, 0x1

    .line 297
    const/4 v1, 0x2

    .line 298
    if-ne p1, v1, :cond_11

    .line 299
    .line 300
    invoke-virtual {p0, v0}, Lcom/google/android/material/datepicker/u;->k(I)V

    .line 301
    .line 302
    .line 303
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 304
    .line 305
    const v0, 0x7f1207f2

    .line 306
    .line 307
    .line 308
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    invoke-virtual {p1, p0}, Landroid/view/View;->announceForAccessibility(Ljava/lang/CharSequence;)V

    .line 313
    .line 314
    .line 315
    goto :goto_5

    .line 316
    :cond_11
    if-ne p1, v0, :cond_12

    .line 317
    .line 318
    invoke-virtual {p0, v1}, Lcom/google/android/material/datepicker/u;->k(I)V

    .line 319
    .line 320
    .line 321
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 322
    .line 323
    const v0, 0x7f1207f3

    .line 324
    .line 325
    .line 326
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object p0

    .line 330
    invoke-virtual {p1, p0}, Landroid/view/View;->announceForAccessibility(Ljava/lang/CharSequence;)V

    .line 331
    .line 332
    .line 333
    :cond_12
    :goto_5
    return-void

    .line 334
    nop

    .line 335
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
