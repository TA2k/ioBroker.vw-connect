.class public final Lq/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/j0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lq/k;


# direct methods
.method public synthetic constructor <init>(Lq/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq/f;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lq/f;->b:Lq/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lq/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lq/k;->i(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lq/k;->j()V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 24
    .line 25
    iget-object p1, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 26
    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    new-instance p1, Landroidx/lifecycle/i0;

    .line 30
    .line 31
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 35
    .line 36
    :cond_0
    iget-object p0, p0, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 37
    .line 38
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 39
    .line 40
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void

    .line 44
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_5

    .line 51
    .line 52
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 53
    .line 54
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 55
    .line 56
    iget-object p1, p1, Lq/s;->f:Lil/g;

    .line 57
    .line 58
    if-eqz p1, :cond_3

    .line 59
    .line 60
    iget-object p1, p1, Lil/g;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Ljava/lang/CharSequence;

    .line 63
    .line 64
    if-eqz p1, :cond_2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    const-string p1, ""

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_3
    const/4 p1, 0x0

    .line 71
    :goto_0
    if-eqz p1, :cond_4

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_4
    const p1, 0x7f1201f0

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    :goto_1
    const/16 v0, 0xd

    .line 82
    .line 83
    invoke-virtual {p0, v0, p1}, Lq/k;->l(ILjava/lang/CharSequence;)V

    .line 84
    .line 85
    .line 86
    const/4 p1, 0x2

    .line 87
    invoke-virtual {p0, p1}, Lq/k;->i(I)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 91
    .line 92
    const/4 p1, 0x0

    .line 93
    invoke-virtual {p0, p1}, Lq/s;->f(Z)V

    .line 94
    .line 95
    .line 96
    :cond_5
    return-void

    .line 97
    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    if-eqz p1, :cond_9

    .line 104
    .line 105
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 106
    .line 107
    invoke-virtual {p0}, Lq/k;->k()V

    .line 108
    .line 109
    .line 110
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 111
    .line 112
    iget-boolean v0, p1, Lq/s;->l:Z

    .line 113
    .line 114
    if-nez v0, :cond_6

    .line 115
    .line 116
    const-string p1, "BiometricFragment"

    .line 117
    .line 118
    const-string v0, "Failure not sent to client. Client is not awaiting a result."

    .line 119
    .line 120
    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 121
    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_6
    iget-object p1, p1, Lq/s;->d:Ljava/util/concurrent/Executor;

    .line 125
    .line 126
    if-eqz p1, :cond_7

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_7
    new-instance p1, Lq/q;

    .line 130
    .line 131
    invoke-direct {p1}, Lq/q;-><init>()V

    .line 132
    .line 133
    .line 134
    :goto_2
    new-instance v0, Laq/p;

    .line 135
    .line 136
    const/16 v1, 0x15

    .line 137
    .line 138
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 139
    .line 140
    .line 141
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 142
    .line 143
    .line 144
    :goto_3
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 145
    .line 146
    iget-object p1, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 147
    .line 148
    if-nez p1, :cond_8

    .line 149
    .line 150
    new-instance p1, Landroidx/lifecycle/i0;

    .line 151
    .line 152
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 153
    .line 154
    .line 155
    iput-object p1, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 156
    .line 157
    :cond_8
    iget-object p0, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 158
    .line 159
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 160
    .line 161
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :cond_9
    return-void

    .line 165
    :pswitch_2
    check-cast p1, Ljava/lang/CharSequence;

    .line 166
    .line 167
    if-eqz p1, :cond_a

    .line 168
    .line 169
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 170
    .line 171
    invoke-virtual {p0}, Lq/k;->k()V

    .line 172
    .line 173
    .line 174
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 175
    .line 176
    const/4 p1, 0x0

    .line 177
    invoke-virtual {p0, p1}, Lq/s;->a(Lq/e;)V

    .line 178
    .line 179
    .line 180
    :cond_a
    return-void

    .line 181
    :pswitch_3
    check-cast p1, Lq/e;

    .line 182
    .line 183
    if-eqz p1, :cond_c

    .line 184
    .line 185
    iget v0, p1, Lq/e;->a:I

    .line 186
    .line 187
    iget-object p1, p1, Lq/e;->b:Ljava/lang/CharSequence;

    .line 188
    .line 189
    packed-switch v0, :pswitch_data_1

    .line 190
    .line 191
    .line 192
    :pswitch_4
    const/16 v0, 0x8

    .line 193
    .line 194
    :pswitch_5
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 195
    .line 196
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 197
    .line 198
    .line 199
    invoke-virtual {p0}, Lq/k;->k()V

    .line 200
    .line 201
    .line 202
    if-eqz p1, :cond_b

    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_b
    new-instance p1, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 208
    .line 209
    .line 210
    const v1, 0x7f1201f0

    .line 211
    .line 212
    .line 213
    invoke-virtual {p0, v1}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    const-string v1, " "

    .line 221
    .line 222
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 223
    .line 224
    .line 225
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object p1

    .line 232
    :goto_4
    invoke-virtual {p0, v0, p1}, Lq/k;->l(ILjava/lang/CharSequence;)V

    .line 233
    .line 234
    .line 235
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 236
    .line 237
    const/4 p1, 0x0

    .line 238
    invoke-virtual {p0, p1}, Lq/s;->a(Lq/e;)V

    .line 239
    .line 240
    .line 241
    :cond_c
    return-void

    .line 242
    :pswitch_6
    check-cast p1, Lq/n;

    .line 243
    .line 244
    if-eqz p1, :cond_e

    .line 245
    .line 246
    iget-object p0, p0, Lq/f;->b:Lq/k;

    .line 247
    .line 248
    invoke-virtual {p0, p1}, Lq/k;->m(Lq/n;)V

    .line 249
    .line 250
    .line 251
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 252
    .line 253
    iget-object p1, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 254
    .line 255
    if-nez p1, :cond_d

    .line 256
    .line 257
    new-instance p1, Landroidx/lifecycle/i0;

    .line 258
    .line 259
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 260
    .line 261
    .line 262
    iput-object p1, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 263
    .line 264
    :cond_d
    iget-object p0, p0, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 265
    .line 266
    const/4 p1, 0x0

    .line 267
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    :cond_e
    return-void

    .line 271
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 272
    .line 273
    .line 274
    .line 275
    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    .line 284
    .line 285
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
    .end packed-switch
.end method
