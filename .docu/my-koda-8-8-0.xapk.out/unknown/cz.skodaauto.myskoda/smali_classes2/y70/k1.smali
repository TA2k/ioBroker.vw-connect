.class public final synthetic Ly70/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/u1;


# direct methods
.method public synthetic constructor <init>(Ly70/u1;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/k1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/k1;->e:Ly70/u1;

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
    iget v0, p0, Ly70/k1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/a;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 9
    .line 10
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 11
    .line 12
    const v1, 0x7f1211c6

    .line 13
    .line 14
    .line 15
    check-cast p0, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_0
    new-instance v0, Llj0/b;

    .line 26
    .line 27
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 28
    .line 29
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 30
    .line 31
    const v1, 0x7f1211c6

    .line 32
    .line 33
    .line 34
    check-cast p0, Ljj0/f;

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const-string v1, "https://web-pages-cz.skoda-auto.cz/servis/objednavka-servisu"

    .line 41
    .line 42
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :pswitch_1
    new-instance v0, Llj0/a;

    .line 47
    .line 48
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 49
    .line 50
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 51
    .line 52
    const v1, 0x7f1211bf

    .line 53
    .line 54
    .line 55
    check-cast p0, Ljj0/f;

    .line 56
    .line 57
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_2
    new-instance v0, Llj0/b;

    .line 66
    .line 67
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 68
    .line 69
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 70
    .line 71
    const v1, 0x7f1211bc

    .line 72
    .line 73
    .line 74
    check-cast p0, Ljj0/f;

    .line 75
    .line 76
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-string v1, "system://phone_app"

    .line 81
    .line 82
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    return-object v0

    .line 86
    :pswitch_3
    new-instance v0, Llj0/b;

    .line 87
    .line 88
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 89
    .line 90
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 91
    .line 92
    const v1, 0x7f1211b4

    .line 93
    .line 94
    .line 95
    check-cast p0, Ljj0/f;

    .line 96
    .line 97
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const-string v1, "https://www.wwesupercard.com"

    .line 102
    .line 103
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    return-object v0

    .line 107
    :pswitch_4
    new-instance v0, Llj0/b;

    .line 108
    .line 109
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 110
    .line 111
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 112
    .line 113
    const v1, 0x7f1211b4

    .line 114
    .line 115
    .line 116
    check-cast p0, Ljj0/f;

    .line 117
    .line 118
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    const-string v1, "https://mon-devis-en-ligne.skoda-entretien.fr"

    .line 123
    .line 124
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    return-object v0

    .line 128
    :pswitch_5
    new-instance v0, Llj0/b;

    .line 129
    .line 130
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 131
    .line 132
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 133
    .line 134
    const v1, 0x7f1211b1

    .line 135
    .line 136
    .line 137
    check-cast p0, Ljj0/f;

    .line 138
    .line 139
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    const-string v1, "system://email_app"

    .line 144
    .line 145
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    return-object v0

    .line 149
    :pswitch_6
    new-instance v0, Llj0/a;

    .line 150
    .line 151
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 152
    .line 153
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 154
    .line 155
    const v1, 0x7f1211c6

    .line 156
    .line 157
    .line 158
    check-cast p0, Ljj0/f;

    .line 159
    .line 160
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    return-object v0

    .line 168
    :pswitch_7
    new-instance v0, Llj0/b;

    .line 169
    .line 170
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 171
    .line 172
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 173
    .line 174
    const v1, 0x7f1211c6

    .line 175
    .line 176
    .line 177
    check-cast p0, Ljj0/f;

    .line 178
    .line 179
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    const-string v1, "https://web-pages-cz.skoda-auto.cz/servis/objednavka-servisu"

    .line 184
    .line 185
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    return-object v0

    .line 189
    :pswitch_8
    new-instance v0, Llj0/a;

    .line 190
    .line 191
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 192
    .line 193
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 194
    .line 195
    const v1, 0x7f1211c6

    .line 196
    .line 197
    .line 198
    check-cast p0, Ljj0/f;

    .line 199
    .line 200
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    return-object v0

    .line 208
    :pswitch_9
    new-instance v0, Llj0/b;

    .line 209
    .line 210
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 211
    .line 212
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 213
    .line 214
    const v1, 0x7f1211c6

    .line 215
    .line 216
    .line 217
    check-cast p0, Ljj0/f;

    .line 218
    .line 219
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    const-string v1, "https://www.skoda.nl/werkplaatsafspraak#/"

    .line 224
    .line 225
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    return-object v0

    .line 229
    :pswitch_a
    new-instance v0, Llj0/a;

    .line 230
    .line 231
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 232
    .line 233
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 234
    .line 235
    const v1, 0x7f1211c6

    .line 236
    .line 237
    .line 238
    check-cast p0, Ljj0/f;

    .line 239
    .line 240
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    return-object v0

    .line 248
    :pswitch_b
    new-instance v0, Llj0/b;

    .line 249
    .line 250
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 251
    .line 252
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 253
    .line 254
    const v1, 0x7f1211c6

    .line 255
    .line 256
    .line 257
    check-cast p0, Ljj0/f;

    .line 258
    .line 259
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    const-string v1, "https://rdv-atelier.skoda-entretien.fr"

    .line 264
    .line 265
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    return-object v0

    .line 269
    :pswitch_c
    new-instance v0, Llj0/a;

    .line 270
    .line 271
    iget-object p0, p0, Ly70/k1;->e:Ly70/u1;

    .line 272
    .line 273
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 274
    .line 275
    const v1, 0x7f120379

    .line 276
    .line 277
    .line 278
    check-cast p0, Ljj0/f;

    .line 279
    .line 280
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    return-object v0

    .line 288
    nop

    .line 289
    :pswitch_data_0
    .packed-switch 0x0
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
