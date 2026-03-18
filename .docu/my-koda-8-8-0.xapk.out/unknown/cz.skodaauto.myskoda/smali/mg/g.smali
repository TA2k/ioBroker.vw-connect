.class public final synthetic Lmg/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lyj/b;Lxh/e;)V
    .locals 0

    .line 1
    const/4 p2, 0x4

    iput p2, p0, Lmg/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lmg/g;->f:Ll2/b1;

    iput-object p3, p0, Lmg/g;->e:Lxh/e;

    return-void
.end method

.method public synthetic constructor <init>(Lxh/e;Ll2/b1;I)V
    .locals 0

    .line 2
    iput p3, p0, Lmg/g;->d:I

    iput-object p1, p0, Lmg/g;->e:Lxh/e;

    iput-object p2, p0, Lmg/g;->f:Ll2/b1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lmg/g;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p3, Ll2/o;

    .line 11
    .line 12
    check-cast p4, Ljava/lang/Integer;

    .line 13
    .line 14
    const-string v0, "$this$composable"

    .line 15
    .line 16
    const-string v1, "it"

    .line 17
    .line 18
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lmg/g;->f:Ll2/b1;

    .line 22
    .line 23
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Ltc/q;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    check-cast p3, Ll2/t;

    .line 31
    .line 32
    if-nez p1, :cond_0

    .line 33
    .line 34
    const p0, 0x65b7a05e

    .line 35
    .line 36
    .line 37
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    :goto_0
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const p4, 0x65b7a05f

    .line 45
    .line 46
    .line 47
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 48
    .line 49
    .line 50
    iget-boolean p4, p1, Ltc/q;->f:Z

    .line 51
    .line 52
    iget-object p1, p1, Ltc/q;->d:Ljava/lang/String;

    .line 53
    .line 54
    iget-object p0, p0, Lmg/g;->e:Lxh/e;

    .line 55
    .line 56
    invoke-static {p0, p4, p1, p3, p2}, Llp/gd;->a(Lxh/e;ZLjava/lang/String;Ll2/o;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_0
    move-object v5, p3

    .line 64
    check-cast v5, Ll2/o;

    .line 65
    .line 66
    check-cast p4, Ljava/lang/Integer;

    .line 67
    .line 68
    const-string p3, "$this$composable"

    .line 69
    .line 70
    const-string v0, "it"

    .line 71
    .line 72
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p0, Lmg/g;->f:Ll2/b1;

    .line 76
    .line 77
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    check-cast p2, Lmg/c;

    .line 82
    .line 83
    iget-object v0, p2, Lmg/c;->l:Lac/a0;

    .line 84
    .line 85
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    check-cast p2, Lmg/c;

    .line 93
    .line 94
    iget-object v2, p2, Lmg/c;->h:Lac/e;

    .line 95
    .line 96
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    check-cast p2, Lmg/c;

    .line 101
    .line 102
    iget-object v3, p2, Lmg/c;->g:Log/i;

    .line 103
    .line 104
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    check-cast p1, Lmg/c;

    .line 109
    .line 110
    iget-object v4, p1, Lmg/c;->k:Ljava/util/List;

    .line 111
    .line 112
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    const/16 v6, 0x8

    .line 116
    .line 117
    iget-object v1, p0, Lmg/g;->e:Lxh/e;

    .line 118
    .line 119
    invoke-static/range {v0 .. v6}, Ljp/tb;->b(Lac/a0;Lxh/e;Lac/e;Log/i;Ljava/util/List;Ll2/o;I)V

    .line 120
    .line 121
    .line 122
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_1
    move-object v5, p3

    .line 126
    check-cast v5, Ll2/o;

    .line 127
    .line 128
    check-cast p4, Ljava/lang/Integer;

    .line 129
    .line 130
    const-string p3, "$this$composable"

    .line 131
    .line 132
    const-string v0, "it"

    .line 133
    .line 134
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    iget-object p1, p0, Lmg/g;->f:Ll2/b1;

    .line 138
    .line 139
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    check-cast p2, Lmg/c;

    .line 144
    .line 145
    iget-object v0, p2, Lmg/c;->l:Lac/a0;

    .line 146
    .line 147
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    check-cast p1, Lmg/c;

    .line 155
    .line 156
    iget-object v4, p1, Lmg/c;->k:Ljava/util/List;

    .line 157
    .line 158
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    const/16 v6, 0xd88

    .line 162
    .line 163
    iget-object v1, p0, Lmg/g;->e:Lxh/e;

    .line 164
    .line 165
    const/4 v2, 0x0

    .line 166
    const/4 v3, 0x0

    .line 167
    invoke-static/range {v0 .. v6}, Ljp/tb;->b(Lac/a0;Lxh/e;Lac/e;Log/i;Ljava/util/List;Ll2/o;I)V

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :pswitch_2
    move-object v4, p3

    .line 172
    check-cast v4, Ll2/o;

    .line 173
    .line 174
    check-cast p4, Ljava/lang/Integer;

    .line 175
    .line 176
    const-string p3, "$this$composable"

    .line 177
    .line 178
    const-string v0, "it"

    .line 179
    .line 180
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    iget-object p1, p0, Lmg/g;->f:Ll2/b1;

    .line 184
    .line 185
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p2

    .line 189
    check-cast p2, Lmg/c;

    .line 190
    .line 191
    iget-object v0, p2, Lmg/c;->f:Lac/e;

    .line 192
    .line 193
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p2

    .line 197
    check-cast p2, Lmg/c;

    .line 198
    .line 199
    iget-object v1, p2, Lmg/c;->l:Lac/a0;

    .line 200
    .line 201
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    check-cast p1, Lmg/c;

    .line 209
    .line 210
    iget-object p1, p1, Lmg/c;->j:Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    const/16 v5, 0x40

    .line 220
    .line 221
    iget-object v3, p0, Lmg/g;->e:Lxh/e;

    .line 222
    .line 223
    invoke-static/range {v0 .. v5}, Ljp/oa;->a(Lac/e;Lac/a0;ZLxh/e;Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    goto :goto_2

    .line 227
    :pswitch_3
    move-object v4, p3

    .line 228
    check-cast v4, Ll2/o;

    .line 229
    .line 230
    check-cast p4, Ljava/lang/Integer;

    .line 231
    .line 232
    const-string p3, "$this$composable"

    .line 233
    .line 234
    const-string v0, "it"

    .line 235
    .line 236
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    iget-object p1, p0, Lmg/g;->f:Ll2/b1;

    .line 240
    .line 241
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object p2

    .line 245
    check-cast p2, Lmg/c;

    .line 246
    .line 247
    iget-object v1, p2, Lmg/c;->l:Lac/a0;

    .line 248
    .line 249
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object p1

    .line 256
    check-cast p1, Lmg/c;

    .line 257
    .line 258
    iget-object p1, p1, Lmg/c;->j:Ljava/lang/Boolean;

    .line 259
    .line 260
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    const/16 v5, 0x46

    .line 268
    .line 269
    const/4 v0, 0x0

    .line 270
    iget-object v3, p0, Lmg/g;->e:Lxh/e;

    .line 271
    .line 272
    invoke-static/range {v0 .. v5}, Ljp/oa;->a(Lac/e;Lac/a0;ZLxh/e;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    goto/16 :goto_2

    .line 276
    .line 277
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
