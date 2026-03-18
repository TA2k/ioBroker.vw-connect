.class public final Lxf0/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lxf0/e1;

.field public static final f:Lxf0/e1;

.field public static final g:Lxf0/e1;

.field public static final h:Lxf0/e1;

.field public static final i:Lxf0/e1;

.field public static final j:Lxf0/e1;

.field public static final k:Lxf0/e1;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lxf0/e1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lxf0/e1;->e:Lxf0/e1;

    .line 8
    .line 9
    new-instance v0, Lxf0/e1;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lxf0/e1;->f:Lxf0/e1;

    .line 16
    .line 17
    new-instance v0, Lxf0/e1;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lxf0/e1;->g:Lxf0/e1;

    .line 24
    .line 25
    new-instance v0, Lxf0/e1;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lxf0/e1;->h:Lxf0/e1;

    .line 32
    .line 33
    new-instance v0, Lxf0/e1;

    .line 34
    .line 35
    const/4 v1, 0x4

    .line 36
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lxf0/e1;->i:Lxf0/e1;

    .line 40
    .line 41
    new-instance v0, Lxf0/e1;

    .line 42
    .line 43
    const/4 v1, 0x5

    .line 44
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lxf0/e1;->j:Lxf0/e1;

    .line 48
    .line 49
    new-instance v0, Lxf0/e1;

    .line 50
    .line 51
    const/4 v1, 0x6

    .line 52
    invoke-direct {v0, v1}, Lxf0/e1;-><init>(I)V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lxf0/e1;->k:Lxf0/e1;

    .line 56
    .line 57
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lxf0/e1;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lxf0/e1;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string p0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 14
    .line 15
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 16
    .line 17
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x6

    .line 21
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 25
    .line 26
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 27
    .line 28
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 32
    .line 33
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 34
    .line 35
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 39
    .line 40
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 41
    .line 42
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 43
    .line 44
    .line 45
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 49
    .line 50
    const-string p0, "$this$constrainAs"

    .line 51
    .line 52
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 56
    .line 57
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 58
    .line 59
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    const/4 v3, 0x6

    .line 63
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 67
    .line 68
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 69
    .line 70
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 74
    .line 75
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 76
    .line 77
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 81
    .line 82
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 83
    .line 84
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 85
    .line 86
    .line 87
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 91
    .line 92
    const-string p0, "$this$constrainAs"

    .line 93
    .line 94
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 98
    .line 99
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 100
    .line 101
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 102
    .line 103
    const/4 v2, 0x0

    .line 104
    const/4 v3, 0x6

    .line 105
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 106
    .line 107
    .line 108
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 109
    .line 110
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 111
    .line 112
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 113
    .line 114
    .line 115
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 116
    .line 117
    iget-object v1, v0, Lz4/f;->g:Lz4/g;

    .line 118
    .line 119
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 120
    .line 121
    .line 122
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 123
    .line 124
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 125
    .line 126
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 127
    .line 128
    .line 129
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_2
    check-cast p1, Lz4/e;

    .line 133
    .line 134
    const-string p0, "$this$constrainAs"

    .line 135
    .line 136
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 140
    .line 141
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 142
    .line 143
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 144
    .line 145
    const/4 v2, 0x0

    .line 146
    const/4 v3, 0x6

    .line 147
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 151
    .line 152
    iget-object v1, v0, Lz4/f;->g:Lz4/g;

    .line 153
    .line 154
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 155
    .line 156
    .line 157
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 158
    .line 159
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 160
    .line 161
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 162
    .line 163
    .line 164
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_3
    check-cast p1, Lz4/e;

    .line 168
    .line 169
    const-string p0, "$this$constrainAs"

    .line 170
    .line 171
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 175
    .line 176
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 177
    .line 178
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 179
    .line 180
    const/4 v2, 0x0

    .line 181
    const/4 v3, 0x6

    .line 182
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 183
    .line 184
    .line 185
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 186
    .line 187
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 188
    .line 189
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 190
    .line 191
    .line 192
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 193
    .line 194
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 195
    .line 196
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 197
    .line 198
    .line 199
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    return-object p0

    .line 202
    :pswitch_4
    check-cast p1, Lz4/e;

    .line 203
    .line 204
    const-string p0, "$this$constrainAs"

    .line 205
    .line 206
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 210
    .line 211
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 212
    .line 213
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 214
    .line 215
    const/4 v2, 0x0

    .line 216
    const/4 v3, 0x6

    .line 217
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 218
    .line 219
    .line 220
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 221
    .line 222
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 223
    .line 224
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 225
    .line 226
    .line 227
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 228
    .line 229
    iget-object p1, v0, Lz4/f;->g:Lz4/g;

    .line 230
    .line 231
    invoke-static {p0, p1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 232
    .line 233
    .line 234
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_5
    check-cast p1, Lz4/e;

    .line 238
    .line 239
    const-string p0, "$this$constrainAs"

    .line 240
    .line 241
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 245
    .line 246
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 247
    .line 248
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 249
    .line 250
    const/4 v2, 0x0

    .line 251
    const/4 v3, 0x6

    .line 252
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 253
    .line 254
    .line 255
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 256
    .line 257
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 258
    .line 259
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 260
    .line 261
    .line 262
    iget-object p0, p1, Lz4/e;->g:Ly41/a;

    .line 263
    .line 264
    iget-object v1, v0, Lz4/f;->g:Lz4/g;

    .line 265
    .line 266
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 267
    .line 268
    .line 269
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 270
    .line 271
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 272
    .line 273
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 274
    .line 275
    .line 276
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
