.class public final synthetic Lb60/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb60/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb60/e;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p2, p0, Lb60/e;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lb60/e;->d:I

    .line 2
    .line 3
    check-cast p1, Lm1/f;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$LazyColumn"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lb60/e;->e:Ljava/util/List;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    new-instance v2, Lnu0/c;

    .line 20
    .line 21
    const/16 v3, 0xc

    .line 22
    .line 23
    invoke-direct {v2, v0, v3}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lak/q;

    .line 27
    .line 28
    const/16 v4, 0xb

    .line 29
    .line 30
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 31
    .line 32
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 33
    .line 34
    .line 35
    new-instance p0, Lt2/b;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    const v4, 0x2fd4df92

    .line 39
    .line 40
    .line 41
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 42
    .line 43
    .line 44
    const/4 v0, 0x0

    .line 45
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    const-string v0, "$this$LazyColumn"

    .line 52
    .line 53
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lb60/e;->e:Ljava/util/List;

    .line 57
    .line 58
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    new-instance v2, Lnu0/c;

    .line 63
    .line 64
    const/16 v3, 0x8

    .line 65
    .line 66
    invoke-direct {v2, v0, v3}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 67
    .line 68
    .line 69
    new-instance v3, Lb60/g;

    .line 70
    .line 71
    const/4 v4, 0x1

    .line 72
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 73
    .line 74
    invoke-direct {v3, v4, p0, v0, v0}, Lb60/g;-><init>(ILay0/k;Ljava/util/List;Ljava/util/List;)V

    .line 75
    .line 76
    .line 77
    new-instance p0, Lt2/b;

    .line 78
    .line 79
    const/4 v0, 0x1

    .line 80
    const v4, 0x799532c4

    .line 81
    .line 82
    .line 83
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 84
    .line 85
    .line 86
    const/4 v0, 0x0

    .line 87
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :pswitch_1
    const-string v0, "$this$LazyColumn"

    .line 92
    .line 93
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    iget-object v0, p0, Lb60/e;->e:Ljava/util/List;

    .line 97
    .line 98
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    new-instance v2, Lak/p;

    .line 103
    .line 104
    const/16 v3, 0x1b

    .line 105
    .line 106
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 107
    .line 108
    .line 109
    new-instance v3, Lak/q;

    .line 110
    .line 111
    const/4 v4, 0x6

    .line 112
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 113
    .line 114
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 115
    .line 116
    .line 117
    new-instance p0, Lt2/b;

    .line 118
    .line 119
    const/4 v0, 0x1

    .line 120
    const v4, 0x799532c4

    .line 121
    .line 122
    .line 123
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 124
    .line 125
    .line 126
    const/4 v0, 0x0

    .line 127
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 128
    .line 129
    .line 130
    goto :goto_0

    .line 131
    :pswitch_2
    const-string v0, "$this$LazyColumn"

    .line 132
    .line 133
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    iget-object v0, p0, Lb60/e;->e:Ljava/util/List;

    .line 137
    .line 138
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    new-instance v2, Lak/p;

    .line 143
    .line 144
    const/16 v3, 0x9

    .line 145
    .line 146
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 147
    .line 148
    .line 149
    new-instance v3, Lak/q;

    .line 150
    .line 151
    const/4 v4, 0x3

    .line 152
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 153
    .line 154
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 155
    .line 156
    .line 157
    new-instance p0, Lt2/b;

    .line 158
    .line 159
    const/4 v0, 0x1

    .line 160
    const v4, 0x2fd4df92

    .line 161
    .line 162
    .line 163
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 164
    .line 165
    .line 166
    const/4 v0, 0x0

    .line 167
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 168
    .line 169
    .line 170
    goto :goto_0

    .line 171
    :pswitch_3
    const-string v0, "$this$LazyRow"

    .line 172
    .line 173
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    new-instance v0, Lc1/c2;

    .line 177
    .line 178
    const/16 v1, 0x12

    .line 179
    .line 180
    invoke-direct {v0, v1}, Lc1/c2;-><init>(I)V

    .line 181
    .line 182
    .line 183
    iget-object v1, p0, Lb60/e;->e:Ljava/util/List;

    .line 184
    .line 185
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    new-instance v3, Lc41/g;

    .line 190
    .line 191
    const/4 v4, 0x0

    .line 192
    invoke-direct {v3, v4, v0, v1}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    new-instance v0, Lak/p;

    .line 196
    .line 197
    const/4 v4, 0x3

    .line 198
    invoke-direct {v0, v1, v4}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 199
    .line 200
    .line 201
    new-instance v4, Lak/q;

    .line 202
    .line 203
    const/4 v5, 0x1

    .line 204
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 205
    .line 206
    invoke-direct {v4, v1, p0, v5}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 207
    .line 208
    .line 209
    new-instance p0, Lt2/b;

    .line 210
    .line 211
    const/4 v1, 0x1

    .line 212
    const v5, 0x2fd4df92

    .line 213
    .line 214
    .line 215
    invoke-direct {p0, v4, v1, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {p1, v2, v3, v0, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_0

    .line 222
    .line 223
    :pswitch_4
    const-string v0, "$this$LazyColumn"

    .line 224
    .line 225
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    iget-object v0, p0, Lb60/e;->e:Ljava/util/List;

    .line 229
    .line 230
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 231
    .line 232
    .line 233
    move-result v1

    .line 234
    new-instance v2, Lak/p;

    .line 235
    .line 236
    const/4 v3, 0x1

    .line 237
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 238
    .line 239
    .line 240
    new-instance v3, Lb60/g;

    .line 241
    .line 242
    const/4 v4, 0x0

    .line 243
    iget-object p0, p0, Lb60/e;->f:Lay0/k;

    .line 244
    .line 245
    invoke-direct {v3, v4, p0, v0, v0}, Lb60/g;-><init>(ILay0/k;Ljava/util/List;Ljava/util/List;)V

    .line 246
    .line 247
    .line 248
    new-instance p0, Lt2/b;

    .line 249
    .line 250
    const/4 v0, 0x1

    .line 251
    const v4, 0x799532c4

    .line 252
    .line 253
    .line 254
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 255
    .line 256
    .line 257
    const/4 v0, 0x0

    .line 258
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 259
    .line 260
    .line 261
    goto/16 :goto_0

    .line 262
    .line 263
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
