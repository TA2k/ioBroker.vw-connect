.class public final Lvv/w;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvv/w;->f:I

    iput-object p1, p0, Lvv/w;->g:Lt2/b;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Lt2/b;II)V
    .locals 0

    .line 2
    iput p3, p0, Lvv/w;->f:I

    iput-object p1, p0, Lvv/w;->g:Lt2/b;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lvv/w;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x7

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lwv/f;->b(Lt2/b;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 27
    .line 28
    check-cast p2, Ljava/lang/Number;

    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    and-int/lit8 p2, p2, 0xb

    .line 35
    .line 36
    const/4 v0, 0x2

    .line 37
    if-ne p2, v0, :cond_1

    .line 38
    .line 39
    move-object p2, p1

    .line 40
    check-cast p2, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-nez v0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    :goto_0
    sget-object p2, Lwv/f;->a:Ll2/e0;

    .line 54
    .line 55
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-virtual {p2, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    new-instance v0, Lvv/w;

    .line 62
    .line 63
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 64
    .line 65
    const/4 v1, 0x4

    .line 66
    invoke-direct {v0, p0, v1}, Lvv/w;-><init>(Lt2/b;I)V

    .line 67
    .line 68
    .line 69
    const p0, -0x499b2425

    .line 70
    .line 71
    .line 72
    invoke-static {p0, p1, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const/16 v0, 0x38

    .line 77
    .line 78
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 85
    .line 86
    check-cast p2, Ljava/lang/Number;

    .line 87
    .line 88
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    and-int/lit8 p2, p2, 0xb

    .line 93
    .line 94
    const/4 v0, 0x2

    .line 95
    if-ne p2, v0, :cond_3

    .line 96
    .line 97
    move-object p2, p1

    .line 98
    check-cast p2, Ll2/t;

    .line 99
    .line 100
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-nez v0, :cond_2

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_3
    :goto_2
    const/4 p2, 0x0

    .line 112
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 117
    .line 118
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object p0

    .line 124
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 125
    .line 126
    check-cast p2, Ljava/lang/Number;

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 129
    .line 130
    .line 131
    move-result p2

    .line 132
    and-int/lit8 p2, p2, 0xb

    .line 133
    .line 134
    const/4 v0, 0x2

    .line 135
    if-ne p2, v0, :cond_5

    .line 136
    .line 137
    move-object p2, p1

    .line 138
    check-cast p2, Ll2/t;

    .line 139
    .line 140
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    if-nez v0, :cond_4

    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_5
    :goto_4
    const/4 p2, 0x0

    .line 152
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object p2

    .line 156
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 157
    .line 158
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 165
    .line 166
    check-cast p2, Ljava/lang/Number;

    .line 167
    .line 168
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 169
    .line 170
    .line 171
    move-result p2

    .line 172
    and-int/lit8 p2, p2, 0xb

    .line 173
    .line 174
    const/4 v0, 0x2

    .line 175
    if-ne p2, v0, :cond_7

    .line 176
    .line 177
    move-object p2, p1

    .line 178
    check-cast p2, Ll2/t;

    .line 179
    .line 180
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-nez v0, :cond_6

    .line 185
    .line 186
    goto :goto_6

    .line 187
    :cond_6
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 188
    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_7
    :goto_6
    const/4 p2, 0x0

    .line 192
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object p2

    .line 196
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 197
    .line 198
    sget-object v0, Lvv/m0;->a:Lvv/m0;

    .line 199
    .line 200
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 207
    .line 208
    check-cast p2, Ljava/lang/Number;

    .line 209
    .line 210
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 211
    .line 212
    .line 213
    const/4 p2, 0x7

    .line 214
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 215
    .line 216
    .line 217
    move-result p2

    .line 218
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 219
    .line 220
    invoke-static {p0, p1, p2}, Lvv/x;->c(Lt2/b;Ll2/o;I)V

    .line 221
    .line 222
    .line 223
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 224
    .line 225
    return-object p0

    .line 226
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 227
    .line 228
    check-cast p2, Ljava/lang/Number;

    .line 229
    .line 230
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 231
    .line 232
    .line 233
    move-result p2

    .line 234
    and-int/lit8 p2, p2, 0xb

    .line 235
    .line 236
    const/4 v0, 0x2

    .line 237
    if-ne p2, v0, :cond_9

    .line 238
    .line 239
    move-object p2, p1

    .line 240
    check-cast p2, Ll2/t;

    .line 241
    .line 242
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 243
    .line 244
    .line 245
    move-result v0

    .line 246
    if-nez v0, :cond_8

    .line 247
    .line 248
    goto :goto_8

    .line 249
    :cond_8
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 250
    .line 251
    .line 252
    goto :goto_9

    .line 253
    :cond_9
    :goto_8
    const/4 p2, 0x0

    .line 254
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 255
    .line 256
    .line 257
    move-result-object p2

    .line 258
    iget-object p0, p0, Lvv/w;->g:Lt2/b;

    .line 259
    .line 260
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 264
    .line 265
    return-object p0

    .line 266
    nop

    .line 267
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
