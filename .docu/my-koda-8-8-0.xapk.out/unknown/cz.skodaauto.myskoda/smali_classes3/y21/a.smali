.class public final synthetic Ly21/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz21/g;


# direct methods
.method public synthetic constructor <init>(Lz21/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly21/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly21/a;->e:Lz21/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ly21/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const-string p4, "$this$composable"

    .line 15
    .line 16
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string p1, "it"

    .line 20
    .line 21
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    packed-switch v0, :pswitch_data_0

    .line 25
    .line 26
    .line 27
    new-instance p1, Ly21/b;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 31
    .line 32
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 33
    .line 34
    .line 35
    const p0, 0x12739efe

    .line 36
    .line 37
    .line 38
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const/16 p1, 0x30

    .line 43
    .line 44
    const/4 p2, 0x0

    .line 45
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

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
    new-instance p1, Ly21/b;

    .line 52
    .line 53
    const/16 p2, 0x8

    .line 54
    .line 55
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 56
    .line 57
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 58
    .line 59
    .line 60
    const p0, 0x24901e7d

    .line 61
    .line 62
    .line 63
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const/16 p1, 0x30

    .line 68
    .line 69
    const/4 p2, 0x0

    .line 70
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    new-instance p1, Ly21/b;

    .line 75
    .line 76
    const/4 p2, 0x2

    .line 77
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 78
    .line 79
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 80
    .line 81
    .line 82
    const p0, 0x48c91d7b

    .line 83
    .line 84
    .line 85
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    const/16 p1, 0x30

    .line 90
    .line 91
    const/4 p2, 0x0

    .line 92
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :pswitch_2
    new-instance p1, Ly21/b;

    .line 97
    .line 98
    const/16 p2, 0x9

    .line 99
    .line 100
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 101
    .line 102
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 103
    .line 104
    .line 105
    const p0, 0x5ae59cfa

    .line 106
    .line 107
    .line 108
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    const/16 p1, 0x30

    .line 113
    .line 114
    const/4 p2, 0x0

    .line 115
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 116
    .line 117
    .line 118
    goto :goto_0

    .line 119
    :pswitch_3
    new-instance p1, Ly21/b;

    .line 120
    .line 121
    const/4 p2, 0x4

    .line 122
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 123
    .line 124
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 125
    .line 126
    .line 127
    const p0, -0x67327229

    .line 128
    .line 129
    .line 130
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    const/16 p1, 0x30

    .line 135
    .line 136
    const/4 p2, 0x0

    .line 137
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :pswitch_4
    new-instance p1, Ly21/b;

    .line 142
    .line 143
    const/4 p2, 0x7

    .line 144
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 145
    .line 146
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 147
    .line 148
    .line 149
    const p0, -0x5515f2aa

    .line 150
    .line 151
    .line 152
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    const/16 p1, 0x30

    .line 157
    .line 158
    const/4 p2, 0x0

    .line 159
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    goto :goto_0

    .line 163
    :pswitch_5
    new-instance p1, Ly21/b;

    .line 164
    .line 165
    const/4 p2, 0x6

    .line 166
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 167
    .line 168
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 169
    .line 170
    .line 171
    const p0, 0x73abd303

    .line 172
    .line 173
    .line 174
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    const/16 p1, 0x30

    .line 179
    .line 180
    const/4 p2, 0x0

    .line 181
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 182
    .line 183
    .line 184
    goto/16 :goto_0

    .line 185
    .line 186
    :pswitch_6
    new-instance p1, Ly21/b;

    .line 187
    .line 188
    const/4 p2, 0x1

    .line 189
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 190
    .line 191
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 192
    .line 193
    .line 194
    const p0, -0x35fe5efe

    .line 195
    .line 196
    .line 197
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    const/16 p1, 0x30

    .line 202
    .line 203
    const/4 p2, 0x0

    .line 204
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 205
    .line 206
    .line 207
    goto/16 :goto_0

    .line 208
    .line 209
    :pswitch_7
    new-instance p1, Ly21/b;

    .line 210
    .line 211
    const/4 p2, 0x5

    .line 212
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 213
    .line 214
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 215
    .line 216
    .line 217
    const p0, -0x23e1df7f

    .line 218
    .line 219
    .line 220
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    const/16 p1, 0x30

    .line 225
    .line 226
    const/4 p2, 0x0

    .line 227
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 228
    .line 229
    .line 230
    goto/16 :goto_0

    .line 231
    .line 232
    :pswitch_8
    new-instance p1, Ly21/b;

    .line 233
    .line 234
    const/4 p2, 0x3

    .line 235
    iget-object p0, p0, Ly21/a;->e:Lz21/g;

    .line 236
    .line 237
    invoke-direct {p1, p0, p2}, Ly21/b;-><init>(Lz21/g;I)V

    .line 238
    .line 239
    .line 240
    const p0, 0x571f7f    # 8.000987E-39f

    .line 241
    .line 242
    .line 243
    invoke-static {p0, p3, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    const/16 p1, 0x30

    .line 248
    .line 249
    const/4 p2, 0x0

    .line 250
    invoke-static {p2, p0, p3, p1}, Lkp/m8;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    goto/16 :goto_0

    .line 254
    .line 255
    :pswitch_data_0
    .packed-switch 0x0
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
