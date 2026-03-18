.class public final Ly1/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# static fields
.field public static final e:Ly1/g;

.field public static final f:Ly1/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ly1/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ly1/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ly1/g;->e:Ly1/g;

    .line 8
    .line 9
    new-instance v0, Ly1/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Ly1/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Ly1/g;->f:Ly1/g;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ly1/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Ly1/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lw1/g;

    .line 7
    .line 8
    check-cast p2, La2/k;

    .line 9
    .line 10
    check-cast p3, Lay0/a;

    .line 11
    .line 12
    check-cast p4, Ll2/o;

    .line 13
    .line 14
    check-cast p5, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p5}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    and-int/lit8 p5, p0, 0x6

    .line 21
    .line 22
    if-nez p5, :cond_2

    .line 23
    .line 24
    and-int/lit8 p5, p0, 0x8

    .line 25
    .line 26
    if-nez p5, :cond_0

    .line 27
    .line 28
    move-object p5, p4

    .line 29
    check-cast p5, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {p5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p5

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object p5, p4

    .line 37
    check-cast p5, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {p5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p5

    .line 43
    :goto_0
    if-eqz p5, :cond_1

    .line 44
    .line 45
    const/4 p5, 0x4

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/4 p5, 0x2

    .line 48
    :goto_1
    or-int/2addr p5, p0

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move p5, p0

    .line 51
    :goto_2
    and-int/lit8 v0, p0, 0x30

    .line 52
    .line 53
    if-nez v0, :cond_5

    .line 54
    .line 55
    and-int/lit8 v0, p0, 0x40

    .line 56
    .line 57
    if-nez v0, :cond_3

    .line 58
    .line 59
    move-object v0, p4

    .line 60
    check-cast v0, Ll2/t;

    .line 61
    .line 62
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    move-object v0, p4

    .line 68
    check-cast v0, Ll2/t;

    .line 69
    .line 70
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    :goto_3
    if-eqz v0, :cond_4

    .line 75
    .line 76
    const/16 v0, 0x20

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/16 v0, 0x10

    .line 80
    .line 81
    :goto_4
    or-int/2addr p5, v0

    .line 82
    :cond_5
    and-int/lit16 p0, p0, 0x180

    .line 83
    .line 84
    if-nez p0, :cond_7

    .line 85
    .line 86
    move-object p0, p4

    .line 87
    check-cast p0, Ll2/t;

    .line 88
    .line 89
    invoke-virtual {p0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_6

    .line 94
    .line 95
    const/16 p0, 0x100

    .line 96
    .line 97
    goto :goto_5

    .line 98
    :cond_6
    const/16 p0, 0x80

    .line 99
    .line 100
    :goto_5
    or-int/2addr p5, p0

    .line 101
    :cond_7
    and-int/lit16 p0, p5, 0x493

    .line 102
    .line 103
    const/16 v0, 0x492

    .line 104
    .line 105
    if-eq p0, v0, :cond_8

    .line 106
    .line 107
    const/4 p0, 0x1

    .line 108
    goto :goto_6

    .line 109
    :cond_8
    const/4 p0, 0x0

    .line 110
    :goto_6
    and-int/lit8 v0, p5, 0x1

    .line 111
    .line 112
    check-cast p4, Ll2/t;

    .line 113
    .line 114
    invoke-virtual {p4, v0, p0}, Ll2/t;->O(IZ)Z

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    if-eqz p0, :cond_9

    .line 119
    .line 120
    and-int/lit16 p0, p5, 0x3fe

    .line 121
    .line 122
    invoke-static {p1, p2, p3, p4, p0}, Ly1/k;->c(Lw1/g;La2/k;Lay0/a;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    goto :goto_7

    .line 126
    :cond_9
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 127
    .line 128
    .line 129
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_0
    check-cast p1, Lw1/g;

    .line 133
    .line 134
    check-cast p2, La2/k;

    .line 135
    .line 136
    check-cast p3, Lay0/a;

    .line 137
    .line 138
    check-cast p4, Ll2/o;

    .line 139
    .line 140
    check-cast p5, Ljava/lang/Number;

    .line 141
    .line 142
    invoke-virtual {p5}, Ljava/lang/Number;->intValue()I

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    and-int/lit8 p5, p0, 0x6

    .line 147
    .line 148
    if-nez p5, :cond_c

    .line 149
    .line 150
    and-int/lit8 p5, p0, 0x8

    .line 151
    .line 152
    if-nez p5, :cond_a

    .line 153
    .line 154
    move-object p5, p4

    .line 155
    check-cast p5, Ll2/t;

    .line 156
    .line 157
    invoke-virtual {p5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result p5

    .line 161
    goto :goto_8

    .line 162
    :cond_a
    move-object p5, p4

    .line 163
    check-cast p5, Ll2/t;

    .line 164
    .line 165
    invoke-virtual {p5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result p5

    .line 169
    :goto_8
    if-eqz p5, :cond_b

    .line 170
    .line 171
    const/4 p5, 0x4

    .line 172
    goto :goto_9

    .line 173
    :cond_b
    const/4 p5, 0x2

    .line 174
    :goto_9
    or-int/2addr p5, p0

    .line 175
    goto :goto_a

    .line 176
    :cond_c
    move p5, p0

    .line 177
    :goto_a
    and-int/lit8 v0, p0, 0x30

    .line 178
    .line 179
    if-nez v0, :cond_f

    .line 180
    .line 181
    and-int/lit8 v0, p0, 0x40

    .line 182
    .line 183
    if-nez v0, :cond_d

    .line 184
    .line 185
    move-object v0, p4

    .line 186
    check-cast v0, Ll2/t;

    .line 187
    .line 188
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v0

    .line 192
    goto :goto_b

    .line 193
    :cond_d
    move-object v0, p4

    .line 194
    check-cast v0, Ll2/t;

    .line 195
    .line 196
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    :goto_b
    if-eqz v0, :cond_e

    .line 201
    .line 202
    const/16 v0, 0x20

    .line 203
    .line 204
    goto :goto_c

    .line 205
    :cond_e
    const/16 v0, 0x10

    .line 206
    .line 207
    :goto_c
    or-int/2addr p5, v0

    .line 208
    :cond_f
    and-int/lit16 p0, p0, 0x180

    .line 209
    .line 210
    if-nez p0, :cond_11

    .line 211
    .line 212
    move-object p0, p4

    .line 213
    check-cast p0, Ll2/t;

    .line 214
    .line 215
    invoke-virtual {p0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result p0

    .line 219
    if-eqz p0, :cond_10

    .line 220
    .line 221
    const/16 p0, 0x100

    .line 222
    .line 223
    goto :goto_d

    .line 224
    :cond_10
    const/16 p0, 0x80

    .line 225
    .line 226
    :goto_d
    or-int/2addr p5, p0

    .line 227
    :cond_11
    and-int/lit16 p0, p5, 0x493

    .line 228
    .line 229
    const/16 v0, 0x492

    .line 230
    .line 231
    if-eq p0, v0, :cond_12

    .line 232
    .line 233
    const/4 p0, 0x1

    .line 234
    goto :goto_e

    .line 235
    :cond_12
    const/4 p0, 0x0

    .line 236
    :goto_e
    and-int/lit8 v0, p5, 0x1

    .line 237
    .line 238
    check-cast p4, Ll2/t;

    .line 239
    .line 240
    invoke-virtual {p4, v0, p0}, Ll2/t;->O(IZ)Z

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    if-eqz p0, :cond_13

    .line 245
    .line 246
    and-int/lit16 p0, p5, 0x3fe

    .line 247
    .line 248
    invoke-static {p1, p2, p3, p4, p0}, Ly1/k;->c(Lw1/g;La2/k;Lay0/a;Ll2/o;I)V

    .line 249
    .line 250
    .line 251
    goto :goto_f

    .line 252
    :cond_13
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 253
    .line 254
    .line 255
    :goto_f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 256
    .line 257
    return-object p0

    .line 258
    nop

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
