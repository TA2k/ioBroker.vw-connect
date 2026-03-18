.class public final synthetic Lqv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lpv0/f;


# direct methods
.method public synthetic constructor <init>(Lpv0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lqv0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqv0/c;->e:Lpv0/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lqv0/c;->d:I

    .line 2
    .line 3
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$item"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    check-cast p2, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 41
    .line 42
    const/high16 p3, 0x3f800000    # 1.0f

    .line 43
    .line 44
    invoke-static {p1, p3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget-object p0, p0, Lqv0/c;->e:Lpv0/f;

    .line 49
    .line 50
    iget-boolean p0, p0, Lpv0/f;->a:Z

    .line 51
    .line 52
    const/4 p3, 0x6

    .line 53
    invoke-static {p3, p2, p1, p0}, Ls80/a;->f(ILl2/o;Lx2/s;Z)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 58
    .line 59
    .line 60
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_0
    const-string v0, "$this$item"

    .line 64
    .line 65
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    and-int/lit8 p1, p3, 0x11

    .line 69
    .line 70
    const/16 v0, 0x10

    .line 71
    .line 72
    const/4 v1, 0x0

    .line 73
    const/4 v2, 0x1

    .line 74
    if-eq p1, v0, :cond_2

    .line 75
    .line 76
    move p1, v2

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    move p1, v1

    .line 79
    :goto_2
    and-int/2addr p3, v2

    .line 80
    check-cast p2, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_5

    .line 87
    .line 88
    iget-object p0, p0, Lqv0/c;->e:Lpv0/f;

    .line 89
    .line 90
    iget-boolean p1, p0, Lpv0/f;->b:Z

    .line 91
    .line 92
    if-nez p1, :cond_4

    .line 93
    .line 94
    iget-boolean p0, p0, Lpv0/f;->a:Z

    .line 95
    .line 96
    if-eqz p0, :cond_3

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_3
    move v2, v1

    .line 100
    :cond_4
    :goto_3
    const/4 p0, 0x0

    .line 101
    invoke-static {v1, p2, p0, v2}, Lf30/a;->g(ILl2/o;Lx2/s;Z)V

    .line 102
    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 106
    .line 107
    .line 108
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_1
    const-string v0, "$this$item"

    .line 112
    .line 113
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    and-int/lit8 p1, p3, 0x11

    .line 117
    .line 118
    const/16 v0, 0x10

    .line 119
    .line 120
    const/4 v1, 0x1

    .line 121
    const/4 v2, 0x0

    .line 122
    if-eq p1, v0, :cond_6

    .line 123
    .line 124
    move p1, v1

    .line 125
    goto :goto_5

    .line 126
    :cond_6
    move p1, v2

    .line 127
    :goto_5
    and-int/2addr p3, v1

    .line 128
    check-cast p2, Ll2/t;

    .line 129
    .line 130
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    if-eqz p1, :cond_8

    .line 135
    .line 136
    iget-object p0, p0, Lqv0/c;->e:Lpv0/f;

    .line 137
    .line 138
    iget-boolean p0, p0, Lpv0/f;->d:Z

    .line 139
    .line 140
    const/high16 p1, 0x3f800000    # 1.0f

    .line 141
    .line 142
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 143
    .line 144
    const/4 v0, 0x6

    .line 145
    if-eqz p0, :cond_7

    .line 146
    .line 147
    const p0, -0x1ac74b74

    .line 148
    .line 149
    .line 150
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 151
    .line 152
    .line 153
    invoke-static {p3, p1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-static {p0, p2, v0}, Li40/l1;->F(Lx2/s;Ll2/o;I)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {p2, v2}, Ll2/t;->q(Z)V

    .line 161
    .line 162
    .line 163
    goto :goto_6

    .line 164
    :cond_7
    const p0, -0x1ac5a970

    .line 165
    .line 166
    .line 167
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    invoke-static {p3, p1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    invoke-static {p0, p2, v0}, Llp/fg;->a(Lx2/s;Ll2/o;I)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {p2, v2}, Ll2/t;->q(Z)V

    .line 178
    .line 179
    .line 180
    :goto_6
    sget-object p0, Lj91/a;->a:Ll2/u2;

    .line 181
    .line 182
    invoke-virtual {p2, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    check-cast p0, Lj91/c;

    .line 187
    .line 188
    iget p0, p0, Lj91/c;->c:F

    .line 189
    .line 190
    invoke-static {p3, p0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-static {p2, p0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 195
    .line 196
    .line 197
    goto :goto_7

    .line 198
    :cond_8
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    return-object p0

    .line 204
    :pswitch_2
    const-string v0, "$this$item"

    .line 205
    .line 206
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    and-int/lit8 p1, p3, 0x11

    .line 210
    .line 211
    const/16 v0, 0x10

    .line 212
    .line 213
    const/4 v1, 0x1

    .line 214
    if-eq p1, v0, :cond_9

    .line 215
    .line 216
    move p1, v1

    .line 217
    goto :goto_8

    .line 218
    :cond_9
    const/4 p1, 0x0

    .line 219
    :goto_8
    and-int/2addr p3, v1

    .line 220
    check-cast p2, Ll2/t;

    .line 221
    .line 222
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 223
    .line 224
    .line 225
    move-result p1

    .line 226
    if-eqz p1, :cond_a

    .line 227
    .line 228
    const p1, 0x7f1211f1

    .line 229
    .line 230
    .line 231
    invoke-static {p2, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    iget-object p0, p0, Lqv0/c;->e:Lpv0/f;

    .line 236
    .line 237
    iget-object p0, p0, Lpv0/f;->g:Ljava/lang/String;

    .line 238
    .line 239
    const-string p3, "settings_general_item_app_version"

    .line 240
    .line 241
    const/16 v0, 0x180

    .line 242
    .line 243
    invoke-static {p1, p0, p3, p2, v0}, Lqv0/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 244
    .line 245
    .line 246
    goto :goto_9

    .line 247
    :cond_a
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 248
    .line 249
    .line 250
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 251
    .line 252
    return-object p0

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
