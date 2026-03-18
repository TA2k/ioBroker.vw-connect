.class public final synthetic Lxf0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F


# direct methods
.method public synthetic constructor <init>(IF)V
    .locals 0

    .line 1
    iput p1, p0, Lxf0/e0;->d:I

    .line 2
    .line 3
    iput p2, p0, Lxf0/e0;->e:F

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
    iget v0, p0, Lxf0/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lx2/s;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const-string p3, "$this$composed"

    .line 16
    .line 17
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    const p3, 0x771c9f38

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 26
    .line 27
    .line 28
    const p3, 0x2271b457

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    sget-object p3, Lw3/h1;->h:Ll2/u2;

    .line 35
    .line 36
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p3

    .line 40
    check-cast p3, Lt4/c;

    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    int-to-float v1, v0

    .line 44
    iget p0, p0, Lxf0/e0;->e:F

    .line 45
    .line 46
    invoke-static {p0, v1}, Lt4/f;->a(FF)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_0

    .line 51
    .line 52
    const p0, -0x46a99cd3

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 56
    .line 57
    .line 58
    sget-object p0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 59
    .line 60
    invoke-virtual {p2, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Landroid/content/res/Configuration;

    .line 65
    .line 66
    iget p0, p0, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 67
    .line 68
    int-to-float p0, p0

    .line 69
    invoke-interface {p3, p0}, Lt4/c;->w0(F)F

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_0
    const v1, -0x46a866f2

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 84
    .line 85
    .line 86
    invoke-interface {p3, p0}, Lt4/c;->w0(F)F

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    :goto_0
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 91
    .line 92
    .line 93
    sget-object p3, Lzb/l;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p3

    .line 99
    check-cast p3, Ll2/b1;

    .line 100
    .line 101
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    or-int/2addr v1, v2

    .line 110
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    if-nez v1, :cond_1

    .line 115
    .line 116
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 117
    .line 118
    if-ne v2, v1, :cond_2

    .line 119
    .line 120
    :cond_1
    new-instance v2, Lc1/u1;

    .line 121
    .line 122
    invoke-direct {v2, p0, p3}, Lc1/u1;-><init>(FLl2/b1;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_2
    check-cast v2, Lay0/k;

    .line 129
    .line 130
    invoke-static {p1, v2}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_0
    check-cast p1, Lb1/a0;

    .line 139
    .line 140
    check-cast p2, Ll2/o;

    .line 141
    .line 142
    check-cast p3, Ljava/lang/Integer;

    .line 143
    .line 144
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    const-string p3, "$this$AnimatedVisibility"

    .line 148
    .line 149
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    sget-object p1, Lj91/h;->a:Ll2/u2;

    .line 153
    .line 154
    move-object p3, p2

    .line 155
    check-cast p3, Ll2/t;

    .line 156
    .line 157
    invoke-virtual {p3, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    check-cast p1, Lj91/e;

    .line 162
    .line 163
    invoke-virtual {p1}, Lj91/e;->c()J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    const p1, 0x3f19999a    # 0.6f

    .line 168
    .line 169
    .line 170
    invoke-static {v0, v1, p1}, Le3/s;->b(JF)J

    .line 171
    .line 172
    .line 173
    move-result-wide v0

    .line 174
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 175
    .line 176
    const/high16 p3, 0x3f800000    # 1.0f

    .line 177
    .line 178
    invoke-static {p1, p3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    iget p0, p0, Lxf0/e0;->e:F

    .line 183
    .line 184
    invoke-static {p1, p0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    new-instance p1, Le3/s;

    .line 189
    .line 190
    invoke-direct {p1, v0, v1}, Le3/s;-><init>(J)V

    .line 191
    .line 192
    .line 193
    sget-wide v0, Le3/s;->h:J

    .line 194
    .line 195
    new-instance p3, Le3/s;

    .line 196
    .line 197
    invoke-direct {p3, v0, v1}, Le3/s;-><init>(J)V

    .line 198
    .line 199
    .line 200
    filled-new-array {p1, p3}, [Le3/s;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    const/4 p3, 0x0

    .line 209
    const/16 v0, 0xe

    .line 210
    .line 211
    invoke-static {p1, p3, p3, v0}, Lpy/a;->t(Ljava/util/List;FFI)Le3/b0;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    invoke-static {p0, p1}, Landroidx/compose/foundation/a;->a(Lx2/s;Le3/b0;)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    const/4 p1, 0x0

    .line 220
    invoke-static {p0, p2, p1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 221
    .line 222
    .line 223
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 224
    .line 225
    return-object p0

    .line 226
    nop

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
