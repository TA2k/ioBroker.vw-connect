.class public final synthetic Lb71/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p1, p0, Lb71/f;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lb71/f;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lb71/f;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lb71/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/t;

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
    const-string v0, "$this$RpaScaffold"

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
    const/16 p1, 0x186

    .line 41
    .line 42
    iget-object p3, p0, Lb71/f;->e:Ljava/lang/String;

    .line 43
    .line 44
    iget-object p0, p0, Lb71/f;->f:Lay0/a;

    .line 45
    .line 46
    invoke-static {p3, p0, p2, p1}, Lz61/a;->f(Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_0
    const-string v0, "$this$RpaScaffold"

    .line 57
    .line 58
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    and-int/lit8 p1, p3, 0x11

    .line 62
    .line 63
    const/16 v0, 0x10

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    const/4 v2, 0x1

    .line 67
    if-eq p1, v0, :cond_2

    .line 68
    .line 69
    move p1, v2

    .line 70
    goto :goto_2

    .line 71
    :cond_2
    move p1, v1

    .line 72
    :goto_2
    and-int/2addr p3, v2

    .line 73
    move-object v9, p2

    .line 74
    check-cast v9, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {v9, p3, p1}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    if-eqz p1, :cond_6

    .line 81
    .line 82
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 83
    .line 84
    const/high16 p2, 0x3f800000    # 1.0f

    .line 85
    .line 86
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 87
    .line 88
    .line 89
    move-result-object p3

    .line 90
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 91
    .line 92
    invoke-static {v0, v1}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    iget-wide v3, v9, Ll2/t;->T:J

    .line 97
    .line 98
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    invoke-static {v9, p3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object p3

    .line 110
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 111
    .line 112
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 116
    .line 117
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 118
    .line 119
    .line 120
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 121
    .line 122
    if-eqz v5, :cond_3

    .line 123
    .line 124
    invoke-virtual {v9, v4}, Ll2/t;->l(Lay0/a;)V

    .line 125
    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_3
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 129
    .line 130
    .line 131
    :goto_3
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 132
    .line 133
    invoke-static {v4, v0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 137
    .line 138
    invoke-static {v0, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 142
    .line 143
    iget-boolean v3, v9, Ll2/t;->S:Z

    .line 144
    .line 145
    if-nez v3, :cond_4

    .line 146
    .line 147
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    if-nez v3, :cond_5

    .line 160
    .line 161
    :cond_4
    invoke-static {v1, v9, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 162
    .line 163
    .line 164
    :cond_5
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 165
    .line 166
    invoke-static {v0, p3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    sget-object p2, Lh71/u;->a:Ll2/u2;

    .line 174
    .line 175
    invoke-virtual {v9, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p3

    .line 179
    check-cast p3, Lh71/t;

    .line 180
    .line 181
    iget p3, p3, Lh71/t;->e:F

    .line 182
    .line 183
    const/4 v0, 0x2

    .line 184
    const/4 v1, 0x0

    .line 185
    invoke-static {p1, p3, v1, v0}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    invoke-virtual {v9, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    check-cast p1, Lh71/t;

    .line 194
    .line 195
    iget v7, p1, Lh71/t;->g:F

    .line 196
    .line 197
    const/4 v8, 0x7

    .line 198
    const/4 v4, 0x0

    .line 199
    const/4 v5, 0x0

    .line 200
    const/4 v6, 0x0

    .line 201
    invoke-static/range {v3 .. v8}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    sget-object p1, Lh71/m;->a:Ll2/u2;

    .line 206
    .line 207
    invoke-virtual {v9, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    check-cast p1, Lh71/l;

    .line 212
    .line 213
    iget-object p1, p1, Lh71/l;->c:Lh71/f;

    .line 214
    .line 215
    iget-object v6, p1, Lh71/f;->b:Lh71/w;

    .line 216
    .line 217
    const/4 v10, 0x0

    .line 218
    const/16 v11, 0x2a

    .line 219
    .line 220
    iget-object v4, p0, Lb71/f;->e:Ljava/lang/String;

    .line 221
    .line 222
    const/4 v5, 0x0

    .line 223
    const/4 v7, 0x0

    .line 224
    iget-object v8, p0, Lb71/f;->f:Lay0/a;

    .line 225
    .line 226
    invoke-static/range {v3 .. v11}, Lkp/h0;->a(Lx2/s;Ljava/lang/String;ZLh71/w;Le71/a;Lay0/a;Ll2/o;II)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    goto :goto_4

    .line 233
    :cond_6
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 234
    .line 235
    .line 236
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
