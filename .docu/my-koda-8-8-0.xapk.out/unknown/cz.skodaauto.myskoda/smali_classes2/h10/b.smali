.class public final synthetic Lh10/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lg10/d;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lg10/d;Lay0/a;Lay0/k;Lay0/k;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh10/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh10/b;->e:Lg10/d;

    iput-object p2, p0, Lh10/b;->f:Lay0/a;

    iput-object p3, p0, Lh10/b;->g:Lay0/k;

    iput-object p4, p0, Lh10/b;->h:Lay0/k;

    iput-object p5, p0, Lh10/b;->i:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lg10/d;Lay0/a;Lay0/k;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p6, 0x0

    iput p6, p0, Lh10/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh10/b;->e:Lg10/d;

    iput-object p2, p0, Lh10/b;->f:Lay0/a;

    iput-object p3, p0, Lh10/b;->g:Lay0/k;

    iput-object p4, p0, Lh10/b;->h:Lay0/k;

    iput-object p5, p0, Lh10/b;->i:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lh10/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x2

    .line 19
    if-eq v0, v3, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v1

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    move-object v9, p1

    .line 26
    check-cast v9, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_5

    .line 33
    .line 34
    sget-object p1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 35
    .line 36
    sget-object p2, Lj91/a;->a:Ll2/u2;

    .line 37
    .line 38
    invoke-virtual {v9, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    check-cast p2, Lj91/c;

    .line 43
    .line 44
    iget p2, p2, Lj91/c;->j:F

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-static {p1, p2, v0, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 52
    .line 53
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 54
    .line 55
    invoke-static {v0, v4, v9, v1}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    iget-wide v4, v9, Ll2/t;->T:J

    .line 60
    .line 61
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-static {v9, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 74
    .line 75
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 79
    .line 80
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v7, v9, Ll2/t;->S:Z

    .line 84
    .line 85
    if-eqz v7, :cond_1

    .line 86
    .line 87
    invoke-virtual {v9, v6}, Ll2/t;->l(Lay0/a;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_1
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 92
    .line 93
    .line 94
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 95
    .line 96
    invoke-static {v6, v0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 100
    .line 101
    invoke-static {v0, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 105
    .line 106
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 107
    .line 108
    if-nez v5, :cond_2

    .line 109
    .line 110
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v6

    .line 118
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    if-nez v5, :cond_3

    .line 123
    .line 124
    :cond_2
    invoke-static {v4, v9, v4, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 125
    .line 126
    .line 127
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 128
    .line 129
    invoke-static {v0, p2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    iget-object v4, p0, Lh10/b;->e:Lg10/d;

    .line 133
    .line 134
    iget-boolean p2, v4, Lg10/d;->d:Z

    .line 135
    .line 136
    if-eqz p2, :cond_4

    .line 137
    .line 138
    const p0, 0x381240aa

    .line 139
    .line 140
    .line 141
    invoke-virtual {v9, p0}, Ll2/t;->Y(I)V

    .line 142
    .line 143
    .line 144
    const/4 p0, 0x6

    .line 145
    invoke-static {p0, v3, v9, p1, v1}, Lxf0/i0;->j(IILl2/o;Lx2/s;Z)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v9, v1}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_4
    const p1, 0x3813e232

    .line 153
    .line 154
    .line 155
    invoke-virtual {v9, p1}, Ll2/t;->Y(I)V

    .line 156
    .line 157
    .line 158
    const/4 v10, 0x0

    .line 159
    iget-object v5, p0, Lh10/b;->f:Lay0/a;

    .line 160
    .line 161
    iget-object v6, p0, Lh10/b;->g:Lay0/k;

    .line 162
    .line 163
    iget-object v7, p0, Lh10/b;->h:Lay0/k;

    .line 164
    .line 165
    iget-object v8, p0, Lh10/b;->i:Lay0/k;

    .line 166
    .line 167
    invoke-static/range {v4 .. v10}, Lh10/a;->a(Lg10/d;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v9, v1}, Ll2/t;->q(Z)V

    .line 171
    .line 172
    .line 173
    :goto_2
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 174
    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_5
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 178
    .line 179
    .line 180
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_0
    move-object v5, p1

    .line 184
    check-cast v5, Ll2/o;

    .line 185
    .line 186
    check-cast p2, Ljava/lang/Integer;

    .line 187
    .line 188
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    const/4 p1, 0x1

    .line 192
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 193
    .line 194
    .line 195
    move-result v6

    .line 196
    iget-object v0, p0, Lh10/b;->e:Lg10/d;

    .line 197
    .line 198
    iget-object v1, p0, Lh10/b;->f:Lay0/a;

    .line 199
    .line 200
    iget-object v2, p0, Lh10/b;->g:Lay0/k;

    .line 201
    .line 202
    iget-object v3, p0, Lh10/b;->h:Lay0/k;

    .line 203
    .line 204
    iget-object v4, p0, Lh10/b;->i:Lay0/k;

    .line 205
    .line 206
    invoke-static/range {v0 .. v6}, Lh10/a;->a(Lg10/d;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 207
    .line 208
    .line 209
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    return-object p0

    .line 212
    nop

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
