.class public final synthetic Li40/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/q;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/q;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Li40/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/j;->e:Lh40/q;

    .line 4
    .line 5
    iput-object p2, p0, Li40/j;->f:Lay0/a;

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
    .locals 8

    .line 1
    iget v0, p0, Li40/j;->d:I

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
    move-object v6, p2

    .line 33
    check-cast v6, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v6, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 42
    .line 43
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    check-cast p2, Lj91/c;

    .line 48
    .line 49
    iget p2, p2, Lj91/c;->d:F

    .line 50
    .line 51
    const p3, 0x7f120c6d

    .line 52
    .line 53
    .line 54
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {v0, p2, v6, p3, v6}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    check-cast p1, Lj91/c;

    .line 65
    .line 66
    iget p1, p1, Lj91/c;->k:F

    .line 67
    .line 68
    const/4 p3, 0x0

    .line 69
    const/4 v1, 0x2

    .line 70
    invoke-static {v0, p1, p3, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    const p1, 0x7f080410

    .line 75
    .line 76
    .line 77
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    iget-object p1, p0, Li40/j;->e:Lh40/q;

    .line 82
    .line 83
    iget-object p3, p1, Lh40/q;->i:Ljava/util/List;

    .line 84
    .line 85
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 86
    .line 87
    .line 88
    move-result p3

    .line 89
    invoke-static {p3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    iget-boolean p1, p1, Lh40/q;->e:Z

    .line 94
    .line 95
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    const/4 v7, 0x0

    .line 100
    iget-object v5, p0, Li40/j;->f:Lay0/a;

    .line 101
    .line 102
    move-object v0, p2

    .line 103
    invoke-static/range {v0 .. v7}, Li40/l1;->g(Ljava/lang/String;Lx2/s;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Boolean;Lay0/a;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_1
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_0
    const-string v0, "$this$item"

    .line 114
    .line 115
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    and-int/lit8 p1, p3, 0x11

    .line 119
    .line 120
    const/16 v0, 0x10

    .line 121
    .line 122
    const/4 v1, 0x1

    .line 123
    if-eq p1, v0, :cond_2

    .line 124
    .line 125
    move p1, v1

    .line 126
    goto :goto_2

    .line 127
    :cond_2
    const/4 p1, 0x0

    .line 128
    :goto_2
    and-int/2addr p3, v1

    .line 129
    move-object v6, p2

    .line 130
    check-cast v6, Ll2/t;

    .line 131
    .line 132
    invoke-virtual {v6, p3, p1}, Ll2/t;->O(IZ)Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    if-eqz p1, :cond_3

    .line 137
    .line 138
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 139
    .line 140
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p2

    .line 144
    check-cast p2, Lj91/c;

    .line 145
    .line 146
    iget p2, p2, Lj91/c;->d:F

    .line 147
    .line 148
    const p3, 0x7f120c6b

    .line 149
    .line 150
    .line 151
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 152
    .line 153
    invoke-static {v0, p2, v6, p3, v6}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    check-cast p1, Lj91/c;

    .line 162
    .line 163
    iget p1, p1, Lj91/c;->k:F

    .line 164
    .line 165
    const/4 p3, 0x0

    .line 166
    const/4 v1, 0x2

    .line 167
    invoke-static {v0, p1, p3, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    const p1, 0x7f080342

    .line 172
    .line 173
    .line 174
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    iget-object p1, p0, Li40/j;->e:Lh40/q;

    .line 179
    .line 180
    iget-object p3, p1, Lh40/q;->j:Ljava/util/List;

    .line 181
    .line 182
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 183
    .line 184
    .line 185
    move-result p3

    .line 186
    invoke-static {p3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    iget-boolean p1, p1, Lh40/q;->f:Z

    .line 191
    .line 192
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    const/4 v7, 0x0

    .line 197
    iget-object v5, p0, Li40/j;->f:Lay0/a;

    .line 198
    .line 199
    move-object v0, p2

    .line 200
    invoke-static/range {v0 .. v7}, Li40/l1;->g(Ljava/lang/String;Lx2/s;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Boolean;Lay0/a;Ll2/o;I)V

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_3
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 205
    .line 206
    .line 207
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    return-object p0

    .line 210
    nop

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
