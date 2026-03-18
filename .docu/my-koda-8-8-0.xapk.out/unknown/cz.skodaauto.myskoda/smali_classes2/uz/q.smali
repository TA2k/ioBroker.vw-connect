.class public final Luz/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:I

.field public final synthetic f:Ltz/x0;

.field public final synthetic g:Ltz/z0;


# direct methods
.method public constructor <init>(Ljava/util/List;ILtz/x0;Ltz/z0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luz/q;->d:Ljava/util/List;

    .line 5
    .line 6
    iput p2, p0, Luz/q;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Luz/q;->f:Ltz/x0;

    .line 9
    .line 10
    iput-object p4, p0, Luz/q;->g:Ltz/z0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Ll2/o;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p4

    .line 17
    and-int/lit8 v0, p4, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    move-object v0, p3

    .line 22
    check-cast v0, Ll2/t;

    .line 23
    .line 24
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    const/4 p1, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p1, 0x2

    .line 33
    :goto_0
    or-int/2addr p1, p4

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move p1, p4

    .line 36
    :goto_1
    and-int/lit8 p4, p4, 0x30

    .line 37
    .line 38
    if-nez p4, :cond_3

    .line 39
    .line 40
    move-object p4, p3

    .line 41
    check-cast p4, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result p4

    .line 47
    if-eqz p4, :cond_2

    .line 48
    .line 49
    const/16 p4, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 p4, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr p1, p4

    .line 55
    :cond_3
    and-int/lit16 p4, p1, 0x93

    .line 56
    .line 57
    const/16 v0, 0x92

    .line 58
    .line 59
    const/4 v1, 0x1

    .line 60
    const/4 v2, 0x0

    .line 61
    if-eq p4, v0, :cond_4

    .line 62
    .line 63
    move p4, v1

    .line 64
    goto :goto_3

    .line 65
    :cond_4
    move p4, v2

    .line 66
    :goto_3
    and-int/2addr p1, v1

    .line 67
    check-cast p3, Ll2/t;

    .line 68
    .line 69
    invoke-virtual {p3, p1, p4}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-eqz p1, :cond_7

    .line 74
    .line 75
    iget-object p1, p0, Luz/q;->d:Ljava/util/List;

    .line 76
    .line 77
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    check-cast p1, Ltz/y0;

    .line 82
    .line 83
    const p4, 0x23871c5d

    .line 84
    .line 85
    .line 86
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 87
    .line 88
    .line 89
    sget-object p4, Lx2/p;->b:Lx2/p;

    .line 90
    .line 91
    const v0, 0x21ed55b1

    .line 92
    .line 93
    .line 94
    if-lez p2, :cond_5

    .line 95
    .line 96
    const v3, 0x2387492a

    .line 97
    .line 98
    .line 99
    invoke-virtual {p3, v3}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 103
    .line 104
    invoke-virtual {p3, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    check-cast v3, Lj91/c;

    .line 109
    .line 110
    iget v3, v3, Lj91/c;->c:F

    .line 111
    .line 112
    const/4 v4, 0x0

    .line 113
    invoke-static {p4, v4, v3, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    invoke-static {v2, v2, p3, v1}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 118
    .line 119
    .line 120
    :goto_4
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_5
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    goto :goto_4

    .line 128
    :goto_5
    const-string v1, "charging_history_"

    .line 129
    .line 130
    const-string v3, "_"

    .line 131
    .line 132
    iget v4, p0, Luz/q;->e:I

    .line 133
    .line 134
    invoke-static {v1, v3, v4, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-static {p1, v1, p3, v2}, Luz/t;->b(Ltz/y0;Ljava/lang/String;Ll2/o;I)V

    .line 139
    .line 140
    .line 141
    iget-object p1, p0, Luz/q;->f:Ltz/x0;

    .line 142
    .line 143
    iget-object p1, p1, Ltz/x0;->c:Ljava/util/List;

    .line 144
    .line 145
    invoke-static {p1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 146
    .line 147
    .line 148
    move-result p1

    .line 149
    if-ne p1, p2, :cond_6

    .line 150
    .line 151
    iget-object p0, p0, Luz/q;->g:Ltz/z0;

    .line 152
    .line 153
    iget-object p0, p0, Ltz/z0;->h:Ljava/util/List;

    .line 154
    .line 155
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    if-eq p0, v4, :cond_6

    .line 160
    .line 161
    const p0, 0x238de2aa

    .line 162
    .line 163
    .line 164
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    sget-object p0, Lj91/a;->a:Ll2/u2;

    .line 168
    .line 169
    invoke-virtual {p3, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    check-cast p0, Lj91/c;

    .line 174
    .line 175
    iget p0, p0, Lj91/c;->f:F

    .line 176
    .line 177
    invoke-static {p4, p0, p3, v2}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 178
    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_6
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    :goto_6
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 188
    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 192
    .line 193
    .line 194
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 195
    .line 196
    return-object p0
.end method
