.class public final Lt1/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Le2/w0;

.field public final synthetic e:Lt1/p0;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Ll4/v;

.field public final synthetic j:Ll4/p;

.field public final synthetic k:Lt4/c;

.field public final synthetic l:I


# direct methods
.method public constructor <init>(Le2/w0;Lt1/p0;ZZLay0/k;Ll4/v;Ll4/p;Lt4/c;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/u;->d:Le2/w0;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/u;->e:Lt1/p0;

    .line 7
    .line 8
    iput-boolean p3, p0, Lt1/u;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lt1/u;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lt1/u;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lt1/u;->i:Ll4/v;

    .line 15
    .line 16
    iput-object p7, p0, Lt1/u;->j:Ll4/p;

    .line 17
    .line 18
    iput-object p8, p0, Lt1/u;->k:Lt4/c;

    .line 19
    .line 20
    iput p9, p0, Lt1/u;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Ll2/o;

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
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x1

    .line 13
    const/4 v3, 0x0

    .line 14
    if-eq v0, v1, :cond_0

    .line 15
    .line 16
    move v0, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v3

    .line 19
    :goto_0
    and-int/2addr p2, v2

    .line 20
    check-cast p1, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    if-eqz p2, :cond_6

    .line 27
    .line 28
    new-instance v4, Lt1/t;

    .line 29
    .line 30
    iget-object v9, p0, Lt1/u;->k:Lt4/c;

    .line 31
    .line 32
    iget v10, p0, Lt1/u;->l:I

    .line 33
    .line 34
    iget-object v5, p0, Lt1/u;->e:Lt1/p0;

    .line 35
    .line 36
    iget-object v6, p0, Lt1/u;->h:Lay0/k;

    .line 37
    .line 38
    iget-object v7, p0, Lt1/u;->i:Ll4/v;

    .line 39
    .line 40
    iget-object v8, p0, Lt1/u;->j:Ll4/p;

    .line 41
    .line 42
    invoke-direct/range {v4 .. v10}, Lt1/t;-><init>(Lt1/p0;Lay0/k;Ll4/v;Ll4/p;Lt4/c;I)V

    .line 43
    .line 44
    .line 45
    iget-wide v0, p1, Ll2/t;->T:J

    .line 46
    .line 47
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 56
    .line 57
    invoke-static {p1, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 62
    .line 63
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 67
    .line 68
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 69
    .line 70
    .line 71
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 72
    .line 73
    if-eqz v7, :cond_1

    .line 74
    .line 75
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 80
    .line 81
    .line 82
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 83
    .line 84
    invoke-static {v6, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 85
    .line 86
    .line 87
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 88
    .line 89
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 90
    .line 91
    .line 92
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 93
    .line 94
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 95
    .line 96
    if-nez v4, :cond_2

    .line 97
    .line 98
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-nez v4, :cond_3

    .line 111
    .line 112
    :cond_2
    invoke-static {p2, p1, p2, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 113
    .line 114
    .line 115
    :cond_3
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 116
    .line 117
    invoke-static {p2, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v5}, Lt1/p0;->a()Lt1/c0;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    sget-object v0, Lt1/c0;->d:Lt1/c0;

    .line 128
    .line 129
    iget-boolean v1, p0, Lt1/u;->f:Z

    .line 130
    .line 131
    if-eq p2, v0, :cond_4

    .line 132
    .line 133
    invoke-virtual {v5}, Lt1/p0;->c()Lt3/y;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    if-eqz p2, :cond_4

    .line 138
    .line 139
    invoke-virtual {v5}, Lt1/p0;->c()Lt3/y;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    invoke-interface {p2}, Lt3/y;->g()Z

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    if-eqz p2, :cond_4

    .line 151
    .line 152
    if-eqz v1, :cond_4

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_4
    move v2, v3

    .line 156
    :goto_2
    iget-object p2, p0, Lt1/u;->d:Le2/w0;

    .line 157
    .line 158
    invoke-static {p2, v2, p1, v3}, Lt1/l0;->j(Le2/w0;ZLl2/o;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v5}, Lt1/p0;->a()Lt1/c0;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    sget-object v2, Lt1/c0;->f:Lt1/c0;

    .line 166
    .line 167
    if-ne v0, v2, :cond_5

    .line 168
    .line 169
    iget-boolean p0, p0, Lt1/u;->g:Z

    .line 170
    .line 171
    if-nez p0, :cond_5

    .line 172
    .line 173
    if-eqz v1, :cond_5

    .line 174
    .line 175
    const p0, -0x2a98f0d6

    .line 176
    .line 177
    .line 178
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 179
    .line 180
    .line 181
    invoke-static {p2, p1, v3}, Lt1/l0;->k(Le2/w0;Ll2/o;I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_5
    const p0, -0x2a97c486

    .line 189
    .line 190
    .line 191
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 195
    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    return-object p0
.end method
