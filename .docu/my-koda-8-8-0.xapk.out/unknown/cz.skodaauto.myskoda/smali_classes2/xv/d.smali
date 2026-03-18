.class public final Lxv/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:J

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Lxv/a;

.field public final synthetic i:Lt4/c;


# direct methods
.method public constructor <init>(JLl2/b1;Lxv/a;Lt4/c;)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lxv/d;->f:J

    .line 2
    .line 3
    iput-object p3, p0, Lxv/d;->g:Ll2/b1;

    .line 4
    .line 5
    iput-object p4, p0, Lxv/d;->h:Lxv/a;

    .line 6
    .line 7
    iput-object p5, p0, Lxv/d;->i:Lt4/c;

    .line 8
    .line 9
    const/4 p1, 0x3

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const-string v0, "alternateText"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    and-int/lit8 v0, p3, 0xe

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    move-object v0, p2

    .line 21
    check-cast v0, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr p3, v0

    .line 33
    :cond_1
    and-int/lit8 v0, p3, 0x5b

    .line 34
    .line 35
    const/16 v1, 0x12

    .line 36
    .line 37
    if-ne v0, v1, :cond_3

    .line 38
    .line 39
    move-object v0, p2

    .line 40
    check-cast v0, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {v0}, Ll2/t;->A()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_3

    .line 53
    .line 54
    :cond_3
    :goto_1
    check-cast p2, Ll2/t;

    .line 55
    .line 56
    const v0, -0x56f54bc4

    .line 57
    .line 58
    .line 59
    invoke-virtual {p2, v0}, Ll2/t;->Z(I)V

    .line 60
    .line 61
    .line 62
    iget-wide v0, p0, Lxv/d;->f:J

    .line 63
    .line 64
    invoke-virtual {p2, v0, v1}, Ll2/t;->f(J)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    iget-object v3, p0, Lxv/d;->g:Ll2/b1;

    .line 69
    .line 70
    invoke-virtual {p2, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    or-int/2addr v2, v4

    .line 75
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    if-nez v2, :cond_4

    .line 80
    .line 81
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 82
    .line 83
    if-ne v4, v2, :cond_5

    .line 84
    .line 85
    :cond_4
    new-instance v4, Lxv/c;

    .line 86
    .line 87
    invoke-direct {v4, v0, v1, v3}, Lxv/c;-><init>(JLl2/b1;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_5
    check-cast v4, Lt3/q0;

    .line 94
    .line 95
    const/4 v0, 0x0

    .line 96
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    const v1, -0x4ee9b9da

    .line 100
    .line 101
    .line 102
    invoke-virtual {p2, v1}, Ll2/t;->Z(I)V

    .line 103
    .line 104
    .line 105
    iget-wide v1, p2, Ll2/t;->T:J

    .line 106
    .line 107
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    invoke-virtual {p2}, Ll2/t;->m()Ll2/p1;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 116
    .line 117
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 121
    .line 122
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 123
    .line 124
    invoke-static {v5}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    invoke-virtual {p2}, Ll2/t;->c0()V

    .line 129
    .line 130
    .line 131
    iget-boolean v6, p2, Ll2/t;->S:Z

    .line 132
    .line 133
    if-eqz v6, :cond_6

    .line 134
    .line 135
    invoke-virtual {p2, v3}, Ll2/t;->l(Lay0/a;)V

    .line 136
    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_6
    invoke-virtual {p2}, Ll2/t;->m0()V

    .line 140
    .line 141
    .line 142
    :goto_2
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 143
    .line 144
    invoke-static {v3, v4, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 145
    .line 146
    .line 147
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 148
    .line 149
    invoke-static {v3, v2, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 153
    .line 154
    iget-boolean v3, p2, Ll2/t;->S:Z

    .line 155
    .line 156
    if-nez v3, :cond_7

    .line 157
    .line 158
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    if-nez v3, :cond_8

    .line 171
    .line 172
    :cond_7
    invoke-static {v1, p2, v1, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 173
    .line 174
    .line 175
    :cond_8
    new-instance v1, Ll2/d2;

    .line 176
    .line 177
    invoke-direct {v1, p2}, Ll2/d2;-><init>(Ll2/o;)V

    .line 178
    .line 179
    .line 180
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    invoke-virtual {v5, v1, p2, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    const v1, 0x7ab4aae9

    .line 188
    .line 189
    .line 190
    invoke-virtual {p2, v1}, Ll2/t;->Z(I)V

    .line 191
    .line 192
    .line 193
    iget-object v1, p0, Lxv/d;->h:Lxv/a;

    .line 194
    .line 195
    iget-object v1, v1, Lxv/a;->b:Lt2/b;

    .line 196
    .line 197
    shl-int/lit8 p3, p3, 0x3

    .line 198
    .line 199
    and-int/lit8 p3, p3, 0x70

    .line 200
    .line 201
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object p3

    .line 205
    iget-object p0, p0, Lxv/d;->i:Lt4/c;

    .line 206
    .line 207
    invoke-virtual {v1, p0, p1, p2, p3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    const/4 p0, 0x1

    .line 211
    invoke-static {p2, v0, p0, v0}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 212
    .line 213
    .line 214
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 215
    .line 216
    return-object p0
.end method
