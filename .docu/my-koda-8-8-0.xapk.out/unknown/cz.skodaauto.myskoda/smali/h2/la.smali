.class public final Lh2/la;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Le3/n0;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:Le1/t;

.field public final synthetic i:F

.field public final synthetic j:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;Le3/n0;JFLe1/t;FLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/la;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/la;->e:Le3/n0;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/la;->f:J

    .line 9
    .line 10
    iput p5, p0, Lh2/la;->g:F

    .line 11
    .line 12
    iput-object p6, p0, Lh2/la;->h:Le1/t;

    .line 13
    .line 14
    iput p7, p0, Lh2/la;->i:F

    .line 15
    .line 16
    iput-object p8, p0, Lh2/la;->j:Lt2/b;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

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
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    if-eqz p2, :cond_6

    .line 29
    .line 30
    iget-wide v4, p0, Lh2/la;->f:J

    .line 31
    .line 32
    iget p2, p0, Lh2/la;->g:F

    .line 33
    .line 34
    invoke-static {v4, v5, p2, p1}, Lh2/oa;->e(JFLl2/t;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v8

    .line 38
    sget-object p2, Lw3/h1;->h:Ll2/u2;

    .line 39
    .line 40
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    iget v1, p0, Lh2/la;->i:F

    .line 45
    .line 46
    check-cast p2, Lt4/c;

    .line 47
    .line 48
    invoke-interface {p2, v1}, Lt4/c;->w0(F)F

    .line 49
    .line 50
    .line 51
    move-result v11

    .line 52
    iget-object v6, p0, Lh2/la;->d:Lx2/s;

    .line 53
    .line 54
    iget-object v7, p0, Lh2/la;->e:Le3/n0;

    .line 55
    .line 56
    iget-object v10, p0, Lh2/la;->h:Le1/t;

    .line 57
    .line 58
    invoke-static/range {v6 .. v11}, Lh2/oa;->d(Lx2/s;Le3/n0;JLe1/t;F)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 67
    .line 68
    if-ne v1, v4, :cond_1

    .line 69
    .line 70
    new-instance v1, Lh10/d;

    .line 71
    .line 72
    const/16 v5, 0x11

    .line 73
    .line 74
    invoke-direct {v1, v5}, Lh10/d;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_1
    check-cast v1, Lay0/k;

    .line 81
    .line 82
    invoke-static {p2, v3, v1}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    if-ne v1, v4, :cond_2

    .line 91
    .line 92
    sget-object v1, Lh2/l4;->f:Lh2/l4;

    .line 93
    .line 94
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_2
    check-cast v1, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 98
    .line 99
    invoke-static {p2, v0, v1}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 104
    .line 105
    invoke-static {v1, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    iget-wide v4, p1, Ll2/t;->T:J

    .line 110
    .line 111
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 124
    .line 125
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 129
    .line 130
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 131
    .line 132
    .line 133
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 134
    .line 135
    if-eqz v7, :cond_3

    .line 136
    .line 137
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 138
    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_3
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 142
    .line 143
    .line 144
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 145
    .line 146
    invoke-static {v6, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 147
    .line 148
    .line 149
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 150
    .line 151
    invoke-static {v1, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 152
    .line 153
    .line 154
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 155
    .line 156
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 157
    .line 158
    if-nez v5, :cond_4

    .line 159
    .line 160
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v5

    .line 164
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    if-nez v5, :cond_5

    .line 173
    .line 174
    :cond_4
    invoke-static {v4, p1, v4, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 175
    .line 176
    .line 177
    :cond_5
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 178
    .line 179
    invoke-static {v1, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 180
    .line 181
    .line 182
    iget-object p0, p0, Lh2/la;->j:Lt2/b;

    .line 183
    .line 184
    invoke-static {v3, p0, p1, v2}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 185
    .line 186
    .line 187
    return-object v0

    .line 188
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    return-object v0
.end method
