.class public final Lf2/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Le3/n0;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;Le3/n0;JFFLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf2/q0;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lf2/q0;->e:Le3/n0;

    .line 7
    .line 8
    iput-wide p3, p0, Lf2/q0;->f:J

    .line 9
    .line 10
    iput p5, p0, Lf2/q0;->g:F

    .line 11
    .line 12
    iput p6, p0, Lf2/q0;->h:F

    .line 13
    .line 14
    iput-object p7, p0, Lf2/q0;->i:Lt2/b;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

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
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x1

    .line 14
    if-eq v0, v1, :cond_0

    .line 15
    .line 16
    move v0, v3

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v2

    .line 19
    :goto_0
    and-int/2addr p2, v3

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
    sget-object p2, Lf2/y;->a:Ll2/u2;

    .line 31
    .line 32
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    check-cast p2, Lf2/q;

    .line 37
    .line 38
    iget v1, p0, Lf2/q0;->g:F

    .line 39
    .line 40
    iget-wide v4, p0, Lf2/q0;->f:J

    .line 41
    .line 42
    invoke-static {v4, v5, p2, v1, p1}, Lkp/g7;->d(JLf2/q;FLl2/t;)J

    .line 43
    .line 44
    .line 45
    move-result-wide v4

    .line 46
    iget p2, p0, Lf2/q0;->h:F

    .line 47
    .line 48
    iget-object v1, p0, Lf2/q0;->e:Le3/n0;

    .line 49
    .line 50
    iget-object v6, p0, Lf2/q0;->d:Lx2/s;

    .line 51
    .line 52
    invoke-static {p2, v4, v5, v1, v6}, Lkp/g7;->c(FJLe3/n0;Lx2/s;)Lx2/s;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 61
    .line 62
    if-ne v1, v4, :cond_1

    .line 63
    .line 64
    new-instance v1, Leh/b;

    .line 65
    .line 66
    const/16 v5, 0x14

    .line 67
    .line 68
    invoke-direct {v1, v5}, Leh/b;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :cond_1
    check-cast v1, Lay0/k;

    .line 75
    .line 76
    invoke-static {p2, v2, v1}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    if-ne v1, v4, :cond_2

    .line 85
    .line 86
    sget-object v1, Lf2/p0;->d:Lf2/p0;

    .line 87
    .line 88
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_2
    check-cast v1, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 92
    .line 93
    invoke-static {p2, v0, v1}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 98
    .line 99
    invoke-static {v1, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    iget-wide v4, p1, Ll2/t;->T:J

    .line 104
    .line 105
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 118
    .line 119
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 123
    .line 124
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 125
    .line 126
    .line 127
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 128
    .line 129
    if-eqz v7, :cond_3

    .line 130
    .line 131
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_3
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 136
    .line 137
    .line 138
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 139
    .line 140
    invoke-static {v6, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 144
    .line 145
    invoke-static {v1, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 149
    .line 150
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 151
    .line 152
    if-nez v5, :cond_4

    .line 153
    .line 154
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 159
    .line 160
    .line 161
    move-result-object v6

    .line 162
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v5

    .line 166
    if-nez v5, :cond_5

    .line 167
    .line 168
    :cond_4
    invoke-static {v4, p1, v4, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 169
    .line 170
    .line 171
    :cond_5
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 172
    .line 173
    invoke-static {v1, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 174
    .line 175
    .line 176
    iget-object p0, p0, Lf2/q0;->i:Lt2/b;

    .line 177
    .line 178
    invoke-static {v2, p0, p1, v3}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 179
    .line 180
    .line 181
    return-object v0

    .line 182
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    return-object v0
.end method
