.class public final Lf2/r0;
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

.field public final synthetic i:Li1/l;

.field public final synthetic j:Z

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;Le3/n0;JFFLi1/l;ZLay0/a;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf2/r0;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lf2/r0;->e:Le3/n0;

    .line 7
    .line 8
    iput-wide p3, p0, Lf2/r0;->f:J

    .line 9
    .line 10
    iput p5, p0, Lf2/r0;->g:F

    .line 11
    .line 12
    iput p6, p0, Lf2/r0;->h:F

    .line 13
    .line 14
    iput-object p7, p0, Lf2/r0;->i:Li1/l;

    .line 15
    .line 16
    iput-boolean p8, p0, Lf2/r0;->j:Z

    .line 17
    .line 18
    iput-object p9, p0, Lf2/r0;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p10, p0, Lf2/r0;->l:Lt2/b;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

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
    if-eqz p2, :cond_4

    .line 27
    .line 28
    sget-object p2, Lf2/z;->a:Ll2/u2;

    .line 29
    .line 30
    sget-object p2, Landroidx/compose/material/MinimumInteractiveModifier;->b:Landroidx/compose/material/MinimumInteractiveModifier;

    .line 31
    .line 32
    iget-object v0, p0, Lf2/r0;->d:Lx2/s;

    .line 33
    .line 34
    invoke-interface {v0, p2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    sget-object v0, Lf2/y;->a:Ll2/u2;

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, Lf2/q;

    .line 45
    .line 46
    iget v1, p0, Lf2/r0;->g:F

    .line 47
    .line 48
    iget-wide v4, p0, Lf2/r0;->f:J

    .line 49
    .line 50
    invoke-static {v4, v5, v0, v1, p1}, Lkp/g7;->d(JLf2/q;FLl2/t;)J

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    iget v4, p0, Lf2/r0;->h:F

    .line 55
    .line 56
    iget-object v5, p0, Lf2/r0;->e:Le3/n0;

    .line 57
    .line 58
    invoke-static {v4, v0, v1, v5, p2}, Lkp/g7;->c(FJLe3/n0;Lx2/s;)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    const/4 p2, 0x7

    .line 63
    invoke-static {p2}, Lf2/i0;->a(I)Lf2/j0;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    iget-object v11, p0, Lf2/r0;->k:Lay0/a;

    .line 68
    .line 69
    const/16 v12, 0x18

    .line 70
    .line 71
    iget-object v7, p0, Lf2/r0;->i:Li1/l;

    .line 72
    .line 73
    iget-boolean v9, p0, Lf2/r0;->j:Z

    .line 74
    .line 75
    const/4 v10, 0x0

    .line 76
    invoke-static/range {v6 .. v12}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 81
    .line 82
    invoke-static {v0, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    iget-wide v4, p1, Ll2/t;->T:J

    .line 87
    .line 88
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 101
    .line 102
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 106
    .line 107
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 108
    .line 109
    .line 110
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 111
    .line 112
    if-eqz v6, :cond_1

    .line 113
    .line 114
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 119
    .line 120
    .line 121
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 122
    .line 123
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 124
    .line 125
    .line 126
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 127
    .line 128
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 132
    .line 133
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 134
    .line 135
    if-nez v4, :cond_2

    .line 136
    .line 137
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v4

    .line 149
    if-nez v4, :cond_3

    .line 150
    .line 151
    :cond_2
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 152
    .line 153
    .line 154
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 155
    .line 156
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 157
    .line 158
    .line 159
    iget-object p0, p0, Lf2/r0;->l:Lt2/b;

    .line 160
    .line 161
    invoke-static {v2, p0, p1, v3}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 166
    .line 167
    .line 168
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object p0
.end method
