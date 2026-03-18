.class public final Lh2/ub;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:J

.field public final synthetic f:Lt2/b;


# direct methods
.method public constructor <init>(FJLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/ub;->d:F

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/ub;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lh2/ub;->f:Lt2/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

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
    sget p2, Lh2/vb;->c:F

    .line 29
    .line 30
    sget v0, Lh2/vb;->b:F

    .line 31
    .line 32
    iget v1, p0, Lh2/ub;->d:F

    .line 33
    .line 34
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 35
    .line 36
    const/16 v5, 0x8

    .line 37
    .line 38
    invoke-static {v4, p2, v0, v1, v5}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    sget-object v0, Lh2/vb;->d:Lk1/a1;

    .line 43
    .line 44
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 49
    .line 50
    invoke-static {v0, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iget-wide v1, p1, Ll2/t;->T:J

    .line 55
    .line 56
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 69
    .line 70
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 74
    .line 75
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 76
    .line 77
    .line 78
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 79
    .line 80
    if-eqz v6, :cond_1

    .line 81
    .line 82
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 87
    .line 88
    .line 89
    :goto_1
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 90
    .line 91
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 95
    .line 96
    invoke-static {v0, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 100
    .line 101
    iget-boolean v2, p1, Ll2/t;->S:Z

    .line 102
    .line 103
    if-nez v2, :cond_2

    .line 104
    .line 105
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-nez v2, :cond_3

    .line 118
    .line 119
    :cond_2
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 120
    .line 121
    .line 122
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 123
    .line 124
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    sget-object p2, Lk2/b0;->d:Lk2/p0;

    .line 128
    .line 129
    invoke-static {p2, p1}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    sget-object v0, Lh2/p1;->a:Ll2/e0;

    .line 134
    .line 135
    iget-wide v1, p0, Lh2/ub;->e:J

    .line 136
    .line 137
    invoke-static {v1, v2, v0}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    sget-object v1, Lh2/rb;->a:Ll2/e0;

    .line 142
    .line 143
    invoke-virtual {v1, p2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    filled-new-array {v0, p2}, [Ll2/t1;

    .line 148
    .line 149
    .line 150
    move-result-object p2

    .line 151
    iget-object p0, p0, Lh2/ub;->f:Lt2/b;

    .line 152
    .line 153
    invoke-static {p2, p0, p1, v5}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 157
    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 161
    .line 162
    .line 163
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0
.end method
