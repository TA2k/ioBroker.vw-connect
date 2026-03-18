.class public final Le1/u0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/q;
.implements Lv3/p;
.implements Lv3/x1;
.implements Lv3/j1;


# instance fields
.field public A:Lt4/l;

.field public B:Lxy0/j;

.field public r:Laj0/c;

.field public s:Le2/b1;

.field public t:Le1/f1;

.field public u:Landroid/view/View;

.field public v:Lt4/c;

.field public w:Lbu/c;

.field public final x:Ll2/j1;

.field public y:Ll2/h0;

.field public z:J


# direct methods
.method public constructor <init>(Laj0/c;Le2/b1;Le1/f1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le1/u0;->r:Laj0/c;

    .line 5
    .line 6
    iput-object p2, p0, Le1/u0;->s:Le2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Le1/u0;->t:Le1/f1;

    .line 9
    .line 10
    sget-object p1, Ll2/x0;->f:Ll2/x0;

    .line 11
    .line 12
    new-instance p2, Ll2/j1;

    .line 13
    .line 14
    const/4 p3, 0x0

    .line 15
    invoke-direct {p2, p3, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 16
    .line 17
    .line 18
    iput-object p2, p0, Le1/u0;->x:Ll2/j1;

    .line 19
    .line 20
    const-wide p1, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    iput-wide p1, p0, Le1/u0;->z:J

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Le1/u0;->B:Lxy0/j;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final K(Lv3/f1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Le1/u0;->x:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final O()V
    .locals 2

    .line 1
    new-instance v0, Le1/t0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Le1/t0;-><init>(Le1/u0;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final P0()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Le1/u0;->O()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x7

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v1, v0, v2}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Le1/u0;->B:Lxy0/j;

    .line 12
    .line 13
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v1, Lvy0/c0;->g:Lvy0/c0;

    .line 18
    .line 19
    new-instance v3, Ldm0/h;

    .line 20
    .line 21
    const/4 v4, 0x6

    .line 22
    invoke-direct {v3, p0, v2, v4}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    invoke-static {v0, v2, v1, v3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final Q0()V
    .locals 1

    .line 1
    iget-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroid/widget/Magnifier;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/widget/Magnifier;->dismiss()V

    .line 10
    .line 11
    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    iput-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 14
    .line 15
    return-void
.end method

.method public final X0()J
    .locals 2

    .line 1
    iget-object v0, p0, Le1/u0;->y:Ll2/h0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Le1/t0;

    .line 6
    .line 7
    const/4 v1, 0x2

    .line 8
    invoke-direct {v0, p0, v1}, Le1/t0;-><init>(Le1/u0;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Le1/u0;->y:Ll2/h0;

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Le1/u0;->y:Ll2/h0;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ld3/b;

    .line 26
    .line 27
    iget-wide v0, p0, Ld3/b;->a:J

    .line 28
    .line 29
    return-wide v0

    .line 30
    :cond_1
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    return-wide v0
.end method

.method public final Y0()V
    .locals 3

    .line 1
    iget-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroid/widget/Magnifier;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/widget/Magnifier;->dismiss()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Le1/u0;->u:Landroid/view/View;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    invoke-static {p0}, Lv3/f;->z(Lv3/m;)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :cond_1
    iput-object v0, p0, Le1/u0;->u:Landroid/view/View;

    .line 21
    .line 22
    iget-object v1, p0, Le1/u0;->v:Lt4/c;

    .line 23
    .line 24
    if-nez v1, :cond_2

    .line 25
    .line 26
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v1, v1, Lv3/h0;->A:Lt4/c;

    .line 31
    .line 32
    :cond_2
    iput-object v1, p0, Le1/u0;->v:Lt4/c;

    .line 33
    .line 34
    iget-object v1, p0, Le1/u0;->t:Le1/f1;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    new-instance v1, Lbu/c;

    .line 40
    .line 41
    new-instance v2, Landroid/widget/Magnifier;

    .line 42
    .line 43
    invoke-direct {v2, v0}, Landroid/widget/Magnifier;-><init>(Landroid/view/View;)V

    .line 44
    .line 45
    .line 46
    const/16 v0, 0x10

    .line 47
    .line 48
    invoke-direct {v1, v2, v0}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 49
    .line 50
    .line 51
    iput-object v1, p0, Le1/u0;->w:Lbu/c;

    .line 52
    .line 53
    invoke-virtual {p0}, Le1/u0;->a1()V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final Z0()V
    .locals 11

    .line 1
    iget-object v0, p0, Le1/u0;->v:Lt4/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 10
    .line 11
    iput-object v0, p0, Le1/u0;->v:Lt4/c;

    .line 12
    .line 13
    :cond_0
    iget-object v1, p0, Le1/u0;->r:Laj0/c;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Laj0/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Ld3/b;

    .line 20
    .line 21
    iget-wide v0, v0, Ld3/b;->a:J

    .line 22
    .line 23
    const-wide v2, 0x7fffffff7fffffffL

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    and-long v4, v0, v2

    .line 29
    .line 30
    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    cmp-long v4, v4, v6

    .line 36
    .line 37
    if-eqz v4, :cond_5

    .line 38
    .line 39
    invoke-virtual {p0}, Le1/u0;->X0()J

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    and-long/2addr v2, v4

    .line 44
    cmp-long v2, v2, v6

    .line 45
    .line 46
    if-eqz v2, :cond_5

    .line 47
    .line 48
    invoke-virtual {p0}, Le1/u0;->X0()J

    .line 49
    .line 50
    .line 51
    move-result-wide v2

    .line 52
    invoke-static {v2, v3, v0, v1}, Ld3/b;->h(JJ)J

    .line 53
    .line 54
    .line 55
    move-result-wide v0

    .line 56
    iput-wide v0, p0, Le1/u0;->z:J

    .line 57
    .line 58
    iget-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 59
    .line 60
    if-nez v0, :cond_1

    .line 61
    .line 62
    invoke-virtual {p0}, Le1/u0;->Y0()V

    .line 63
    .line 64
    .line 65
    :cond_1
    iget-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 66
    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    iget-wide v1, p0, Le1/u0;->z:J

    .line 70
    .line 71
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Landroid/widget/Magnifier;

    .line 74
    .line 75
    const/high16 v3, 0x7fc00000    # Float.NaN

    .line 76
    .line 77
    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-nez v4, :cond_2

    .line 82
    .line 83
    invoke-virtual {v0, v3}, Landroid/widget/Magnifier;->setZoom(F)V

    .line 84
    .line 85
    .line 86
    :cond_2
    const-wide v3, 0x7fffffff7fffffffL

    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    and-long/2addr v3, v6

    .line 92
    const-wide v8, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    cmp-long v3, v3, v8

    .line 98
    .line 99
    const-wide v4, 0xffffffffL

    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    const/16 v8, 0x20

    .line 105
    .line 106
    if-eqz v3, :cond_3

    .line 107
    .line 108
    shr-long v9, v1, v8

    .line 109
    .line 110
    long-to-int v3, v9

    .line 111
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    and-long/2addr v1, v4

    .line 116
    long-to-int v1, v1

    .line 117
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    shr-long v8, v6, v8

    .line 122
    .line 123
    long-to-int v2, v8

    .line 124
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    and-long/2addr v4, v6

    .line 129
    long-to-int v4, v4

    .line 130
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 131
    .line 132
    .line 133
    move-result v4

    .line 134
    invoke-virtual {v0, v3, v1, v2, v4}, Landroid/widget/Magnifier;->show(FFFF)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_3
    shr-long v6, v1, v8

    .line 139
    .line 140
    long-to-int v3, v6

    .line 141
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    and-long/2addr v1, v4

    .line 146
    long-to-int v1, v1

    .line 147
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    invoke-virtual {v0, v3, v1}, Landroid/widget/Magnifier;->show(FF)V

    .line 152
    .line 153
    .line 154
    :cond_4
    :goto_0
    invoke-virtual {p0}, Le1/u0;->a1()V

    .line 155
    .line 156
    .line 157
    return-void

    .line 158
    :cond_5
    iput-wide v6, p0, Le1/u0;->z:J

    .line 159
    .line 160
    iget-object p0, p0, Le1/u0;->w:Lbu/c;

    .line 161
    .line 162
    if-eqz p0, :cond_6

    .line 163
    .line 164
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p0, Landroid/widget/Magnifier;

    .line 167
    .line 168
    invoke-virtual {p0}, Landroid/widget/Magnifier;->dismiss()V

    .line 169
    .line 170
    .line 171
    :cond_6
    return-void
.end method

.method public final a0(Ld4/l;)V
    .locals 3

    .line 1
    sget-object v0, Le1/v0;->a:Ld4/z;

    .line 2
    .line 3
    new-instance v1, Le1/t0;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v1, p0, v2}, Le1/t0;-><init>(Le1/u0;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, v0, v1}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final a1()V
    .locals 6

    .line 1
    iget-object v0, p0, Le1/u0;->w:Lbu/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object v1, p0, Le1/u0;->v:Lt4/c;

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    :goto_0
    return-void

    .line 11
    :cond_1
    invoke-virtual {v0}, Lbu/c;->u()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    iget-object v4, p0, Le1/u0;->A:Lt4/l;

    .line 16
    .line 17
    if-nez v4, :cond_2

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_2
    iget-wide v4, v4, Lt4/l;->a:J

    .line 21
    .line 22
    cmp-long v2, v2, v4

    .line 23
    .line 24
    if-eqz v2, :cond_3

    .line 25
    .line 26
    :goto_1
    iget-object v2, p0, Le1/u0;->s:Le2/b1;

    .line 27
    .line 28
    invoke-virtual {v0}, Lbu/c;->u()J

    .line 29
    .line 30
    .line 31
    move-result-wide v3

    .line 32
    invoke-static {v3, v4}, Lkp/f9;->c(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-interface {v1, v3, v4}, Lt4/c;->n(J)J

    .line 37
    .line 38
    .line 39
    move-result-wide v3

    .line 40
    new-instance v1, Lt4/h;

    .line 41
    .line 42
    invoke-direct {v1, v3, v4}, Lt4/h;-><init>(J)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v2, v1}, Le2/b1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Lbu/c;->u()J

    .line 49
    .line 50
    .line 51
    move-result-wide v0

    .line 52
    new-instance v2, Lt4/l;

    .line 53
    .line 54
    invoke-direct {v2, v0, v1}, Lt4/l;-><init>(J)V

    .line 55
    .line 56
    .line 57
    iput-object v2, p0, Le1/u0;->A:Lt4/l;

    .line 58
    .line 59
    :cond_3
    return-void
.end method
