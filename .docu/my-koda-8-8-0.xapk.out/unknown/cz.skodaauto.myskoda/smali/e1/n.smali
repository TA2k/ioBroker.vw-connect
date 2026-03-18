.class public final Le1/n;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p;
.implements Lv3/j1;
.implements Lv3/x1;


# instance fields
.field public r:J

.field public s:Le3/p;

.field public t:F

.field public u:Le3/n0;

.field public v:J

.field public w:Lt4/m;

.field public x:Le3/g0;

.field public y:Le3/n0;

.field public z:Le3/g0;


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 12

    .line 1
    iget-object v2, p1, Lv3/j0;->d:Lg3/b;

    .line 2
    .line 3
    iget-object v3, p0, Le1/n;->u:Le3/n0;

    .line 4
    .line 5
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 6
    .line 7
    if-ne v3, v4, :cond_1

    .line 8
    .line 9
    iget-wide v2, p0, Le1/n;->r:J

    .line 10
    .line 11
    sget-wide v4, Le3/s;->i:J

    .line 12
    .line 13
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    iget-wide v2, p0, Le1/n;->r:J

    .line 20
    .line 21
    const/4 v10, 0x0

    .line 22
    const/16 v11, 0x7e

    .line 23
    .line 24
    const-wide/16 v4, 0x0

    .line 25
    .line 26
    const-wide/16 v6, 0x0

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    const/4 v9, 0x0

    .line 30
    move-object v1, p1

    .line 31
    invoke-static/range {v1 .. v11}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object v1, p0, Le1/n;->s:Le3/p;

    .line 35
    .line 36
    if-eqz v1, :cond_4

    .line 37
    .line 38
    iget v6, p0, Le1/n;->t:F

    .line 39
    .line 40
    const/4 v8, 0x0

    .line 41
    const/16 v9, 0x76

    .line 42
    .line 43
    const-wide/16 v2, 0x0

    .line 44
    .line 45
    const-wide/16 v4, 0x0

    .line 46
    .line 47
    const/4 v7, 0x0

    .line 48
    move-object v0, p1

    .line 49
    invoke-static/range {v0 .. v9}, Lg3/d;->i0(Lg3/d;Le3/p;JJFLg3/e;II)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-interface {v2}, Lg3/d;->e()J

    .line 54
    .line 55
    .line 56
    move-result-wide v3

    .line 57
    iget-wide v5, p0, Le1/n;->v:J

    .line 58
    .line 59
    invoke-static {v3, v4, v5, v6}, Ld3/e;->a(JJ)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    invoke-virtual {p1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    iget-object v4, p0, Le1/n;->w:Lt4/m;

    .line 70
    .line 71
    if-ne v3, v4, :cond_2

    .line 72
    .line 73
    iget-object v3, p0, Le1/n;->y:Le3/n0;

    .line 74
    .line 75
    iget-object v4, p0, Le1/n;->u:Le3/n0;

    .line 76
    .line 77
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_2

    .line 82
    .line 83
    iget-object v3, p0, Le1/n;->x:Le3/g0;

    .line 84
    .line 85
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    new-instance v3, Ld90/w;

    .line 90
    .line 91
    const/4 v4, 0x6

    .line 92
    invoke-direct {v3, v4, p0, p1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-static {p0, v3}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 96
    .line 97
    .line 98
    iget-object v3, p0, Le1/n;->z:Le3/g0;

    .line 99
    .line 100
    const/4 v4, 0x0

    .line 101
    iput-object v4, p0, Le1/n;->z:Le3/g0;

    .line 102
    .line 103
    :goto_0
    iput-object v3, p0, Le1/n;->x:Le3/g0;

    .line 104
    .line 105
    invoke-interface {v2}, Lg3/d;->e()J

    .line 106
    .line 107
    .line 108
    move-result-wide v4

    .line 109
    iput-wide v4, p0, Le1/n;->v:J

    .line 110
    .line 111
    invoke-virtual {p1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    iput-object v2, p0, Le1/n;->w:Lt4/m;

    .line 116
    .line 117
    iget-object v2, p0, Le1/n;->u:Le3/n0;

    .line 118
    .line 119
    iput-object v2, p0, Le1/n;->y:Le3/n0;

    .line 120
    .line 121
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    iget-wide v4, p0, Le1/n;->r:J

    .line 125
    .line 126
    sget-wide v6, Le3/s;->i:J

    .line 127
    .line 128
    invoke-static {v4, v5, v6, v7}, Le3/s;->c(JJ)Z

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    if-nez v2, :cond_3

    .line 133
    .line 134
    iget-wide v4, p0, Le1/n;->r:J

    .line 135
    .line 136
    invoke-static {p1, v3, v4, v5}, Le3/j0;->o(Lg3/d;Le3/g0;J)V

    .line 137
    .line 138
    .line 139
    :cond_3
    iget-object v2, p0, Le1/n;->s:Le3/p;

    .line 140
    .line 141
    if-eqz v2, :cond_4

    .line 142
    .line 143
    iget v0, p0, Le1/n;->t:F

    .line 144
    .line 145
    invoke-static {p1, v3, v2, v0}, Le3/j0;->n(Lg3/d;Le3/g0;Le3/p;F)V

    .line 146
    .line 147
    .line 148
    :cond_4
    :goto_1
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 149
    .line 150
    .line 151
    return-void
.end method

.method public final O()V
    .locals 2

    .line 1
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide v0, p0, Le1/n;->v:J

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Le1/n;->w:Lt4/m;

    .line 10
    .line 11
    iput-object v0, p0, Le1/n;->x:Le3/g0;

    .line 12
    .line 13
    iput-object v0, p0, Le1/n;->y:Le3/n0;

    .line 14
    .line 15
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final a0(Ld4/l;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
