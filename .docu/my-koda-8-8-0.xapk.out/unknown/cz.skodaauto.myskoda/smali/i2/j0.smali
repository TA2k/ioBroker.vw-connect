.class public final Li2/j0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:Lg1/q;

.field public s:Lay0/n;

.field public t:Lg1/w1;

.field public u:Z


# virtual methods
.method public final Q0()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Li2/j0;->u:Z

    .line 3
    .line 4
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 7

    .line 1
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-interface {p1}, Lt3/t;->I()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-boolean v0, p0, Li2/j0;->u:Z

    .line 12
    .line 13
    if-nez v0, :cond_3

    .line 14
    .line 15
    :cond_0
    iget v0, p2, Lt3/e1;->d:I

    .line 16
    .line 17
    iget v1, p2, Lt3/e1;->e:I

    .line 18
    .line 19
    int-to-long v2, v0

    .line 20
    const/16 v0, 0x20

    .line 21
    .line 22
    shl-long/2addr v2, v0

    .line 23
    int-to-long v0, v1

    .line 24
    const-wide v4, 0xffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    and-long/2addr v0, v4

    .line 30
    or-long/2addr v0, v2

    .line 31
    iget-object v2, p0, Li2/j0;->s:Lay0/n;

    .line 32
    .line 33
    new-instance v3, Lt4/l;

    .line 34
    .line 35
    invoke-direct {v3, v0, v1}, Lt4/l;-><init>(J)V

    .line 36
    .line 37
    .line 38
    new-instance v0, Lt4/a;

    .line 39
    .line 40
    invoke-direct {v0, p3, p4}, Lt4/a;-><init>(J)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v2, v3, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p3

    .line 47
    check-cast p3, Llx0/l;

    .line 48
    .line 49
    iget-object p4, p0, Li2/j0;->r:Lg1/q;

    .line 50
    .line 51
    iget-object v0, p3, Llx0/l;->d:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lg1/z;

    .line 54
    .line 55
    iget-object p3, p3, Llx0/l;->e:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-virtual {p4}, Lg1/q;->g()Lg1/z;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    iget-object v2, p4, Lg1/q;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v2, Ll2/j1;

    .line 64
    .line 65
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-nez v1, :cond_3

    .line 70
    .line 71
    iget-object v1, p4, Lg1/q;->g:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v1, Ll2/j1;

    .line 74
    .line 75
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p4, Lg1/q;->c:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Le1/b1;

    .line 81
    .line 82
    iget-object v1, v0, Le1/b1;->b:Lez0/c;

    .line 83
    .line 84
    iget-object v0, v0, Le1/b1;->b:Lez0/c;

    .line 85
    .line 86
    invoke-virtual {v1}, Lez0/c;->tryLock()Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_2

    .line 91
    .line 92
    const/4 v3, 0x0

    .line 93
    :try_start_0
    iget-object v4, p4, Lg1/q;->k:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v4, Lg1/p;

    .line 96
    .line 97
    invoke-virtual {p4}, Lg1/q;->g()Lg1/z;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    invoke-virtual {v5, p3}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 106
    .line 107
    .line 108
    move-result v6

    .line 109
    if-nez v6, :cond_1

    .line 110
    .line 111
    invoke-static {v4, v5}, Lg1/p;->b(Lg1/p;F)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v2, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :catchall_0
    move-exception p0

    .line 119
    goto :goto_1

    .line 120
    :cond_1
    :goto_0
    invoke-virtual {p4, p3}, Lg1/q;->m(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object p4, p4, Lg1/q;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p4, Ll2/j1;

    .line 126
    .line 127
    invoke-virtual {p4, p3}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0, v3}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_2

    .line 134
    :goto_1
    invoke-virtual {v0, v3}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :cond_2
    :goto_2
    if-nez v1, :cond_3

    .line 139
    .line 140
    invoke-virtual {v2, p3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_3
    invoke-interface {p1}, Lt3/t;->I()Z

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    if-nez p3, :cond_5

    .line 148
    .line 149
    iget-boolean p3, p0, Li2/j0;->u:Z

    .line 150
    .line 151
    if-eqz p3, :cond_4

    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_4
    const/4 p3, 0x0

    .line 155
    goto :goto_4

    .line 156
    :cond_5
    :goto_3
    const/4 p3, 0x1

    .line 157
    :goto_4
    iput-boolean p3, p0, Li2/j0;->u:Z

    .line 158
    .line 159
    iget p3, p2, Lt3/e1;->d:I

    .line 160
    .line 161
    iget p4, p2, Lt3/e1;->e:I

    .line 162
    .line 163
    new-instance v0, Laa/o;

    .line 164
    .line 165
    const/16 v1, 0x1b

    .line 166
    .line 167
    invoke-direct {v0, p1, p0, p2, v1}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 171
    .line 172
    invoke-interface {p1, p3, p4, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0
.end method
