.class public abstract Llp/vd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Lt2/b;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x439751f4

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    and-int/lit8 v0, v0, 0x5b

    .line 12
    .line 13
    const/16 v1, 0x12

    .line 14
    .line 15
    if-ne v0, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 25
    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_1
    :goto_0
    const p0, -0x4ee9b9da

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 32
    .line 33
    .line 34
    iget-wide v0, p2, Ll2/t;->T:J

    .line 35
    .line 36
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-virtual {p2}, Ll2/t;->m()Ll2/p1;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sget-object v1, Lv3/k;->m1:Lv3/j;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    sget-object v1, Lv3/j;->b:Lv3/i;

    .line 50
    .line 51
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 52
    .line 53
    invoke-static {v2}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-virtual {p2}, Ll2/t;->c0()V

    .line 58
    .line 59
    .line 60
    iget-boolean v4, p2, Ll2/t;->S:Z

    .line 61
    .line 62
    if-eqz v4, :cond_2

    .line 63
    .line 64
    invoke-virtual {p2, v1}, Ll2/t;->l(Lay0/a;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-virtual {p2}, Ll2/t;->m0()V

    .line 69
    .line 70
    .line 71
    :goto_1
    sget-object v1, Lv3/j;->g:Lv3/h;

    .line 72
    .line 73
    sget-object v4, Lkn/h0;->a:Lkn/h0;

    .line 74
    .line 75
    invoke-static {v1, v4, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 76
    .line 77
    .line 78
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 79
    .line 80
    invoke-static {v1, v0, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 81
    .line 82
    .line 83
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 84
    .line 85
    iget-boolean v1, p2, Ll2/t;->S:Z

    .line 86
    .line 87
    if-nez v1, :cond_3

    .line 88
    .line 89
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_4

    .line 102
    .line 103
    :cond_3
    invoke-static {p0, p2, p0, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 104
    .line 105
    .line 106
    :cond_4
    new-instance p0, Ll2/d2;

    .line 107
    .line 108
    invoke-direct {p0, p2}, Ll2/d2;-><init>(Ll2/o;)V

    .line 109
    .line 110
    .line 111
    const/4 v0, 0x0

    .line 112
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-virtual {v3, p0, p2, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    const p0, 0x7ab4aae9

    .line 120
    .line 121
    .line 122
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 123
    .line 124
    .line 125
    const/4 p0, 0x6

    .line 126
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-virtual {p1, p2, p0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 134
    .line 135
    .line 136
    const/4 p0, 0x1

    .line 137
    invoke-virtual {p2, p0}, Ll2/t;->q(Z)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    move-object p0, v2

    .line 144
    :goto_2
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 145
    .line 146
    .line 147
    move-result-object p2

    .line 148
    if-eqz p2, :cond_5

    .line 149
    .line 150
    new-instance v0, Lkn/i0;

    .line 151
    .line 152
    const/4 v1, 0x0

    .line 153
    invoke-direct {v0, p3, v1, p0, p1}, Lkn/i0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 157
    .line 158
    :cond_5
    return-void
.end method

.method public static final b(Ljava/io/Closeable;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    :try_start_0
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    invoke-static {p1, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    return-void
.end method
