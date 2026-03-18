.class public final Lb1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/r1;


# instance fields
.field public final a:Lc1/w1;

.field public b:Lx2/e;

.field public c:Lt4/m;

.field public final d:Ll2/j1;

.field public final e:Landroidx/collection/q0;

.field public f:Lc1/p1;


# direct methods
.method public constructor <init>(Lc1/w1;Lx2/e;Lt4/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb1/t;->a:Lc1/w1;

    .line 5
    .line 6
    iput-object p2, p0, Lb1/t;->b:Lx2/e;

    .line 7
    .line 8
    iput-object p3, p0, Lb1/t;->c:Lt4/m;

    .line 9
    .line 10
    new-instance p1, Lt4/l;

    .line 11
    .line 12
    const-wide/16 p2, 0x0

    .line 13
    .line 14
    invoke-direct {p1, p2, p3}, Lt4/l;-><init>(J)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lb1/t;->d:Ll2/j1;

    .line 22
    .line 23
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 24
    .line 25
    new-instance p1, Landroidx/collection/q0;

    .line 26
    .line 27
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 31
    .line 32
    return-void
.end method

.method public static final d(Lb1/t;)J
    .locals 2

    .line 1
    iget-object v0, p0, Lb1/t;->f:Lc1/p1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt4/l;

    .line 10
    .line 11
    iget-wide v0, p0, Lt4/l;->a:J

    .line 12
    .line 13
    return-wide v0

    .line 14
    :cond_0
    iget-object p0, p0, Lb1/t;->d:Ll2/j1;

    .line 15
    .line 16
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lt4/l;

    .line 21
    .line 22
    iget-wide v0, p0, Lt4/l;->a:J

    .line 23
    .line 24
    return-wide v0
.end method

.method public static e(Lb1/t;I)Lb1/t0;
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-long v1, v0

    .line 3
    const/16 v3, 0x20

    .line 4
    .line 5
    shl-long v3, v1, v3

    .line 6
    .line 7
    const-wide v5, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v1, v5

    .line 13
    or-long/2addr v1, v3

    .line 14
    new-instance v3, Lt4/j;

    .line 15
    .line 16
    invoke-direct {v3, v1, v2}, Lt4/j;-><init>(J)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x3

    .line 21
    invoke-static {v1, v1, v3, v2}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    if-nez p1, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v4, 0x4

    .line 33
    if-ne p1, v4, :cond_1

    .line 34
    .line 35
    iget-object v5, p0, Lb1/t;->c:Lt4/m;

    .line 36
    .line 37
    sget-object v6, Lt4/m;->d:Lt4/m;

    .line 38
    .line 39
    if-eq v5, v6, :cond_2

    .line 40
    .line 41
    :cond_1
    const/4 v5, 0x5

    .line 42
    if-ne p1, v5, :cond_3

    .line 43
    .line 44
    iget-object v6, p0, Lb1/t;->c:Lt4/m;

    .line 45
    .line 46
    sget-object v7, Lt4/m;->e:Lt4/m;

    .line 47
    .line 48
    if-ne v6, v7, :cond_3

    .line 49
    .line 50
    :cond_2
    :goto_0
    new-instance p1, Lb1/s;

    .line 51
    .line 52
    invoke-direct {p1, p0, v3}, Lb1/s;-><init>(Lb1/t;I)V

    .line 53
    .line 54
    .line 55
    sget-object p0, Lb1/o0;->a:Lc1/b2;

    .line 56
    .line 57
    new-instance p0, Lb1/n0;

    .line 58
    .line 59
    invoke-direct {p0, v3, p1}, Lb1/n0;-><init>(ILay0/k;)V

    .line 60
    .line 61
    .line 62
    new-instance p1, Lb1/t0;

    .line 63
    .line 64
    new-instance v2, Lb1/i1;

    .line 65
    .line 66
    new-instance v4, Lb1/g1;

    .line 67
    .line 68
    invoke-direct {v4, p0, v1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 69
    .line 70
    .line 71
    const/4 v7, 0x0

    .line 72
    const/16 v8, 0x3d

    .line 73
    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v5, 0x0

    .line 76
    const/4 v6, 0x0

    .line 77
    invoke-direct/range {v2 .. v8}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 78
    .line 79
    .line 80
    invoke-direct {p1, v2}, Lb1/t0;-><init>(Lb1/i1;)V

    .line 81
    .line 82
    .line 83
    return-object p1

    .line 84
    :cond_3
    if-ne p1, v0, :cond_4

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_4
    if-ne p1, v4, :cond_5

    .line 88
    .line 89
    iget-object v4, p0, Lb1/t;->c:Lt4/m;

    .line 90
    .line 91
    sget-object v6, Lt4/m;->e:Lt4/m;

    .line 92
    .line 93
    if-eq v4, v6, :cond_6

    .line 94
    .line 95
    :cond_5
    if-ne p1, v5, :cond_7

    .line 96
    .line 97
    iget-object v4, p0, Lb1/t;->c:Lt4/m;

    .line 98
    .line 99
    sget-object v5, Lt4/m;->d:Lt4/m;

    .line 100
    .line 101
    if-ne v4, v5, :cond_7

    .line 102
    .line 103
    :cond_6
    :goto_1
    new-instance p1, Lb1/s;

    .line 104
    .line 105
    invoke-direct {p1, p0, v0}, Lb1/s;-><init>(Lb1/t;I)V

    .line 106
    .line 107
    .line 108
    sget-object p0, Lb1/o0;->a:Lc1/b2;

    .line 109
    .line 110
    new-instance p0, Lb1/n0;

    .line 111
    .line 112
    invoke-direct {p0, v3, p1}, Lb1/n0;-><init>(ILay0/k;)V

    .line 113
    .line 114
    .line 115
    new-instance p1, Lb1/t0;

    .line 116
    .line 117
    new-instance v2, Lb1/i1;

    .line 118
    .line 119
    new-instance v4, Lb1/g1;

    .line 120
    .line 121
    invoke-direct {v4, p0, v1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 122
    .line 123
    .line 124
    const/4 v7, 0x0

    .line 125
    const/16 v8, 0x3d

    .line 126
    .line 127
    const/4 v3, 0x0

    .line 128
    const/4 v5, 0x0

    .line 129
    const/4 v6, 0x0

    .line 130
    invoke-direct/range {v2 .. v8}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 131
    .line 132
    .line 133
    invoke-direct {p1, v2}, Lb1/t0;-><init>(Lb1/i1;)V

    .line 134
    .line 135
    .line 136
    return-object p1

    .line 137
    :cond_7
    const/4 v0, 0x2

    .line 138
    if-ne p1, v0, :cond_8

    .line 139
    .line 140
    new-instance p1, Lb1/s;

    .line 141
    .line 142
    invoke-direct {p1, p0, v0}, Lb1/s;-><init>(Lb1/t;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {p1, v1}, Lb1/o0;->h(Lay0/k;Lc1/a0;)Lb1/t0;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    return-object p0

    .line 150
    :cond_8
    if-ne p1, v2, :cond_9

    .line 151
    .line 152
    new-instance p1, Lb1/s;

    .line 153
    .line 154
    invoke-direct {p1, p0, v2}, Lb1/s;-><init>(Lb1/t;I)V

    .line 155
    .line 156
    .line 157
    invoke-static {p1, v1}, Lb1/o0;->h(Lay0/k;Lc1/a0;)Lb1/t0;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    return-object p0

    .line 162
    :cond_9
    sget-object p0, Lb1/t0;->b:Lb1/t0;

    .line 163
    .line 164
    return-object p0
.end method

.method public static f(Lb1/t;I)Lb1/u0;
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-long v1, v0

    .line 3
    const/16 v3, 0x20

    .line 4
    .line 5
    shl-long v3, v1, v3

    .line 6
    .line 7
    const-wide v5, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v1, v5

    .line 13
    or-long/2addr v1, v3

    .line 14
    new-instance v3, Lt4/j;

    .line 15
    .line 16
    invoke-direct {v3, v1, v2}, Lt4/j;-><init>(J)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x3

    .line 21
    invoke-static {v1, v1, v3, v2}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const/4 v3, 0x4

    .line 29
    if-nez p1, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    if-ne p1, v3, :cond_1

    .line 33
    .line 34
    iget-object v4, p0, Lb1/t;->c:Lt4/m;

    .line 35
    .line 36
    sget-object v5, Lt4/m;->d:Lt4/m;

    .line 37
    .line 38
    if-eq v4, v5, :cond_2

    .line 39
    .line 40
    :cond_1
    const/4 v4, 0x5

    .line 41
    if-ne p1, v4, :cond_3

    .line 42
    .line 43
    iget-object v5, p0, Lb1/t;->c:Lt4/m;

    .line 44
    .line 45
    sget-object v6, Lt4/m;->e:Lt4/m;

    .line 46
    .line 47
    if-ne v5, v6, :cond_3

    .line 48
    .line 49
    :cond_2
    :goto_0
    new-instance p1, Lb1/s;

    .line 50
    .line 51
    invoke-direct {p1, p0, v3}, Lb1/s;-><init>(Lb1/t;I)V

    .line 52
    .line 53
    .line 54
    sget-object p0, Lb1/o0;->a:Lc1/b2;

    .line 55
    .line 56
    new-instance p0, Lb1/n0;

    .line 57
    .line 58
    invoke-direct {p0, v0, p1}, Lb1/n0;-><init>(ILay0/k;)V

    .line 59
    .line 60
    .line 61
    new-instance p1, Lb1/u0;

    .line 62
    .line 63
    new-instance v2, Lb1/i1;

    .line 64
    .line 65
    new-instance v4, Lb1/g1;

    .line 66
    .line 67
    invoke-direct {v4, p0, v1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 68
    .line 69
    .line 70
    const/4 v7, 0x0

    .line 71
    const/16 v8, 0x3d

    .line 72
    .line 73
    const/4 v3, 0x0

    .line 74
    const/4 v5, 0x0

    .line 75
    const/4 v6, 0x0

    .line 76
    invoke-direct/range {v2 .. v8}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p1, v2}, Lb1/u0;-><init>(Lb1/i1;)V

    .line 80
    .line 81
    .line 82
    return-object p1

    .line 83
    :cond_3
    if-ne p1, v0, :cond_4

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_4
    if-ne p1, v3, :cond_5

    .line 87
    .line 88
    iget-object v3, p0, Lb1/t;->c:Lt4/m;

    .line 89
    .line 90
    sget-object v5, Lt4/m;->e:Lt4/m;

    .line 91
    .line 92
    if-eq v3, v5, :cond_6

    .line 93
    .line 94
    :cond_5
    if-ne p1, v4, :cond_7

    .line 95
    .line 96
    iget-object v3, p0, Lb1/t;->c:Lt4/m;

    .line 97
    .line 98
    sget-object v5, Lt4/m;->d:Lt4/m;

    .line 99
    .line 100
    if-ne v3, v5, :cond_7

    .line 101
    .line 102
    :cond_6
    :goto_1
    new-instance p1, Lb1/s;

    .line 103
    .line 104
    invoke-direct {p1, p0, v4}, Lb1/s;-><init>(Lb1/t;I)V

    .line 105
    .line 106
    .line 107
    sget-object p0, Lb1/o0;->a:Lc1/b2;

    .line 108
    .line 109
    new-instance p0, Lb1/n0;

    .line 110
    .line 111
    invoke-direct {p0, v0, p1}, Lb1/n0;-><init>(ILay0/k;)V

    .line 112
    .line 113
    .line 114
    new-instance p1, Lb1/u0;

    .line 115
    .line 116
    new-instance v2, Lb1/i1;

    .line 117
    .line 118
    new-instance v4, Lb1/g1;

    .line 119
    .line 120
    invoke-direct {v4, p0, v1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 121
    .line 122
    .line 123
    const/4 v7, 0x0

    .line 124
    const/16 v8, 0x3d

    .line 125
    .line 126
    const/4 v3, 0x0

    .line 127
    const/4 v5, 0x0

    .line 128
    const/4 v6, 0x0

    .line 129
    invoke-direct/range {v2 .. v8}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 130
    .line 131
    .line 132
    invoke-direct {p1, v2}, Lb1/u0;-><init>(Lb1/i1;)V

    .line 133
    .line 134
    .line 135
    return-object p1

    .line 136
    :cond_7
    const/4 v0, 0x2

    .line 137
    if-ne p1, v0, :cond_8

    .line 138
    .line 139
    new-instance p1, Lb1/s;

    .line 140
    .line 141
    const/4 v0, 0x6

    .line 142
    invoke-direct {p1, p0, v0}, Lb1/s;-><init>(Lb1/t;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {p1, v1}, Lb1/o0;->j(Lay0/k;Lc1/a0;)Lb1/u0;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    return-object p0

    .line 150
    :cond_8
    if-ne p1, v2, :cond_9

    .line 151
    .line 152
    new-instance p1, Lb1/s;

    .line 153
    .line 154
    const/4 v0, 0x7

    .line 155
    invoke-direct {p1, p0, v0}, Lb1/s;-><init>(Lb1/t;I)V

    .line 156
    .line 157
    .line 158
    invoke-static {p1, v1}, Lb1/o0;->j(Lay0/k;Lc1/a0;)Lb1/u0;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0

    .line 163
    :cond_9
    sget-object p0, Lb1/u0;->b:Lb1/u0;

    .line 164
    .line 165
    return-object p0
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lb1/t;->a:Lc1/w1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lc1/w1;->f()Lc1/r1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lc1/r1;->a()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final b()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lb1/t;->a:Lc1/w1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lc1/w1;->f()Lc1/r1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lc1/r1;->b()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
