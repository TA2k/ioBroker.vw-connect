.class public abstract Llp/af;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x3390edc4

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x2

    .line 13
    const/4 v3, 0x1

    .line 14
    if-eq v0, v2, :cond_0

    .line 15
    .line 16
    move v0, v3

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    and-int/lit8 v2, p2, 0x1

    .line 20
    .line 21
    invoke-virtual {p1, v2, v0}, Ll2/t;->O(IZ)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_5

    .line 26
    .line 27
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iget-wide v1, p1, Ll2/t;->T:J

    .line 34
    .line 35
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-static {p1, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 48
    .line 49
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 53
    .line 54
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 55
    .line 56
    .line 57
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 58
    .line 59
    if-eqz v6, :cond_1

    .line 60
    .line 61
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 66
    .line 67
    .line 68
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 69
    .line 70
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 71
    .line 72
    .line 73
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 74
    .line 75
    invoke-static {v0, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 76
    .line 77
    .line 78
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 79
    .line 80
    iget-boolean v2, p1, Ll2/t;->S:Z

    .line 81
    .line 82
    if-nez v2, :cond_2

    .line 83
    .line 84
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-nez v2, :cond_3

    .line 97
    .line 98
    :cond_2
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 99
    .line 100
    .line 101
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 102
    .line 103
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object v0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 107
    .line 108
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 113
    .line 114
    if-ne v1, v2, :cond_4

    .line 115
    .line 116
    new-instance v1, Lkq0/a;

    .line 117
    .line 118
    const/4 v2, 0x6

    .line 119
    invoke-direct {v1, v2}, Lkq0/a;-><init>(I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_4
    check-cast v1, Lay0/k;

    .line 126
    .line 127
    const/16 v2, 0x36

    .line 128
    .line 129
    invoke-static {v0, v1, p1, v2}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 137
    .line 138
    .line 139
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-eqz p1, :cond_6

    .line 144
    .line 145
    new-instance v0, Ll30/a;

    .line 146
    .line 147
    const/4 v1, 0x2

    .line 148
    invoke-direct {v0, p0, p2, v1}, Ll30/a;-><init>(Lx2/s;II)V

    .line 149
    .line 150
    .line 151
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 152
    .line 153
    :cond_6
    return-void
.end method

.method public static final b(Lx2/s;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZLl2/o;I)V
    .locals 7

    .line 1
    move-object v4, p4

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p4, 0x64b7691a

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p4, p5, 0x6

    .line 11
    .line 12
    if-nez p4, :cond_1

    .line 13
    .line 14
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p4

    .line 18
    if-eqz p4, :cond_0

    .line 19
    .line 20
    const/4 p4, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p4, 0x2

    .line 23
    :goto_0
    or-int/2addr p4, p5

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p4, p5

    .line 26
    :goto_1
    and-int/lit8 v0, p5, 0x30

    .line 27
    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    const/16 v0, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v0, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr p4, v0

    .line 46
    :cond_3
    and-int/lit16 v0, p5, 0x180

    .line 47
    .line 48
    if-nez v0, :cond_5

    .line 49
    .line 50
    invoke-virtual {v4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    const/16 v0, 0x100

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_4
    const/16 v0, 0x80

    .line 60
    .line 61
    :goto_3
    or-int/2addr p4, v0

    .line 62
    :cond_5
    and-int/lit16 v0, p5, 0xc00

    .line 63
    .line 64
    if-nez v0, :cond_7

    .line 65
    .line 66
    invoke-virtual {v4, p3}, Ll2/t;->h(Z)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_6

    .line 71
    .line 72
    const/16 v0, 0x800

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_6
    const/16 v0, 0x400

    .line 76
    .line 77
    :goto_4
    or-int/2addr p4, v0

    .line 78
    :cond_7
    and-int/lit16 v0, p4, 0x493

    .line 79
    .line 80
    const/16 v1, 0x492

    .line 81
    .line 82
    const/4 v2, 0x1

    .line 83
    if-eq v0, v1, :cond_8

    .line 84
    .line 85
    move v0, v2

    .line 86
    goto :goto_5

    .line 87
    :cond_8
    const/4 v0, 0x0

    .line 88
    :goto_5
    and-int/2addr p4, v2

    .line 89
    invoke-virtual {v4, p4, v0}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result p4

    .line 93
    if-eqz p4, :cond_9

    .line 94
    .line 95
    sget-wide v0, Ln61/a;->a:J

    .line 96
    .line 97
    sget-object p4, Le3/j0;->a:Le3/i0;

    .line 98
    .line 99
    invoke-static {p0, v0, v1, p4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    new-instance p4, Ld00/i;

    .line 104
    .line 105
    const/4 v1, 0x5

    .line 106
    invoke-direct {p4, p1, p2, p3, v1}, Ld00/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 107
    .line 108
    .line 109
    const v1, -0x5556cf90

    .line 110
    .line 111
    .line 112
    invoke-static {v1, v4, p4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    const/16 v5, 0xc00

    .line 117
    .line 118
    const/4 v6, 0x6

    .line 119
    const/4 v1, 0x0

    .line 120
    const/4 v2, 0x0

    .line 121
    invoke-static/range {v0 .. v6}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 122
    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_9
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 126
    .line 127
    .line 128
    :goto_6
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 129
    .line 130
    .line 131
    move-result-object p4

    .line 132
    if-eqz p4, :cond_a

    .line 133
    .line 134
    new-instance v0, Lbl/d;

    .line 135
    .line 136
    const/4 v6, 0x7

    .line 137
    move-object v1, p0

    .line 138
    move-object v2, p1

    .line 139
    move-object v3, p2

    .line 140
    move v4, p3

    .line 141
    move v5, p5

    .line 142
    invoke-direct/range {v0 .. v6}, Lbl/d;-><init>(Lx2/s;Ljava/lang/Object;Ljava/lang/Object;ZII)V

    .line 143
    .line 144
    .line 145
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 146
    .line 147
    :cond_a
    return-void
.end method

.method public static final c(Lx2/s;Lx61/a;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v5, p2

    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const p2, -0x7cce0731

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p2, p3, 0x6

    .line 16
    .line 17
    if-nez p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {v5, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    const/4 p2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p2, 0x2

    .line 28
    :goto_0
    or-int/2addr p2, p3

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p2, p3

    .line 31
    :goto_1
    and-int/lit8 v0, p3, 0x30

    .line 32
    .line 33
    if-nez v0, :cond_4

    .line 34
    .line 35
    and-int/lit8 v0, p3, 0x40

    .line 36
    .line 37
    if-nez v0, :cond_2

    .line 38
    .line 39
    invoke-virtual {v5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    :goto_2
    if-eqz v0, :cond_3

    .line 49
    .line 50
    const/16 v0, 0x20

    .line 51
    .line 52
    goto :goto_3

    .line 53
    :cond_3
    const/16 v0, 0x10

    .line 54
    .line 55
    :goto_3
    or-int/2addr p2, v0

    .line 56
    :cond_4
    and-int/lit8 v0, p2, 0x13

    .line 57
    .line 58
    const/16 v1, 0x12

    .line 59
    .line 60
    if-eq v0, v1, :cond_5

    .line 61
    .line 62
    const/4 v0, 0x1

    .line 63
    goto :goto_4

    .line 64
    :cond_5
    const/4 v0, 0x0

    .line 65
    :goto_4
    and-int/lit8 v1, p2, 0x1

    .line 66
    .line 67
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_a

    .line 72
    .line 73
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 74
    .line 75
    const/4 v1, 0x0

    .line 76
    if-eqz v0, :cond_6

    .line 77
    .line 78
    move-object v0, p1

    .line 79
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 80
    .line 81
    goto :goto_5

    .line 82
    :cond_6
    move-object v0, v1

    .line 83
    :goto_5
    if-eqz v0, :cond_7

    .line 84
    .line 85
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;->getError()Lyy0/a2;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    goto :goto_6

    .line 90
    :cond_7
    move-object v2, v1

    .line 91
    :goto_6
    invoke-static {v2, v1, v5}, Ljp/pb;->a(Lyy0/a2;Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    if-eqz v0, :cond_8

    .line 96
    .line 97
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;->getCurrentScenario()Lyy0/a2;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    goto :goto_7

    .line 102
    :cond_8
    move-object v3, v1

    .line 103
    :goto_7
    sget-object v4, Ls71/k;->e:Ls71/k;

    .line 104
    .line 105
    invoke-static {v3, v4, v5}, Ljp/pb;->a(Lyy0/a2;Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    if-eqz v0, :cond_9

    .line 110
    .line 111
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;->isDriving()Lyy0/a2;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    :cond_9
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 116
    .line 117
    invoke-static {v1, v0, v5}, Ljp/pb;->a(Lyy0/a2;Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    check-cast v1, Ls71/k;

    .line 126
    .line 127
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    move-object v3, v2

    .line 132
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 133
    .line 134
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Ljava/lang/Boolean;

    .line 139
    .line 140
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 141
    .line 142
    .line 143
    move-result v4

    .line 144
    and-int/lit8 v6, p2, 0xe

    .line 145
    .line 146
    move-object v2, v1

    .line 147
    move-object v1, p0

    .line 148
    invoke-static/range {v1 .. v6}, Llp/af;->b(Lx2/s;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZLl2/o;I)V

    .line 149
    .line 150
    .line 151
    goto :goto_8

    .line 152
    :cond_a
    move-object v1, p0

    .line 153
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 154
    .line 155
    .line 156
    :goto_8
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    if-eqz p0, :cond_b

    .line 161
    .line 162
    new-instance p2, Ljk/b;

    .line 163
    .line 164
    const/4 v0, 0x7

    .line 165
    invoke-direct {p2, p3, v0, v1, p1}, Ljk/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 169
    .line 170
    :cond_b
    return-void
.end method

.method public static final d(Lu01/k;Lu01/y;)V
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Lu01/k;->k(Lu01/y;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_1

    .line 5
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const/4 v0, 0x0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lu01/y;

    .line 21
    .line 22
    :try_start_1
    invoke-virtual {p0, v1}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    iget-boolean v2, v2, Li5/f;->c:Z

    .line 27
    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    invoke-static {p0, v1}, Llp/af;->d(Lu01/k;Lu01/y;)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :catch_0
    move-exception v1

    .line 35
    goto :goto_2

    .line 36
    :cond_1
    :goto_1
    invoke-virtual {p0, v1}, Lu01/k;->g(Lu01/y;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :goto_2
    if-nez v0, :cond_0

    .line 41
    .line 42
    move-object v0, v1

    .line 43
    goto :goto_0

    .line 44
    :cond_2
    if-nez v0, :cond_3

    .line 45
    .line 46
    return-void

    .line 47
    :cond_3
    throw v0

    .line 48
    :catch_1
    return-void
.end method
