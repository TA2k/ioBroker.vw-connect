.class public final Lc3/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc3/j;


# instance fields
.field public final a:Lw3/t;

.field public final b:Lw3/t;

.field public final c:Lc3/v;

.field public final d:Lc3/h;

.field public final e:Landroidx/compose/ui/focus/FocusOwnerImpl$modifier$1;

.field public f:Landroidx/collection/f0;

.field public final g:Landroidx/collection/l0;

.field public h:Lc3/v;


# direct methods
.method public constructor <init>(Lw3/t;Lw3/t;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc3/l;->a:Lw3/t;

    .line 5
    .line 6
    iput-object p2, p0, Lc3/l;->b:Lw3/t;

    .line 7
    .line 8
    new-instance p1, Lc3/v;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x6

    .line 12
    const/4 v2, 0x2

    .line 13
    invoke-direct {p1, v2, v0, v1}, Lc3/v;-><init>(ILay0/n;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lc3/l;->c:Lc3/v;

    .line 17
    .line 18
    new-instance p1, Lc3/h;

    .line 19
    .line 20
    invoke-direct {p1, p0, p2}, Lc3/h;-><init>(Lc3/l;Lw3/t;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lc3/l;->d:Lc3/h;

    .line 24
    .line 25
    new-instance p1, Landroidx/compose/ui/focus/FocusOwnerImpl$modifier$1;

    .line 26
    .line 27
    invoke-direct {p1, p0}, Landroidx/compose/ui/focus/FocusOwnerImpl$modifier$1;-><init>(Lc3/l;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lc3/l;->e:Landroidx/compose/ui/focus/FocusOwnerImpl$modifier$1;

    .line 31
    .line 32
    new-instance p1, Landroidx/collection/l0;

    .line 33
    .line 34
    const/4 p2, 0x1

    .line 35
    invoke-direct {p1, p2}, Landroidx/collection/l0;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lc3/l;->g:Landroidx/collection/l0;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final b(Z)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const/16 v1, 0x8

    .line 3
    .line 4
    invoke-virtual {p0, v1, p1, v0}, Lc3/l;->d(IZZ)Z

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final c(Z)Z
    .locals 7

    .line 1
    iget-object p1, p0, Lc3/l;->h:Lc3/v;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    goto/16 :goto_6

    .line 7
    .line 8
    :cond_0
    const/4 v1, 0x0

    .line 9
    invoke-virtual {p0, v1}, Lc3/l;->i(Lc3/v;)V

    .line 10
    .line 11
    .line 12
    sget-object p0, Lc3/u;->d:Lc3/u;

    .line 13
    .line 14
    sget-object v2, Lc3/u;->g:Lc3/u;

    .line 15
    .line 16
    invoke-virtual {p1, p0, v2}, Lc3/v;->X0(Lc3/u;Lc3/u;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p1, Lx2/r;->d:Lx2/r;

    .line 20
    .line 21
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 22
    .line 23
    if-nez p0, :cond_1

    .line 24
    .line 25
    const-string p0, "visitAncestors called on an unattached node"

    .line 26
    .line 27
    invoke-static {p0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    iget-object p0, p1, Lx2/r;->d:Lx2/r;

    .line 31
    .line 32
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 33
    .line 34
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    :goto_0
    if-eqz p1, :cond_c

    .line 39
    .line 40
    iget-object v2, p1, Lv3/h0;->H:Lg1/q;

    .line 41
    .line 42
    iget-object v2, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v2, Lx2/r;

    .line 45
    .line 46
    iget v2, v2, Lx2/r;->g:I

    .line 47
    .line 48
    and-int/lit16 v2, v2, 0x400

    .line 49
    .line 50
    if-eqz v2, :cond_a

    .line 51
    .line 52
    :goto_1
    if-eqz p0, :cond_a

    .line 53
    .line 54
    iget v2, p0, Lx2/r;->f:I

    .line 55
    .line 56
    and-int/lit16 v2, v2, 0x400

    .line 57
    .line 58
    if-eqz v2, :cond_9

    .line 59
    .line 60
    move-object v2, p0

    .line 61
    move-object v3, v1

    .line 62
    :goto_2
    if-eqz v2, :cond_9

    .line 63
    .line 64
    instance-of v4, v2, Lc3/v;

    .line 65
    .line 66
    if-eqz v4, :cond_2

    .line 67
    .line 68
    check-cast v2, Lc3/v;

    .line 69
    .line 70
    sget-object v4, Lc3/u;->e:Lc3/u;

    .line 71
    .line 72
    sget-object v5, Lc3/u;->g:Lc3/u;

    .line 73
    .line 74
    invoke-virtual {v2, v4, v5}, Lc3/v;->X0(Lc3/u;Lc3/u;)V

    .line 75
    .line 76
    .line 77
    goto :goto_5

    .line 78
    :cond_2
    iget v4, v2, Lx2/r;->f:I

    .line 79
    .line 80
    and-int/lit16 v4, v4, 0x400

    .line 81
    .line 82
    if-eqz v4, :cond_8

    .line 83
    .line 84
    instance-of v4, v2, Lv3/n;

    .line 85
    .line 86
    if-eqz v4, :cond_8

    .line 87
    .line 88
    move-object v4, v2

    .line 89
    check-cast v4, Lv3/n;

    .line 90
    .line 91
    iget-object v4, v4, Lv3/n;->s:Lx2/r;

    .line 92
    .line 93
    const/4 v5, 0x0

    .line 94
    :goto_3
    if-eqz v4, :cond_7

    .line 95
    .line 96
    iget v6, v4, Lx2/r;->f:I

    .line 97
    .line 98
    and-int/lit16 v6, v6, 0x400

    .line 99
    .line 100
    if-eqz v6, :cond_6

    .line 101
    .line 102
    add-int/lit8 v5, v5, 0x1

    .line 103
    .line 104
    if-ne v5, v0, :cond_3

    .line 105
    .line 106
    move-object v2, v4

    .line 107
    goto :goto_4

    .line 108
    :cond_3
    if-nez v3, :cond_4

    .line 109
    .line 110
    new-instance v3, Ln2/b;

    .line 111
    .line 112
    const/16 v6, 0x10

    .line 113
    .line 114
    new-array v6, v6, [Lx2/r;

    .line 115
    .line 116
    invoke-direct {v3, v6}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    :cond_4
    if-eqz v2, :cond_5

    .line 120
    .line 121
    invoke-virtual {v3, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    move-object v2, v1

    .line 125
    :cond_5
    invoke-virtual {v3, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_6
    :goto_4
    iget-object v4, v4, Lx2/r;->i:Lx2/r;

    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_7
    if-ne v5, v0, :cond_8

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_8
    :goto_5
    invoke-static {v3}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    goto :goto_2

    .line 139
    :cond_9
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_a
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    if-eqz p1, :cond_b

    .line 147
    .line 148
    iget-object p0, p1, Lv3/h0;->H:Lg1/q;

    .line 149
    .line 150
    if-eqz p0, :cond_b

    .line 151
    .line 152
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p0, Lv3/z1;

    .line 155
    .line 156
    goto :goto_0

    .line 157
    :cond_b
    move-object p0, v1

    .line 158
    goto :goto_0

    .line 159
    :cond_c
    :goto_6
    return v0
.end method

.method public final d(IZZ)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p2, :cond_3

    .line 3
    .line 4
    iget-object v1, p0, Lc3/l;->c:Lc3/v;

    .line 5
    .line 6
    invoke-static {v1, p1}, Lc3/f;->s(Lc3/v;I)Lc3/b;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-eqz p1, :cond_2

    .line 15
    .line 16
    if-eq p1, v0, :cond_1

    .line 17
    .line 18
    const/4 p2, 0x2

    .line 19
    if-eq p1, p2, :cond_1

    .line 20
    .line 21
    const/4 p2, 0x3

    .line 22
    if-ne p1, p2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 32
    goto :goto_1

    .line 33
    :cond_2
    invoke-virtual {p0, p2}, Lc3/l;->c(Z)Z

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_3
    invoke-virtual {p0, p2}, Lc3/l;->c(Z)Z

    .line 38
    .line 39
    .line 40
    :goto_1
    if-eqz v0, :cond_4

    .line 41
    .line 42
    if-eqz p3, :cond_4

    .line 43
    .line 44
    invoke-virtual {p0}, Lc3/l;->e()V

    .line 45
    .line 46
    .line 47
    :cond_4
    return v0
.end method

.method public final e()V
    .locals 1

    .line 1
    iget-object p0, p0, Lc3/l;->a:Lw3/t;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/view/View;->clearFocus()V

    .line 29
    .line 30
    .line 31
    :cond_1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->clearFocus()V

    .line 32
    .line 33
    .line 34
    :cond_2
    return-void

    .line 35
    :cond_3
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->clearFocus()V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final f(Landroid/view/KeyEvent;Lay0/a;)Z
    .locals 12

    .line 1
    iget-object v0, p0, Lc3/l;->c:Lc3/v;

    .line 2
    .line 3
    const-string v1, "FocusOwnerImpl:dispatchKeyEvent"

    .line 4
    .line 5
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :try_start_0
    iget-object v1, p0, Lc3/l;->d:Lc3/h;

    .line 9
    .line 10
    iget-boolean v1, v1, Lc3/h;->e:Z

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    const-string p0, "FocusRelatedWarning: Dispatching key event while focus system is invalidated."

    .line 16
    .line 17
    sget-object p1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 23
    .line 24
    .line 25
    return v2

    .line 26
    :cond_0
    :try_start_1
    invoke-virtual {p0, p1}, Lc3/l;->j(Landroid/view/KeyEvent;)Z

    .line 27
    .line 28
    .line 29
    move-result p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    if-nez p0, :cond_1

    .line 31
    .line 32
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 33
    .line 34
    .line 35
    return v2

    .line 36
    :cond_1
    :try_start_2
    invoke-static {v0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 37
    .line 38
    .line 39
    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 40
    const-string v1, "visitAncestors called on an unattached node"

    .line 41
    .line 42
    const/16 v3, 0x10

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    const/4 v5, 0x1

    .line 46
    if-eqz p0, :cond_7

    .line 47
    .line 48
    :try_start_3
    iget-object v6, p0, Lx2/r;->d:Lx2/r;

    .line 49
    .line 50
    iget-boolean v6, v6, Lx2/r;->q:Z

    .line 51
    .line 52
    if-nez v6, :cond_2

    .line 53
    .line 54
    const-string v6, "visitLocalDescendants called on an unattached node"

    .line 55
    .line 56
    invoke-static {v6}, Ls3/a;->b(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    :cond_2
    iget-object v6, p0, Lx2/r;->d:Lx2/r;

    .line 60
    .line 61
    iget v7, v6, Lx2/r;->g:I

    .line 62
    .line 63
    and-int/lit16 v7, v7, 0x2400

    .line 64
    .line 65
    if-eqz v7, :cond_5

    .line 66
    .line 67
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 68
    .line 69
    move-object v7, v4

    .line 70
    :goto_0
    if-eqz v6, :cond_6

    .line 71
    .line 72
    iget v8, v6, Lx2/r;->f:I

    .line 73
    .line 74
    and-int/lit16 v9, v8, 0x2400

    .line 75
    .line 76
    if-eqz v9, :cond_4

    .line 77
    .line 78
    and-int/lit16 v8, v8, 0x400

    .line 79
    .line 80
    if-eqz v8, :cond_3

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_3
    move-object v7, v6

    .line 84
    :cond_4
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_5
    move-object v7, v4

    .line 88
    :cond_6
    :goto_1
    if-nez v7, :cond_22

    .line 89
    .line 90
    :cond_7
    if-eqz p0, :cond_14

    .line 91
    .line 92
    iget-object v6, p0, Lx2/r;->d:Lx2/r;

    .line 93
    .line 94
    iget-boolean v6, v6, Lx2/r;->q:Z

    .line 95
    .line 96
    if-nez v6, :cond_8

    .line 97
    .line 98
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    :cond_8
    iget-object v6, p0, Lx2/r;->d:Lx2/r;

    .line 102
    .line 103
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    :goto_2
    if-eqz p0, :cond_13

    .line 108
    .line 109
    iget-object v7, p0, Lv3/h0;->H:Lg1/q;

    .line 110
    .line 111
    iget-object v7, v7, Lg1/q;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v7, Lx2/r;

    .line 114
    .line 115
    iget v7, v7, Lx2/r;->g:I

    .line 116
    .line 117
    and-int/lit16 v7, v7, 0x2000

    .line 118
    .line 119
    if-eqz v7, :cond_11

    .line 120
    .line 121
    :goto_3
    if-eqz v6, :cond_11

    .line 122
    .line 123
    iget v7, v6, Lx2/r;->f:I

    .line 124
    .line 125
    and-int/lit16 v7, v7, 0x2000

    .line 126
    .line 127
    if-eqz v7, :cond_10

    .line 128
    .line 129
    move-object v8, v4

    .line 130
    move-object v7, v6

    .line 131
    :goto_4
    if-eqz v7, :cond_10

    .line 132
    .line 133
    instance-of v9, v7, Ln3/d;

    .line 134
    .line 135
    if-eqz v9, :cond_9

    .line 136
    .line 137
    goto :goto_7

    .line 138
    :cond_9
    iget v9, v7, Lx2/r;->f:I

    .line 139
    .line 140
    and-int/lit16 v9, v9, 0x2000

    .line 141
    .line 142
    if-eqz v9, :cond_f

    .line 143
    .line 144
    instance-of v9, v7, Lv3/n;

    .line 145
    .line 146
    if-eqz v9, :cond_f

    .line 147
    .line 148
    move-object v9, v7

    .line 149
    check-cast v9, Lv3/n;

    .line 150
    .line 151
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 152
    .line 153
    move v10, v2

    .line 154
    :goto_5
    if-eqz v9, :cond_e

    .line 155
    .line 156
    iget v11, v9, Lx2/r;->f:I

    .line 157
    .line 158
    and-int/lit16 v11, v11, 0x2000

    .line 159
    .line 160
    if-eqz v11, :cond_d

    .line 161
    .line 162
    add-int/lit8 v10, v10, 0x1

    .line 163
    .line 164
    if-ne v10, v5, :cond_a

    .line 165
    .line 166
    move-object v7, v9

    .line 167
    goto :goto_6

    .line 168
    :cond_a
    if-nez v8, :cond_b

    .line 169
    .line 170
    new-instance v8, Ln2/b;

    .line 171
    .line 172
    new-array v11, v3, [Lx2/r;

    .line 173
    .line 174
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    :cond_b
    if-eqz v7, :cond_c

    .line 178
    .line 179
    invoke-virtual {v8, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    move-object v7, v4

    .line 183
    :cond_c
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_d
    :goto_6
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_e
    if-ne v10, v5, :cond_f

    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_f
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    goto :goto_4

    .line 197
    :cond_10
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 198
    .line 199
    goto :goto_3

    .line 200
    :cond_11
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    if-eqz p0, :cond_12

    .line 205
    .line 206
    iget-object v6, p0, Lv3/h0;->H:Lg1/q;

    .line 207
    .line 208
    if-eqz v6, :cond_12

    .line 209
    .line 210
    iget-object v6, v6, Lg1/q;->f:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v6, Lv3/z1;

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :cond_12
    move-object v6, v4

    .line 216
    goto :goto_2

    .line 217
    :cond_13
    move-object v7, v4

    .line 218
    :goto_7
    check-cast v7, Ln3/d;

    .line 219
    .line 220
    if-eqz v7, :cond_14

    .line 221
    .line 222
    check-cast v7, Lx2/r;

    .line 223
    .line 224
    iget-object v7, v7, Lx2/r;->d:Lx2/r;

    .line 225
    .line 226
    goto/16 :goto_e

    .line 227
    .line 228
    :cond_14
    iget-object p0, v0, Lx2/r;->d:Lx2/r;

    .line 229
    .line 230
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 231
    .line 232
    if-nez p0, :cond_15

    .line 233
    .line 234
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    :cond_15
    iget-object p0, v0, Lx2/r;->d:Lx2/r;

    .line 238
    .line 239
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 240
    .line 241
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    :goto_8
    if-eqz v0, :cond_20

    .line 246
    .line 247
    iget-object v6, v0, Lv3/h0;->H:Lg1/q;

    .line 248
    .line 249
    iget-object v6, v6, Lg1/q;->g:Ljava/lang/Object;

    .line 250
    .line 251
    check-cast v6, Lx2/r;

    .line 252
    .line 253
    iget v6, v6, Lx2/r;->g:I

    .line 254
    .line 255
    and-int/lit16 v6, v6, 0x2000

    .line 256
    .line 257
    if-eqz v6, :cond_1e

    .line 258
    .line 259
    :goto_9
    if-eqz p0, :cond_1e

    .line 260
    .line 261
    iget v6, p0, Lx2/r;->f:I

    .line 262
    .line 263
    and-int/lit16 v6, v6, 0x2000

    .line 264
    .line 265
    if-eqz v6, :cond_1d

    .line 266
    .line 267
    move-object v6, p0

    .line 268
    move-object v7, v4

    .line 269
    :goto_a
    if-eqz v6, :cond_1d

    .line 270
    .line 271
    instance-of v8, v6, Ln3/d;

    .line 272
    .line 273
    if-eqz v8, :cond_16

    .line 274
    .line 275
    goto :goto_d

    .line 276
    :cond_16
    iget v8, v6, Lx2/r;->f:I

    .line 277
    .line 278
    and-int/lit16 v8, v8, 0x2000

    .line 279
    .line 280
    if-eqz v8, :cond_1c

    .line 281
    .line 282
    instance-of v8, v6, Lv3/n;

    .line 283
    .line 284
    if-eqz v8, :cond_1c

    .line 285
    .line 286
    move-object v8, v6

    .line 287
    check-cast v8, Lv3/n;

    .line 288
    .line 289
    iget-object v8, v8, Lv3/n;->s:Lx2/r;

    .line 290
    .line 291
    move v9, v2

    .line 292
    :goto_b
    if-eqz v8, :cond_1b

    .line 293
    .line 294
    iget v10, v8, Lx2/r;->f:I

    .line 295
    .line 296
    and-int/lit16 v10, v10, 0x2000

    .line 297
    .line 298
    if-eqz v10, :cond_1a

    .line 299
    .line 300
    add-int/lit8 v9, v9, 0x1

    .line 301
    .line 302
    if-ne v9, v5, :cond_17

    .line 303
    .line 304
    move-object v6, v8

    .line 305
    goto :goto_c

    .line 306
    :cond_17
    if-nez v7, :cond_18

    .line 307
    .line 308
    new-instance v7, Ln2/b;

    .line 309
    .line 310
    new-array v10, v3, [Lx2/r;

    .line 311
    .line 312
    invoke-direct {v7, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    :cond_18
    if-eqz v6, :cond_19

    .line 316
    .line 317
    invoke-virtual {v7, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 318
    .line 319
    .line 320
    move-object v6, v4

    .line 321
    :cond_19
    invoke-virtual {v7, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    :cond_1a
    :goto_c
    iget-object v8, v8, Lx2/r;->i:Lx2/r;

    .line 325
    .line 326
    goto :goto_b

    .line 327
    :cond_1b
    if-ne v9, v5, :cond_1c

    .line 328
    .line 329
    goto :goto_a

    .line 330
    :cond_1c
    invoke-static {v7}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 331
    .line 332
    .line 333
    move-result-object v6

    .line 334
    goto :goto_a

    .line 335
    :cond_1d
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 336
    .line 337
    goto :goto_9

    .line 338
    :cond_1e
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    if-eqz v0, :cond_1f

    .line 343
    .line 344
    iget-object p0, v0, Lv3/h0;->H:Lg1/q;

    .line 345
    .line 346
    if-eqz p0, :cond_1f

    .line 347
    .line 348
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast p0, Lv3/z1;

    .line 351
    .line 352
    goto :goto_8

    .line 353
    :cond_1f
    move-object p0, v4

    .line 354
    goto :goto_8

    .line 355
    :cond_20
    move-object v6, v4

    .line 356
    :goto_d
    check-cast v6, Ln3/d;

    .line 357
    .line 358
    if-eqz v6, :cond_21

    .line 359
    .line 360
    check-cast v6, Lx2/r;

    .line 361
    .line 362
    iget-object v7, v6, Lx2/r;->d:Lx2/r;

    .line 363
    .line 364
    goto :goto_e

    .line 365
    :cond_21
    move-object v7, v4

    .line 366
    :cond_22
    :goto_e
    if-eqz v7, :cond_45

    .line 367
    .line 368
    iget-object p0, v7, Lx2/r;->d:Lx2/r;

    .line 369
    .line 370
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 371
    .line 372
    if-nez p0, :cond_23

    .line 373
    .line 374
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    :cond_23
    iget-object p0, v7, Lx2/r;->d:Lx2/r;

    .line 378
    .line 379
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 380
    .line 381
    invoke-static {v7}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 382
    .line 383
    .line 384
    move-result-object v0

    .line 385
    move-object v1, v4

    .line 386
    :goto_f
    if-eqz v0, :cond_2f

    .line 387
    .line 388
    iget-object v6, v0, Lv3/h0;->H:Lg1/q;

    .line 389
    .line 390
    iget-object v6, v6, Lg1/q;->g:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v6, Lx2/r;

    .line 393
    .line 394
    iget v6, v6, Lx2/r;->g:I

    .line 395
    .line 396
    and-int/lit16 v6, v6, 0x2000

    .line 397
    .line 398
    if-eqz v6, :cond_2d

    .line 399
    .line 400
    :goto_10
    if-eqz p0, :cond_2d

    .line 401
    .line 402
    iget v6, p0, Lx2/r;->f:I

    .line 403
    .line 404
    and-int/lit16 v6, v6, 0x2000

    .line 405
    .line 406
    if-eqz v6, :cond_2c

    .line 407
    .line 408
    move-object v6, p0

    .line 409
    move-object v8, v4

    .line 410
    :goto_11
    if-eqz v6, :cond_2c

    .line 411
    .line 412
    instance-of v9, v6, Ln3/d;

    .line 413
    .line 414
    if-eqz v9, :cond_25

    .line 415
    .line 416
    if-nez v1, :cond_24

    .line 417
    .line 418
    new-instance v1, Ljava/util/ArrayList;

    .line 419
    .line 420
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 421
    .line 422
    .line 423
    :cond_24
    invoke-interface {v1, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    goto :goto_14

    .line 427
    :cond_25
    iget v9, v6, Lx2/r;->f:I

    .line 428
    .line 429
    and-int/lit16 v9, v9, 0x2000

    .line 430
    .line 431
    if-eqz v9, :cond_2b

    .line 432
    .line 433
    instance-of v9, v6, Lv3/n;

    .line 434
    .line 435
    if-eqz v9, :cond_2b

    .line 436
    .line 437
    move-object v9, v6

    .line 438
    check-cast v9, Lv3/n;

    .line 439
    .line 440
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 441
    .line 442
    move v10, v2

    .line 443
    :goto_12
    if-eqz v9, :cond_2a

    .line 444
    .line 445
    iget v11, v9, Lx2/r;->f:I

    .line 446
    .line 447
    and-int/lit16 v11, v11, 0x2000

    .line 448
    .line 449
    if-eqz v11, :cond_29

    .line 450
    .line 451
    add-int/lit8 v10, v10, 0x1

    .line 452
    .line 453
    if-ne v10, v5, :cond_26

    .line 454
    .line 455
    move-object v6, v9

    .line 456
    goto :goto_13

    .line 457
    :cond_26
    if-nez v8, :cond_27

    .line 458
    .line 459
    new-instance v8, Ln2/b;

    .line 460
    .line 461
    new-array v11, v3, [Lx2/r;

    .line 462
    .line 463
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 464
    .line 465
    .line 466
    :cond_27
    if-eqz v6, :cond_28

    .line 467
    .line 468
    invoke-virtual {v8, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    move-object v6, v4

    .line 472
    :cond_28
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 473
    .line 474
    .line 475
    :cond_29
    :goto_13
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 476
    .line 477
    goto :goto_12

    .line 478
    :cond_2a
    if-ne v10, v5, :cond_2b

    .line 479
    .line 480
    goto :goto_11

    .line 481
    :cond_2b
    :goto_14
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 482
    .line 483
    .line 484
    move-result-object v6

    .line 485
    goto :goto_11

    .line 486
    :cond_2c
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 487
    .line 488
    goto :goto_10

    .line 489
    :cond_2d
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 490
    .line 491
    .line 492
    move-result-object v0

    .line 493
    if-eqz v0, :cond_2e

    .line 494
    .line 495
    iget-object p0, v0, Lv3/h0;->H:Lg1/q;

    .line 496
    .line 497
    if-eqz p0, :cond_2e

    .line 498
    .line 499
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast p0, Lv3/z1;

    .line 502
    .line 503
    goto :goto_f

    .line 504
    :cond_2e
    move-object p0, v4

    .line 505
    goto :goto_f

    .line 506
    :cond_2f
    if-eqz v1, :cond_32

    .line 507
    .line 508
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 509
    .line 510
    .line 511
    move-result p0

    .line 512
    add-int/lit8 p0, p0, -0x1

    .line 513
    .line 514
    if-ltz p0, :cond_32

    .line 515
    .line 516
    :goto_15
    add-int/lit8 v0, p0, -0x1

    .line 517
    .line 518
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object p0

    .line 522
    check-cast p0, Ln3/d;

    .line 523
    .line 524
    invoke-interface {p0, p1}, Ln3/d;->Z(Landroid/view/KeyEvent;)Z

    .line 525
    .line 526
    .line 527
    move-result p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 528
    if-eqz p0, :cond_30

    .line 529
    .line 530
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 531
    .line 532
    .line 533
    return v5

    .line 534
    :cond_30
    if-gez v0, :cond_31

    .line 535
    .line 536
    goto :goto_16

    .line 537
    :cond_31
    move p0, v0

    .line 538
    goto :goto_15

    .line 539
    :cond_32
    :goto_16
    :try_start_4
    iget-object p0, v7, Lx2/r;->d:Lx2/r;

    .line 540
    .line 541
    move-object v0, v4

    .line 542
    :goto_17
    if-eqz p0, :cond_3a

    .line 543
    .line 544
    instance-of v6, p0, Ln3/d;

    .line 545
    .line 546
    if-eqz v6, :cond_33

    .line 547
    .line 548
    check-cast p0, Ln3/d;

    .line 549
    .line 550
    invoke-interface {p0, p1}, Ln3/d;->Z(Landroid/view/KeyEvent;)Z

    .line 551
    .line 552
    .line 553
    move-result p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 554
    if-eqz p0, :cond_39

    .line 555
    .line 556
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 557
    .line 558
    .line 559
    return v5

    .line 560
    :cond_33
    :try_start_5
    iget v6, p0, Lx2/r;->f:I

    .line 561
    .line 562
    and-int/lit16 v6, v6, 0x2000

    .line 563
    .line 564
    if-eqz v6, :cond_39

    .line 565
    .line 566
    instance-of v6, p0, Lv3/n;

    .line 567
    .line 568
    if-eqz v6, :cond_39

    .line 569
    .line 570
    move-object v6, p0

    .line 571
    check-cast v6, Lv3/n;

    .line 572
    .line 573
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 574
    .line 575
    move v8, v2

    .line 576
    :goto_18
    if-eqz v6, :cond_38

    .line 577
    .line 578
    iget v9, v6, Lx2/r;->f:I

    .line 579
    .line 580
    and-int/lit16 v9, v9, 0x2000

    .line 581
    .line 582
    if-eqz v9, :cond_37

    .line 583
    .line 584
    add-int/lit8 v8, v8, 0x1

    .line 585
    .line 586
    if-ne v8, v5, :cond_34

    .line 587
    .line 588
    move-object p0, v6

    .line 589
    goto :goto_19

    .line 590
    :cond_34
    if-nez v0, :cond_35

    .line 591
    .line 592
    new-instance v0, Ln2/b;

    .line 593
    .line 594
    new-array v9, v3, [Lx2/r;

    .line 595
    .line 596
    invoke-direct {v0, v9}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 597
    .line 598
    .line 599
    :cond_35
    if-eqz p0, :cond_36

    .line 600
    .line 601
    invoke-virtual {v0, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 602
    .line 603
    .line 604
    move-object p0, v4

    .line 605
    :cond_36
    invoke-virtual {v0, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 606
    .line 607
    .line 608
    :cond_37
    :goto_19
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 609
    .line 610
    goto :goto_18

    .line 611
    :cond_38
    if-ne v8, v5, :cond_39

    .line 612
    .line 613
    goto :goto_17

    .line 614
    :cond_39
    invoke-static {v0}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 615
    .line 616
    .line 617
    move-result-object p0

    .line 618
    goto :goto_17

    .line 619
    :cond_3a
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object p0

    .line 623
    check-cast p0, Ljava/lang/Boolean;

    .line 624
    .line 625
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 626
    .line 627
    .line 628
    move-result p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 629
    if-eqz p0, :cond_3b

    .line 630
    .line 631
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 632
    .line 633
    .line 634
    return v5

    .line 635
    :cond_3b
    :try_start_6
    iget-object p0, v7, Lx2/r;->d:Lx2/r;

    .line 636
    .line 637
    move-object p2, v4

    .line 638
    :goto_1a
    if-eqz p0, :cond_43

    .line 639
    .line 640
    instance-of v0, p0, Ln3/d;

    .line 641
    .line 642
    if-eqz v0, :cond_3c

    .line 643
    .line 644
    check-cast p0, Ln3/d;

    .line 645
    .line 646
    invoke-interface {p0, p1}, Ln3/d;->h0(Landroid/view/KeyEvent;)Z

    .line 647
    .line 648
    .line 649
    move-result p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 650
    if-eqz p0, :cond_42

    .line 651
    .line 652
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 653
    .line 654
    .line 655
    return v5

    .line 656
    :cond_3c
    :try_start_7
    iget v0, p0, Lx2/r;->f:I

    .line 657
    .line 658
    and-int/lit16 v0, v0, 0x2000

    .line 659
    .line 660
    if-eqz v0, :cond_42

    .line 661
    .line 662
    instance-of v0, p0, Lv3/n;

    .line 663
    .line 664
    if-eqz v0, :cond_42

    .line 665
    .line 666
    move-object v0, p0

    .line 667
    check-cast v0, Lv3/n;

    .line 668
    .line 669
    iget-object v0, v0, Lv3/n;->s:Lx2/r;

    .line 670
    .line 671
    move v6, v2

    .line 672
    :goto_1b
    if-eqz v0, :cond_41

    .line 673
    .line 674
    iget v7, v0, Lx2/r;->f:I

    .line 675
    .line 676
    and-int/lit16 v7, v7, 0x2000

    .line 677
    .line 678
    if-eqz v7, :cond_40

    .line 679
    .line 680
    add-int/lit8 v6, v6, 0x1

    .line 681
    .line 682
    if-ne v6, v5, :cond_3d

    .line 683
    .line 684
    move-object p0, v0

    .line 685
    goto :goto_1c

    .line 686
    :cond_3d
    if-nez p2, :cond_3e

    .line 687
    .line 688
    new-instance p2, Ln2/b;

    .line 689
    .line 690
    new-array v7, v3, [Lx2/r;

    .line 691
    .line 692
    invoke-direct {p2, v7}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 693
    .line 694
    .line 695
    :cond_3e
    if-eqz p0, :cond_3f

    .line 696
    .line 697
    invoke-virtual {p2, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 698
    .line 699
    .line 700
    move-object p0, v4

    .line 701
    :cond_3f
    invoke-virtual {p2, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 702
    .line 703
    .line 704
    :cond_40
    :goto_1c
    iget-object v0, v0, Lx2/r;->i:Lx2/r;

    .line 705
    .line 706
    goto :goto_1b

    .line 707
    :cond_41
    if-ne v6, v5, :cond_42

    .line 708
    .line 709
    goto :goto_1a

    .line 710
    :cond_42
    invoke-static {p2}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 711
    .line 712
    .line 713
    move-result-object p0

    .line 714
    goto :goto_1a

    .line 715
    :cond_43
    if-eqz v1, :cond_45

    .line 716
    .line 717
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 718
    .line 719
    .line 720
    move-result p0

    .line 721
    move p2, v2

    .line 722
    :goto_1d
    if-ge p2, p0, :cond_45

    .line 723
    .line 724
    invoke-interface {v1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 725
    .line 726
    .line 727
    move-result-object v0

    .line 728
    check-cast v0, Ln3/d;

    .line 729
    .line 730
    invoke-interface {v0, p1}, Ln3/d;->h0(Landroid/view/KeyEvent;)Z

    .line 731
    .line 732
    .line 733
    move-result v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 734
    if-eqz v0, :cond_44

    .line 735
    .line 736
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 737
    .line 738
    .line 739
    return v5

    .line 740
    :cond_44
    add-int/lit8 p2, p2, 0x1

    .line 741
    .line 742
    goto :goto_1d

    .line 743
    :cond_45
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 744
    .line 745
    .line 746
    return v2

    .line 747
    :catchall_0
    move-exception p0

    .line 748
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 749
    .line 750
    .line 751
    throw p0
.end method

.method public final g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    iget-object v4, v0, Lc3/l;->c:Lc3/v;

    .line 10
    .line 11
    invoke-static {v4}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    const/4 v7, 0x4

    .line 16
    const/4 v8, 0x3

    .line 17
    const/4 v9, 0x6

    .line 18
    const/4 v10, 0x5

    .line 19
    const/4 v11, 0x2

    .line 20
    const/4 v12, 0x1

    .line 21
    iget-object v14, v0, Lc3/l;->b:Lw3/t;

    .line 22
    .line 23
    if-eqz v5, :cond_14

    .line 24
    .line 25
    invoke-virtual {v14}, Lw3/t;->getLayoutDirection()Lt4/m;

    .line 26
    .line 27
    .line 28
    move-result-object v16

    .line 29
    const/16 v17, 0x0

    .line 30
    .line 31
    invoke-virtual {v5}, Lc3/v;->Y0()Lc3/o;

    .line 32
    .line 33
    .line 34
    move-result-object v15

    .line 35
    iget-object v6, v15, Lc3/o;->h:Lc3/q;

    .line 36
    .line 37
    iget-object v13, v15, Lc3/o;->i:Lc3/q;

    .line 38
    .line 39
    if-ne v1, v12, :cond_0

    .line 40
    .line 41
    iget-object v6, v15, Lc3/o;->b:Lc3/q;

    .line 42
    .line 43
    goto/16 :goto_4

    .line 44
    .line 45
    :cond_0
    if-ne v1, v11, :cond_1

    .line 46
    .line 47
    iget-object v6, v15, Lc3/o;->c:Lc3/q;

    .line 48
    .line 49
    goto/16 :goto_4

    .line 50
    .line 51
    :cond_1
    if-ne v1, v10, :cond_2

    .line 52
    .line 53
    iget-object v6, v15, Lc3/o;->d:Lc3/q;

    .line 54
    .line 55
    goto/16 :goto_4

    .line 56
    .line 57
    :cond_2
    if-ne v1, v9, :cond_3

    .line 58
    .line 59
    iget-object v6, v15, Lc3/o;->e:Lc3/q;

    .line 60
    .line 61
    goto/16 :goto_4

    .line 62
    .line 63
    :cond_3
    if-ne v1, v8, :cond_7

    .line 64
    .line 65
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-eqz v9, :cond_5

    .line 70
    .line 71
    if-ne v9, v12, :cond_4

    .line 72
    .line 73
    move-object v6, v13

    .line 74
    goto :goto_0

    .line 75
    :cond_4
    new-instance v0, La8/r0;

    .line 76
    .line 77
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_5
    :goto_0
    sget-object v9, Lc3/q;->b:Lc3/q;

    .line 82
    .line 83
    if-ne v6, v9, :cond_6

    .line 84
    .line 85
    move-object/from16 v6, v17

    .line 86
    .line 87
    :cond_6
    if-nez v6, :cond_10

    .line 88
    .line 89
    iget-object v6, v15, Lc3/o;->f:Lc3/q;

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_7
    if-ne v1, v7, :cond_b

    .line 93
    .line 94
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    .line 95
    .line 96
    .line 97
    move-result v9

    .line 98
    if-eqz v9, :cond_9

    .line 99
    .line 100
    if-ne v9, v12, :cond_8

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_8
    new-instance v0, La8/r0;

    .line 104
    .line 105
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 106
    .line 107
    .line 108
    throw v0

    .line 109
    :cond_9
    move-object v6, v13

    .line 110
    :goto_1
    sget-object v9, Lc3/q;->b:Lc3/q;

    .line 111
    .line 112
    if-ne v6, v9, :cond_a

    .line 113
    .line 114
    move-object/from16 v6, v17

    .line 115
    .line 116
    :cond_a
    if-nez v6, :cond_10

    .line 117
    .line 118
    iget-object v6, v15, Lc3/o;->g:Lc3/q;

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_b
    const/4 v6, 0x7

    .line 122
    if-ne v1, v6, :cond_c

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_c
    const/16 v9, 0x8

    .line 126
    .line 127
    if-ne v1, v9, :cond_13

    .line 128
    .line 129
    :goto_2
    new-instance v9, Lc3/a;

    .line 130
    .line 131
    invoke-direct {v9, v1}, Lc3/a;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-static {v5}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 135
    .line 136
    .line 137
    move-result-object v13

    .line 138
    check-cast v13, Lw3/t;

    .line 139
    .line 140
    invoke-virtual {v13}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 141
    .line 142
    .line 143
    move-result-object v13

    .line 144
    check-cast v13, Lc3/l;

    .line 145
    .line 146
    iget-object v10, v13, Lc3/l;->h:Lc3/v;

    .line 147
    .line 148
    if-ne v1, v6, :cond_d

    .line 149
    .line 150
    iget-object v6, v15, Lc3/o;->j:Lkotlin/jvm/internal/n;

    .line 151
    .line 152
    invoke-interface {v6, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_d
    iget-object v6, v15, Lc3/o;->k:Lkotlin/jvm/internal/n;

    .line 157
    .line 158
    invoke-interface {v6, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    :goto_3
    iget-boolean v6, v9, Lc3/a;->b:Z

    .line 162
    .line 163
    if-eqz v6, :cond_e

    .line 164
    .line 165
    sget-object v6, Lc3/q;->c:Lc3/q;

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_e
    iget-object v6, v13, Lc3/l;->h:Lc3/v;

    .line 169
    .line 170
    if-eq v10, v6, :cond_f

    .line 171
    .line 172
    sget-object v6, Lc3/q;->d:Lc3/q;

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_f
    sget-object v6, Lc3/q;->b:Lc3/q;

    .line 176
    .line 177
    :cond_10
    :goto_4
    sget-object v9, Lc3/q;->c:Lc3/q;

    .line 178
    .line 179
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v9

    .line 183
    if-eqz v9, :cond_11

    .line 184
    .line 185
    goto/16 :goto_9

    .line 186
    .line 187
    :cond_11
    sget-object v9, Lc3/q;->d:Lc3/q;

    .line 188
    .line 189
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v9

    .line 193
    if-eqz v9, :cond_12

    .line 194
    .line 195
    invoke-static {v4}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    if-eqz v0, :cond_20

    .line 200
    .line 201
    invoke-interface {v3, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    check-cast v0, Ljava/lang/Boolean;

    .line 206
    .line 207
    return-object v0

    .line 208
    :cond_12
    sget-object v9, Lc3/q;->b:Lc3/q;

    .line 209
    .line 210
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v9

    .line 214
    if-nez v9, :cond_15

    .line 215
    .line 216
    invoke-virtual {v6, v3}, Lc3/q;->a(Lay0/k;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    return-object v0

    .line 225
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 226
    .line 227
    const-string v1, "invalid FocusDirection"

    .line 228
    .line 229
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    throw v0

    .line 233
    :cond_14
    const/16 v17, 0x0

    .line 234
    .line 235
    move-object/from16 v5, v17

    .line 236
    .line 237
    :cond_15
    invoke-virtual {v14}, Lw3/t;->getLayoutDirection()Lt4/m;

    .line 238
    .line 239
    .line 240
    move-result-object v6

    .line 241
    new-instance v9, La3/g;

    .line 242
    .line 243
    invoke-direct {v9, v5, v0, v3}, La3/g;-><init>(Lc3/v;Lc3/l;Lay0/k;)V

    .line 244
    .line 245
    .line 246
    if-ne v1, v12, :cond_16

    .line 247
    .line 248
    goto :goto_5

    .line 249
    :cond_16
    if-ne v1, v11, :cond_19

    .line 250
    .line 251
    :goto_5
    if-ne v1, v12, :cond_17

    .line 252
    .line 253
    invoke-static {v4, v9}, Lc3/f;->k(Lc3/v;La3/g;)Z

    .line 254
    .line 255
    .line 256
    move-result v0

    .line 257
    goto :goto_6

    .line 258
    :cond_17
    if-ne v1, v11, :cond_18

    .line 259
    .line 260
    invoke-static {v4, v9}, Lc3/f;->a(Lc3/v;La3/g;)Z

    .line 261
    .line 262
    .line 263
    move-result v0

    .line 264
    :goto_6
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    return-object v0

    .line 269
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 270
    .line 271
    const-string v1, "This function should only be used for 1-D focus search"

    .line 272
    .line 273
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_19
    if-ne v1, v8, :cond_1a

    .line 278
    .line 279
    goto :goto_7

    .line 280
    :cond_1a
    if-ne v1, v7, :cond_1b

    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_1b
    const/4 v0, 0x5

    .line 284
    if-ne v1, v0, :cond_1c

    .line 285
    .line 286
    goto :goto_7

    .line 287
    :cond_1c
    const/4 v0, 0x6

    .line 288
    if-ne v1, v0, :cond_1d

    .line 289
    .line 290
    :goto_7
    invoke-static {v1, v9, v4, v2}, Lc3/f;->E(ILa3/g;Lc3/v;Ld3/c;)Ljava/lang/Boolean;

    .line 291
    .line 292
    .line 293
    move-result-object v0

    .line 294
    return-object v0

    .line 295
    :cond_1d
    const/4 v0, 0x7

    .line 296
    if-ne v1, v0, :cond_21

    .line 297
    .line 298
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 299
    .line 300
    .line 301
    move-result v0

    .line 302
    if-eqz v0, :cond_1f

    .line 303
    .line 304
    if-ne v0, v12, :cond_1e

    .line 305
    .line 306
    move v7, v8

    .line 307
    goto :goto_8

    .line 308
    :cond_1e
    new-instance v0, La8/r0;

    .line 309
    .line 310
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 311
    .line 312
    .line 313
    throw v0

    .line 314
    :cond_1f
    :goto_8
    invoke-static {v4}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    if-eqz v0, :cond_20

    .line 319
    .line 320
    invoke-static {v7, v9, v0, v2}, Lc3/f;->E(ILa3/g;Lc3/v;Ld3/c;)Ljava/lang/Boolean;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    return-object v0

    .line 325
    :cond_20
    :goto_9
    return-object v17

    .line 326
    :cond_21
    const/16 v0, 0x8

    .line 327
    .line 328
    if-ne v1, v0, :cond_30

    .line 329
    .line 330
    invoke-static {v4}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    const/4 v1, 0x0

    .line 335
    if-eqz v0, :cond_2d

    .line 336
    .line 337
    iget-object v2, v0, Lx2/r;->d:Lx2/r;

    .line 338
    .line 339
    iget-boolean v2, v2, Lx2/r;->q:Z

    .line 340
    .line 341
    if-nez v2, :cond_22

    .line 342
    .line 343
    const-string v2, "visitAncestors called on an unattached node"

    .line 344
    .line 345
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 346
    .line 347
    .line 348
    :cond_22
    iget-object v2, v0, Lx2/r;->d:Lx2/r;

    .line 349
    .line 350
    iget-object v2, v2, Lx2/r;->h:Lx2/r;

    .line 351
    .line 352
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    :goto_a
    if-eqz v0, :cond_2d

    .line 357
    .line 358
    iget-object v3, v0, Lv3/h0;->H:Lg1/q;

    .line 359
    .line 360
    iget-object v3, v3, Lg1/q;->g:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v3, Lx2/r;

    .line 363
    .line 364
    iget v3, v3, Lx2/r;->g:I

    .line 365
    .line 366
    and-int/lit16 v3, v3, 0x400

    .line 367
    .line 368
    if-eqz v3, :cond_2b

    .line 369
    .line 370
    :goto_b
    if-eqz v2, :cond_2b

    .line 371
    .line 372
    iget v3, v2, Lx2/r;->f:I

    .line 373
    .line 374
    and-int/lit16 v3, v3, 0x400

    .line 375
    .line 376
    if-eqz v3, :cond_2a

    .line 377
    .line 378
    move-object v3, v2

    .line 379
    move-object/from16 v5, v17

    .line 380
    .line 381
    :goto_c
    if-eqz v3, :cond_2a

    .line 382
    .line 383
    instance-of v6, v3, Lc3/v;

    .line 384
    .line 385
    if-eqz v6, :cond_23

    .line 386
    .line 387
    check-cast v3, Lc3/v;

    .line 388
    .line 389
    invoke-virtual {v3}, Lc3/v;->Y0()Lc3/o;

    .line 390
    .line 391
    .line 392
    move-result-object v6

    .line 393
    iget-boolean v6, v6, Lc3/o;->a:Z

    .line 394
    .line 395
    if-eqz v6, :cond_29

    .line 396
    .line 397
    move-object v15, v3

    .line 398
    goto :goto_f

    .line 399
    :cond_23
    iget v6, v3, Lx2/r;->f:I

    .line 400
    .line 401
    and-int/lit16 v6, v6, 0x400

    .line 402
    .line 403
    if-eqz v6, :cond_29

    .line 404
    .line 405
    instance-of v6, v3, Lv3/n;

    .line 406
    .line 407
    if-eqz v6, :cond_29

    .line 408
    .line 409
    move-object v6, v3

    .line 410
    check-cast v6, Lv3/n;

    .line 411
    .line 412
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 413
    .line 414
    move v7, v1

    .line 415
    :goto_d
    if-eqz v6, :cond_28

    .line 416
    .line 417
    iget v8, v6, Lx2/r;->f:I

    .line 418
    .line 419
    and-int/lit16 v8, v8, 0x400

    .line 420
    .line 421
    if-eqz v8, :cond_27

    .line 422
    .line 423
    add-int/lit8 v7, v7, 0x1

    .line 424
    .line 425
    if-ne v7, v12, :cond_24

    .line 426
    .line 427
    move-object v3, v6

    .line 428
    goto :goto_e

    .line 429
    :cond_24
    if-nez v5, :cond_25

    .line 430
    .line 431
    new-instance v5, Ln2/b;

    .line 432
    .line 433
    const/16 v8, 0x10

    .line 434
    .line 435
    new-array v8, v8, [Lx2/r;

    .line 436
    .line 437
    invoke-direct {v5, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    :cond_25
    if-eqz v3, :cond_26

    .line 441
    .line 442
    invoke-virtual {v5, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 443
    .line 444
    .line 445
    move-object/from16 v3, v17

    .line 446
    .line 447
    :cond_26
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 448
    .line 449
    .line 450
    :cond_27
    :goto_e
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 451
    .line 452
    goto :goto_d

    .line 453
    :cond_28
    if-ne v7, v12, :cond_29

    .line 454
    .line 455
    goto :goto_c

    .line 456
    :cond_29
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 457
    .line 458
    .line 459
    move-result-object v3

    .line 460
    goto :goto_c

    .line 461
    :cond_2a
    iget-object v2, v2, Lx2/r;->h:Lx2/r;

    .line 462
    .line 463
    goto :goto_b

    .line 464
    :cond_2b
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 465
    .line 466
    .line 467
    move-result-object v0

    .line 468
    if-eqz v0, :cond_2c

    .line 469
    .line 470
    iget-object v2, v0, Lv3/h0;->H:Lg1/q;

    .line 471
    .line 472
    if-eqz v2, :cond_2c

    .line 473
    .line 474
    iget-object v2, v2, Lg1/q;->f:Ljava/lang/Object;

    .line 475
    .line 476
    check-cast v2, Lv3/z1;

    .line 477
    .line 478
    goto :goto_a

    .line 479
    :cond_2c
    move-object/from16 v2, v17

    .line 480
    .line 481
    goto :goto_a

    .line 482
    :cond_2d
    move-object/from16 v15, v17

    .line 483
    .line 484
    :goto_f
    if-eqz v15, :cond_2f

    .line 485
    .line 486
    invoke-virtual {v15, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 487
    .line 488
    .line 489
    move-result v0

    .line 490
    if-eqz v0, :cond_2e

    .line 491
    .line 492
    goto :goto_10

    .line 493
    :cond_2e
    invoke-virtual {v9, v15}, La3/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    check-cast v0, Ljava/lang/Boolean;

    .line 498
    .line 499
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 500
    .line 501
    .line 502
    move-result v1

    .line 503
    :cond_2f
    :goto_10
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    return-object v0

    .line 508
    :cond_30
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 509
    .line 510
    new-instance v2, Ljava/lang/StringBuilder;

    .line 511
    .line 512
    const-string v3, "Focus search invoked with invalid FocusDirection "

    .line 513
    .line 514
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    invoke-static {v1}, Lc3/d;->a(I)Ljava/lang/String;

    .line 518
    .line 519
    .line 520
    move-result-object v1

    .line 521
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 522
    .line 523
    .line 524
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 525
    .line 526
    .line 527
    move-result-object v1

    .line 528
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 529
    .line 530
    .line 531
    move-result-object v1

    .line 532
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    throw v0
.end method

.method public final h(I)Z
    .locals 9

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 7
    .line 8
    iput-object v1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object v1, p0, Lc3/l;->h:Lc3/v;

    .line 11
    .line 12
    iget-object v6, p0, Lc3/l;->a:Lw3/t;

    .line 13
    .line 14
    invoke-virtual {v6}, Lw3/t;->getEmbeddedViewFocusRect()Ld3/c;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    new-instance v3, Lym/d;

    .line 19
    .line 20
    const/4 v4, 0x2

    .line 21
    invoke-direct {v3, v0, p1, v4}, Lym/d;-><init>(Ljava/lang/Object;II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1, v2, v3}, Lc3/l;->g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    const/4 v8, 0x1

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    iget-object v3, p0, Lc3/l;->h:Lc3/v;

    .line 38
    .line 39
    if-eq v1, v3, :cond_0

    .line 40
    .line 41
    goto/16 :goto_7

    .line 42
    .line 43
    :cond_0
    const/4 v1, 0x0

    .line 44
    if-eqz v2, :cond_d

    .line 45
    .line 46
    iget-object v3, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 47
    .line 48
    if-nez v3, :cond_1

    .line 49
    .line 50
    goto/16 :goto_9

    .line 51
    .line 52
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ljava/lang/Boolean;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    goto/16 :goto_7

    .line 69
    .line 70
    :cond_2
    const/4 v0, 0x0

    .line 71
    if-ne p1, v8, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    const/4 v2, 0x2

    .line 75
    if-ne p1, v2, :cond_5

    .line 76
    .line 77
    :goto_0
    invoke-virtual {p0, p1, v1, v1}, Lc3/l;->d(IZZ)Z

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    if-eqz v2, :cond_d

    .line 82
    .line 83
    new-instance v2, Lc3/k;

    .line 84
    .line 85
    const/4 v3, 0x0

    .line 86
    invoke-direct {v2, p1, v3}, Lc3/k;-><init>(II)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0, p1, v0, v2}, Lc3/l;->g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-eqz p0, :cond_4

    .line 94
    .line 95
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    goto :goto_1

    .line 100
    :cond_4
    move p0, v1

    .line 101
    :goto_1
    if-eqz p0, :cond_d

    .line 102
    .line 103
    goto/16 :goto_7

    .line 104
    .line 105
    :cond_5
    const/4 p0, 0x7

    .line 106
    if-ne p1, p0, :cond_6

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_6
    const/16 p0, 0x8

    .line 110
    .line 111
    if-ne p1, p0, :cond_7

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_7
    invoke-static {p1}, Lc3/f;->C(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    if-eqz p0, :cond_c

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    invoke-virtual {v6}, Lw3/t;->getEmbeddedViewFocusRect()Ld3/c;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-eqz p0, :cond_8

    .line 129
    .line 130
    invoke-static {p0}, Le3/j0;->v(Ld3/c;)Landroid/graphics/Rect;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    goto :goto_2

    .line 135
    :cond_8
    move-object p0, v0

    .line 136
    :goto_2
    sget-object p1, Lw3/m1;->f:Ley0/b;

    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    move-object v2, p1

    .line 146
    check-cast v2, Lw3/m1;

    .line 147
    .line 148
    if-nez p0, :cond_9

    .line 149
    .line 150
    invoke-virtual {v6}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {v2, v3, p1, v6}, Lw3/m1;->b(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    goto :goto_4

    .line 159
    :cond_9
    iget-object p1, v2, Lw3/m1;->a:Landroid/graphics/Rect;

    .line 160
    .line 161
    invoke-virtual {p1, p0}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 162
    .line 163
    .line 164
    iget-object v4, v2, Lw3/m1;->a:Landroid/graphics/Rect;

    .line 165
    .line 166
    iget-object v7, v2, Lw3/m1;->e:Ljava/util/ArrayList;

    .line 167
    .line 168
    :try_start_0
    invoke-virtual {v7}, Ljava/util/ArrayList;->clear()V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v6}, Landroid/view/View;->isInTouchMode()Z

    .line 172
    .line 173
    .line 174
    move-result p1

    .line 175
    invoke-virtual {v6, v7, v3, p1}, Landroid/view/View;->addFocusables(Ljava/util/ArrayList;II)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 179
    .line 180
    .line 181
    move-result p1

    .line 182
    if-nez p1, :cond_a

    .line 183
    .line 184
    const/4 v5, 0x0

    .line 185
    invoke-virtual/range {v2 .. v7}, Lw3/m1;->a(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;

    .line 186
    .line 187
    .line 188
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 189
    :cond_a
    invoke-virtual {v7}, Ljava/util/ArrayList;->clear()V

    .line 190
    .line 191
    .line 192
    goto :goto_3

    .line 193
    :catchall_0
    move-exception v0

    .line 194
    move-object p0, v0

    .line 195
    goto :goto_8

    .line 196
    :goto_3
    move-object p1, v0

    .line 197
    :goto_4
    if-eqz p1, :cond_b

    .line 198
    .line 199
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-static {p1, v0, p0}, Lc3/f;->y(Landroid/view/View;Ljava/lang/Integer;Landroid/graphics/Rect;)Z

    .line 204
    .line 205
    .line 206
    move-result p0

    .line 207
    goto :goto_6

    .line 208
    :cond_b
    :goto_5
    move p0, v1

    .line 209
    :goto_6
    if-eqz p0, :cond_d

    .line 210
    .line 211
    :goto_7
    return v8

    .line 212
    :goto_8
    invoke-virtual {v7}, Ljava/util/ArrayList;->clear()V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 217
    .line 218
    const-string p1, "Invalid focus direction"

    .line 219
    .line 220
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p0

    .line 224
    :cond_d
    :goto_9
    return v1
.end method

.method public final i(Lc3/v;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lc3/l;->h:Lc3/v;

    .line 2
    .line 3
    iput-object p1, p0, Lc3/l;->h:Lc3/v;

    .line 4
    .line 5
    iget-object p0, p0, Lc3/l;->g:Landroidx/collection/l0;

    .line 6
    .line 7
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 8
    .line 9
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, p0, :cond_2

    .line 13
    .line 14
    aget-object v3, v1, v2

    .line 15
    .line 16
    check-cast v3, Ly2/b;

    .line 17
    .line 18
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    const/4 v4, 0x1

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    if-eqz v5, :cond_0

    .line 29
    .line 30
    invoke-virtual {v5}, Lv3/h0;->x()Ld4/l;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    if-eqz v6, :cond_0

    .line 35
    .line 36
    iget-object v6, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 37
    .line 38
    sget-object v7, Ld4/k;->g:Ld4/z;

    .line 39
    .line 40
    invoke-virtual {v6, v7}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    if-ne v6, v4, :cond_0

    .line 45
    .line 46
    iget-object v6, v3, Ly2/b;->a:Lpv/g;

    .line 47
    .line 48
    iget-object v7, v3, Ly2/b;->c:Lw3/t;

    .line 49
    .line 50
    iget v5, v5, Lv3/h0;->e:I

    .line 51
    .line 52
    iget-object v6, v6, Lpv/g;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v6, Landroid/view/autofill/AutofillManager;

    .line 55
    .line 56
    invoke-virtual {v6, v7, v5}, Landroid/view/autofill/AutofillManager;->notifyViewExited(Landroid/view/View;I)V

    .line 57
    .line 58
    .line 59
    :cond_0
    if-eqz p1, :cond_1

    .line 60
    .line 61
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    if-eqz v5, :cond_1

    .line 66
    .line 67
    invoke-virtual {v5}, Lv3/h0;->x()Ld4/l;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    if-eqz v6, :cond_1

    .line 72
    .line 73
    iget-object v6, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 74
    .line 75
    sget-object v7, Ld4/k;->g:Ld4/z;

    .line 76
    .line 77
    invoke-virtual {v6, v7}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-ne v6, v4, :cond_1

    .line 82
    .line 83
    iget v4, v5, Lv3/h0;->e:I

    .line 84
    .line 85
    iget-object v5, v3, Ly2/b;->d:Le4/a;

    .line 86
    .line 87
    iget-object v5, v5, Le4/a;->a:Lbb/g0;

    .line 88
    .line 89
    new-instance v6, Ly2/a;

    .line 90
    .line 91
    invoke-direct {v6, v3, v4}, Ly2/a;-><init>(Ly2/b;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v5, v4, v6}, Lbb/g0;->u(ILay0/p;)V

    .line 95
    .line 96
    .line 97
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_2
    return-void
.end method

.method public final j(Landroid/view/KeyEvent;)Z
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static/range {p1 .. p1}, Ln3/c;->b(Landroid/view/KeyEvent;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static/range {p1 .. p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/4 v4, 0x2

    .line 12
    const v10, -0x3361d2af    # -8.2930312E7f

    .line 13
    .line 14
    .line 15
    const-wide/16 v15, 0x0

    .line 16
    .line 17
    const-wide v17, 0x101010101010101L

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    const-wide/16 v19, 0xfe

    .line 23
    .line 24
    const/16 p1, 0x6

    .line 25
    .line 26
    const/16 v5, 0x8

    .line 27
    .line 28
    const/16 v21, 0x0

    .line 29
    .line 30
    const-wide/16 v22, 0x1

    .line 31
    .line 32
    const/4 v6, 0x3

    .line 33
    const/4 v7, 0x1

    .line 34
    if-ne v3, v4, :cond_10

    .line 35
    .line 36
    iget-object v3, v0, Lc3/l;->f:Landroidx/collection/f0;

    .line 37
    .line 38
    if-nez v3, :cond_0

    .line 39
    .line 40
    new-instance v3, Landroidx/collection/f0;

    .line 41
    .line 42
    invoke-direct {v3, v6}, Landroidx/collection/f0;-><init>(I)V

    .line 43
    .line 44
    .line 45
    iput-object v3, v0, Lc3/l;->f:Landroidx/collection/f0;

    .line 46
    .line 47
    :cond_0
    move-object v4, v3

    .line 48
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    mul-int/2addr v0, v10

    .line 53
    shl-int/lit8 v3, v0, 0x10

    .line 54
    .line 55
    xor-int/2addr v0, v3

    .line 56
    ushr-int/lit8 v3, v0, 0x7

    .line 57
    .line 58
    and-int/lit8 v0, v0, 0x7f

    .line 59
    .line 60
    move/from16 v24, v6

    .line 61
    .line 62
    iget v6, v4, Landroidx/collection/f0;->c:I

    .line 63
    .line 64
    and-int v25, v3, v6

    .line 65
    .line 66
    move/from16 v26, v21

    .line 67
    .line 68
    const/16 v27, 0x3f

    .line 69
    .line 70
    :goto_0
    iget-object v8, v4, Landroidx/collection/f0;->a:[J

    .line 71
    .line 72
    shr-int/lit8 v28, v25, 0x3

    .line 73
    .line 74
    and-int/lit8 v29, v25, 0x7

    .line 75
    .line 76
    const/16 v30, 0x7

    .line 77
    .line 78
    shl-int/lit8 v9, v29, 0x3

    .line 79
    .line 80
    aget-wide v31, v8, v28

    .line 81
    .line 82
    ushr-long v31, v31, v9

    .line 83
    .line 84
    add-int/lit8 v28, v28, 0x1

    .line 85
    .line 86
    aget-wide v28, v8, v28

    .line 87
    .line 88
    rsub-int/lit8 v8, v9, 0x40

    .line 89
    .line 90
    shl-long v28, v28, v8

    .line 91
    .line 92
    int-to-long v8, v9

    .line 93
    neg-long v8, v8

    .line 94
    shr-long v8, v8, v27

    .line 95
    .line 96
    and-long v8, v28, v8

    .line 97
    .line 98
    or-long v8, v31, v8

    .line 99
    .line 100
    move/from16 v28, v10

    .line 101
    .line 102
    const-wide/16 v31, 0xff

    .line 103
    .line 104
    int-to-long v10, v0

    .line 105
    mul-long v33, v10, v17

    .line 106
    .line 107
    const-wide v35, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    xor-long v13, v8, v33

    .line 113
    .line 114
    sub-long v33, v13, v17

    .line 115
    .line 116
    not-long v12, v13

    .line 117
    and-long v12, v33, v12

    .line 118
    .line 119
    and-long v12, v12, v35

    .line 120
    .line 121
    :goto_1
    cmp-long v14, v12, v15

    .line 122
    .line 123
    if-eqz v14, :cond_2

    .line 124
    .line 125
    invoke-static {v12, v13}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 126
    .line 127
    .line 128
    move-result v14

    .line 129
    shr-int/lit8 v14, v14, 0x3

    .line 130
    .line 131
    add-int v14, v25, v14

    .line 132
    .line 133
    and-int/2addr v14, v6

    .line 134
    move-wide/from16 v33, v15

    .line 135
    .line 136
    iget-object v15, v4, Landroidx/collection/f0;->b:[J

    .line 137
    .line 138
    aget-wide v15, v15, v14

    .line 139
    .line 140
    cmp-long v15, v15, v1

    .line 141
    .line 142
    if-nez v15, :cond_1

    .line 143
    .line 144
    move/from16 v37, v7

    .line 145
    .line 146
    goto/16 :goto_b

    .line 147
    .line 148
    :cond_1
    sub-long v14, v12, v22

    .line 149
    .line 150
    and-long/2addr v12, v14

    .line 151
    move-wide/from16 v15, v33

    .line 152
    .line 153
    goto :goto_1

    .line 154
    :cond_2
    move-wide/from16 v33, v15

    .line 155
    .line 156
    not-long v12, v8

    .line 157
    shl-long v12, v12, p1

    .line 158
    .line 159
    and-long/2addr v8, v12

    .line 160
    and-long v8, v8, v35

    .line 161
    .line 162
    cmp-long v8, v8, v33

    .line 163
    .line 164
    if-eqz v8, :cond_f

    .line 165
    .line 166
    invoke-virtual {v4, v3}, Landroidx/collection/f0;->b(I)I

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    iget v6, v4, Landroidx/collection/f0;->e:I

    .line 171
    .line 172
    if-nez v6, :cond_3

    .line 173
    .line 174
    iget-object v6, v4, Landroidx/collection/f0;->a:[J

    .line 175
    .line 176
    shr-int/lit8 v12, v0, 0x3

    .line 177
    .line 178
    aget-wide v12, v6, v12

    .line 179
    .line 180
    and-int/lit8 v6, v0, 0x7

    .line 181
    .line 182
    shl-int/lit8 v6, v6, 0x3

    .line 183
    .line 184
    shr-long/2addr v12, v6

    .line 185
    and-long v12, v12, v31

    .line 186
    .line 187
    cmp-long v6, v12, v19

    .line 188
    .line 189
    if-nez v6, :cond_4

    .line 190
    .line 191
    :cond_3
    move/from16 v37, v7

    .line 192
    .line 193
    const-wide/16 p0, 0x80

    .line 194
    .line 195
    goto/16 :goto_a

    .line 196
    .line 197
    :cond_4
    iget v0, v4, Landroidx/collection/f0;->c:I

    .line 198
    .line 199
    if-le v0, v5, :cond_b

    .line 200
    .line 201
    iget v6, v4, Landroidx/collection/f0;->d:I

    .line 202
    .line 203
    int-to-long v12, v6

    .line 204
    const-wide/16 v14, 0x20

    .line 205
    .line 206
    mul-long/2addr v12, v14

    .line 207
    int-to-long v14, v0

    .line 208
    const-wide/16 v16, 0x19

    .line 209
    .line 210
    mul-long v14, v14, v16

    .line 211
    .line 212
    invoke-static {v12, v13, v14, v15}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 213
    .line 214
    .line 215
    move-result v0

    .line 216
    if-gtz v0, :cond_b

    .line 217
    .line 218
    iget-object v0, v4, Landroidx/collection/f0;->a:[J

    .line 219
    .line 220
    iget v6, v4, Landroidx/collection/f0;->c:I

    .line 221
    .line 222
    iget-object v12, v4, Landroidx/collection/f0;->b:[J

    .line 223
    .line 224
    add-int/lit8 v13, v6, 0x7

    .line 225
    .line 226
    shr-int/lit8 v13, v13, 0x3

    .line 227
    .line 228
    move/from16 v14, v21

    .line 229
    .line 230
    :goto_2
    if-ge v14, v13, :cond_5

    .line 231
    .line 232
    aget-wide v15, v0, v14

    .line 233
    .line 234
    const-wide/16 p0, 0x80

    .line 235
    .line 236
    and-long v8, v15, v35

    .line 237
    .line 238
    move v15, v5

    .line 239
    move/from16 v16, v6

    .line 240
    .line 241
    not-long v5, v8

    .line 242
    ushr-long v8, v8, v30

    .line 243
    .line 244
    add-long/2addr v5, v8

    .line 245
    const-wide v8, -0x101010101010102L

    .line 246
    .line 247
    .line 248
    .line 249
    .line 250
    and-long/2addr v5, v8

    .line 251
    aput-wide v5, v0, v14

    .line 252
    .line 253
    add-int/lit8 v14, v14, 0x1

    .line 254
    .line 255
    move v5, v15

    .line 256
    move/from16 v6, v16

    .line 257
    .line 258
    goto :goto_2

    .line 259
    :cond_5
    move v15, v5

    .line 260
    move/from16 v16, v6

    .line 261
    .line 262
    const-wide/16 p0, 0x80

    .line 263
    .line 264
    invoke-static {v0}, Lmx0/n;->A([J)I

    .line 265
    .line 266
    .line 267
    move-result v5

    .line 268
    add-int/lit8 v6, v5, -0x1

    .line 269
    .line 270
    aget-wide v8, v0, v6

    .line 271
    .line 272
    const-wide v13, 0xffffffffffffffL

    .line 273
    .line 274
    .line 275
    .line 276
    .line 277
    and-long/2addr v8, v13

    .line 278
    const-wide/high16 v17, -0x100000000000000L

    .line 279
    .line 280
    or-long v8, v8, v17

    .line 281
    .line 282
    aput-wide v8, v0, v6

    .line 283
    .line 284
    aget-wide v8, v0, v21

    .line 285
    .line 286
    aput-wide v8, v0, v5

    .line 287
    .line 288
    move/from16 v5, v16

    .line 289
    .line 290
    move/from16 v6, v21

    .line 291
    .line 292
    :goto_3
    if-eq v6, v5, :cond_a

    .line 293
    .line 294
    shr-int/lit8 v8, v6, 0x3

    .line 295
    .line 296
    aget-wide v16, v0, v8

    .line 297
    .line 298
    and-int/lit8 v9, v6, 0x7

    .line 299
    .line 300
    shl-int/lit8 v9, v9, 0x3

    .line 301
    .line 302
    shr-long v16, v16, v9

    .line 303
    .line 304
    and-long v16, v16, v31

    .line 305
    .line 306
    cmp-long v18, v16, p0

    .line 307
    .line 308
    if-nez v18, :cond_6

    .line 309
    .line 310
    :goto_4
    add-int/lit8 v6, v6, 0x1

    .line 311
    .line 312
    goto :goto_3

    .line 313
    :cond_6
    cmp-long v16, v16, v19

    .line 314
    .line 315
    if-eqz v16, :cond_7

    .line 316
    .line 317
    goto :goto_4

    .line 318
    :cond_7
    aget-wide v16, v12, v6

    .line 319
    .line 320
    invoke-static/range {v16 .. v17}, Ljava/lang/Long;->hashCode(J)I

    .line 321
    .line 322
    .line 323
    move-result v16

    .line 324
    mul-int v16, v16, v28

    .line 325
    .line 326
    shl-int/lit8 v17, v16, 0x10

    .line 327
    .line 328
    xor-int v16, v16, v17

    .line 329
    .line 330
    move-wide/from16 v17, v13

    .line 331
    .line 332
    ushr-int/lit8 v13, v16, 0x7

    .line 333
    .line 334
    invoke-virtual {v4, v13}, Landroidx/collection/f0;->b(I)I

    .line 335
    .line 336
    .line 337
    move-result v14

    .line 338
    and-int/2addr v13, v5

    .line 339
    sub-int v22, v14, v13

    .line 340
    .line 341
    and-int v22, v22, v5

    .line 342
    .line 343
    move/from16 v29, v15

    .line 344
    .line 345
    div-int/lit8 v15, v22, 0x8

    .line 346
    .line 347
    sub-int v13, v6, v13

    .line 348
    .line 349
    and-int/2addr v13, v5

    .line 350
    div-int/lit8 v13, v13, 0x8

    .line 351
    .line 352
    const-wide/high16 v22, -0x8000000000000000L

    .line 353
    .line 354
    if-ne v15, v13, :cond_8

    .line 355
    .line 356
    and-int/lit8 v13, v16, 0x7f

    .line 357
    .line 358
    int-to-long v13, v13

    .line 359
    aget-wide v15, v0, v8

    .line 360
    .line 361
    move/from16 v37, v7

    .line 362
    .line 363
    move/from16 v25, v8

    .line 364
    .line 365
    shl-long v7, v31, v9

    .line 366
    .line 367
    not-long v7, v7

    .line 368
    and-long/2addr v7, v15

    .line 369
    shl-long/2addr v13, v9

    .line 370
    or-long/2addr v7, v13

    .line 371
    aput-wide v7, v0, v25

    .line 372
    .line 373
    array-length v7, v0

    .line 374
    add-int/lit8 v7, v7, -0x1

    .line 375
    .line 376
    aget-wide v8, v0, v21

    .line 377
    .line 378
    and-long v8, v8, v17

    .line 379
    .line 380
    or-long v8, v8, v22

    .line 381
    .line 382
    aput-wide v8, v0, v7

    .line 383
    .line 384
    add-int/lit8 v6, v6, 0x1

    .line 385
    .line 386
    :goto_5
    move-wide/from16 v13, v17

    .line 387
    .line 388
    move/from16 v15, v29

    .line 389
    .line 390
    move/from16 v7, v37

    .line 391
    .line 392
    goto :goto_3

    .line 393
    :cond_8
    move/from16 v37, v7

    .line 394
    .line 395
    move/from16 v25, v8

    .line 396
    .line 397
    shr-int/lit8 v7, v14, 0x3

    .line 398
    .line 399
    aget-wide v26, v0, v7

    .line 400
    .line 401
    and-int/lit8 v8, v14, 0x7

    .line 402
    .line 403
    shl-int/lit8 v8, v8, 0x3

    .line 404
    .line 405
    shr-long v35, v26, v8

    .line 406
    .line 407
    and-long v35, v35, v31

    .line 408
    .line 409
    cmp-long v13, v35, p0

    .line 410
    .line 411
    if-nez v13, :cond_9

    .line 412
    .line 413
    and-int/lit8 v13, v16, 0x7f

    .line 414
    .line 415
    move v15, v5

    .line 416
    move/from16 v35, v6

    .line 417
    .line 418
    int-to-long v5, v13

    .line 419
    move-wide/from16 v38, v5

    .line 420
    .line 421
    shl-long v5, v31, v8

    .line 422
    .line 423
    not-long v5, v5

    .line 424
    and-long v5, v26, v5

    .line 425
    .line 426
    shl-long v26, v38, v8

    .line 427
    .line 428
    or-long v5, v5, v26

    .line 429
    .line 430
    aput-wide v5, v0, v7

    .line 431
    .line 432
    aget-wide v5, v0, v25

    .line 433
    .line 434
    shl-long v7, v31, v9

    .line 435
    .line 436
    not-long v7, v7

    .line 437
    and-long/2addr v5, v7

    .line 438
    shl-long v7, p0, v9

    .line 439
    .line 440
    or-long/2addr v5, v7

    .line 441
    aput-wide v5, v0, v25

    .line 442
    .line 443
    aget-wide v5, v12, v35

    .line 444
    .line 445
    aput-wide v5, v12, v14

    .line 446
    .line 447
    aput-wide v33, v12, v35

    .line 448
    .line 449
    move/from16 v6, v35

    .line 450
    .line 451
    goto :goto_6

    .line 452
    :cond_9
    move v15, v5

    .line 453
    move/from16 v35, v6

    .line 454
    .line 455
    and-int/lit8 v5, v16, 0x7f

    .line 456
    .line 457
    int-to-long v5, v5

    .line 458
    move-wide/from16 v38, v5

    .line 459
    .line 460
    shl-long v5, v31, v8

    .line 461
    .line 462
    not-long v5, v5

    .line 463
    and-long v5, v26, v5

    .line 464
    .line 465
    shl-long v8, v38, v8

    .line 466
    .line 467
    or-long/2addr v5, v8

    .line 468
    aput-wide v5, v0, v7

    .line 469
    .line 470
    aget-wide v5, v12, v14

    .line 471
    .line 472
    aget-wide v7, v12, v35

    .line 473
    .line 474
    aput-wide v7, v12, v14

    .line 475
    .line 476
    aput-wide v5, v12, v35

    .line 477
    .line 478
    add-int/lit8 v6, v35, -0x1

    .line 479
    .line 480
    :goto_6
    array-length v5, v0

    .line 481
    add-int/lit8 v5, v5, -0x1

    .line 482
    .line 483
    aget-wide v7, v0, v21

    .line 484
    .line 485
    and-long v7, v7, v17

    .line 486
    .line 487
    or-long v7, v7, v22

    .line 488
    .line 489
    aput-wide v7, v0, v5

    .line 490
    .line 491
    add-int/lit8 v6, v6, 0x1

    .line 492
    .line 493
    move v5, v15

    .line 494
    goto :goto_5

    .line 495
    :cond_a
    move/from16 v37, v7

    .line 496
    .line 497
    iget v0, v4, Landroidx/collection/f0;->c:I

    .line 498
    .line 499
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 500
    .line 501
    .line 502
    move-result v0

    .line 503
    iget v5, v4, Landroidx/collection/f0;->d:I

    .line 504
    .line 505
    sub-int/2addr v0, v5

    .line 506
    iput v0, v4, Landroidx/collection/f0;->e:I

    .line 507
    .line 508
    goto/16 :goto_9

    .line 509
    .line 510
    :cond_b
    move/from16 v37, v7

    .line 511
    .line 512
    const-wide/16 p0, 0x80

    .line 513
    .line 514
    iget v0, v4, Landroidx/collection/f0;->c:I

    .line 515
    .line 516
    invoke-static {v0}, Landroidx/collection/y0;->b(I)I

    .line 517
    .line 518
    .line 519
    move-result v0

    .line 520
    iget-object v5, v4, Landroidx/collection/f0;->a:[J

    .line 521
    .line 522
    iget-object v6, v4, Landroidx/collection/f0;->b:[J

    .line 523
    .line 524
    iget v7, v4, Landroidx/collection/f0;->c:I

    .line 525
    .line 526
    invoke-virtual {v4, v0}, Landroidx/collection/f0;->c(I)V

    .line 527
    .line 528
    .line 529
    iget-object v0, v4, Landroidx/collection/f0;->a:[J

    .line 530
    .line 531
    iget-object v8, v4, Landroidx/collection/f0;->b:[J

    .line 532
    .line 533
    iget v9, v4, Landroidx/collection/f0;->c:I

    .line 534
    .line 535
    move/from16 v12, v21

    .line 536
    .line 537
    :goto_7
    if-ge v12, v7, :cond_d

    .line 538
    .line 539
    shr-int/lit8 v13, v12, 0x3

    .line 540
    .line 541
    aget-wide v13, v5, v13

    .line 542
    .line 543
    and-int/lit8 v15, v12, 0x7

    .line 544
    .line 545
    shl-int/lit8 v15, v15, 0x3

    .line 546
    .line 547
    shr-long/2addr v13, v15

    .line 548
    and-long v13, v13, v31

    .line 549
    .line 550
    cmp-long v13, v13, p0

    .line 551
    .line 552
    if-gez v13, :cond_c

    .line 553
    .line 554
    aget-wide v13, v6, v12

    .line 555
    .line 556
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 557
    .line 558
    .line 559
    move-result v15

    .line 560
    mul-int v15, v15, v28

    .line 561
    .line 562
    shl-int/lit8 v16, v15, 0x10

    .line 563
    .line 564
    xor-int v15, v15, v16

    .line 565
    .line 566
    move-object/from16 v16, v0

    .line 567
    .line 568
    ushr-int/lit8 v0, v15, 0x7

    .line 569
    .line 570
    invoke-virtual {v4, v0}, Landroidx/collection/f0;->b(I)I

    .line 571
    .line 572
    .line 573
    move-result v0

    .line 574
    and-int/lit8 v15, v15, 0x7f

    .line 575
    .line 576
    move-object/from16 v17, v5

    .line 577
    .line 578
    move-object/from16 v18, v6

    .line 579
    .line 580
    int-to-long v5, v15

    .line 581
    shr-int/lit8 v15, v0, 0x3

    .line 582
    .line 583
    and-int/lit8 v19, v0, 0x7

    .line 584
    .line 585
    shl-int/lit8 v19, v19, 0x3

    .line 586
    .line 587
    aget-wide v22, v16, v15

    .line 588
    .line 589
    move-wide/from16 v25, v5

    .line 590
    .line 591
    shl-long v5, v31, v19

    .line 592
    .line 593
    not-long v5, v5

    .line 594
    and-long v5, v22, v5

    .line 595
    .line 596
    shl-long v19, v25, v19

    .line 597
    .line 598
    or-long v5, v5, v19

    .line 599
    .line 600
    aput-wide v5, v16, v15

    .line 601
    .line 602
    add-int/lit8 v15, v0, -0x7

    .line 603
    .line 604
    and-int/2addr v15, v9

    .line 605
    and-int/lit8 v19, v9, 0x7

    .line 606
    .line 607
    add-int v15, v15, v19

    .line 608
    .line 609
    shr-int/lit8 v15, v15, 0x3

    .line 610
    .line 611
    aput-wide v5, v16, v15

    .line 612
    .line 613
    aput-wide v13, v8, v0

    .line 614
    .line 615
    goto :goto_8

    .line 616
    :cond_c
    move-object/from16 v16, v0

    .line 617
    .line 618
    move-object/from16 v17, v5

    .line 619
    .line 620
    move-object/from16 v18, v6

    .line 621
    .line 622
    :goto_8
    add-int/lit8 v12, v12, 0x1

    .line 623
    .line 624
    move-object/from16 v0, v16

    .line 625
    .line 626
    move-object/from16 v5, v17

    .line 627
    .line 628
    move-object/from16 v6, v18

    .line 629
    .line 630
    goto :goto_7

    .line 631
    :cond_d
    :goto_9
    invoke-virtual {v4, v3}, Landroidx/collection/f0;->b(I)I

    .line 632
    .line 633
    .line 634
    move-result v0

    .line 635
    :goto_a
    move v14, v0

    .line 636
    iget v0, v4, Landroidx/collection/f0;->d:I

    .line 637
    .line 638
    add-int/lit8 v0, v0, 0x1

    .line 639
    .line 640
    iput v0, v4, Landroidx/collection/f0;->d:I

    .line 641
    .line 642
    iget v0, v4, Landroidx/collection/f0;->e:I

    .line 643
    .line 644
    iget-object v3, v4, Landroidx/collection/f0;->a:[J

    .line 645
    .line 646
    shr-int/lit8 v5, v14, 0x3

    .line 647
    .line 648
    aget-wide v6, v3, v5

    .line 649
    .line 650
    and-int/lit8 v8, v14, 0x7

    .line 651
    .line 652
    shl-int/lit8 v8, v8, 0x3

    .line 653
    .line 654
    shr-long v12, v6, v8

    .line 655
    .line 656
    and-long v12, v12, v31

    .line 657
    .line 658
    cmp-long v9, v12, p0

    .line 659
    .line 660
    if-nez v9, :cond_e

    .line 661
    .line 662
    move/from16 v21, v37

    .line 663
    .line 664
    :cond_e
    sub-int v0, v0, v21

    .line 665
    .line 666
    iput v0, v4, Landroidx/collection/f0;->e:I

    .line 667
    .line 668
    iget v0, v4, Landroidx/collection/f0;->c:I

    .line 669
    .line 670
    shl-long v12, v31, v8

    .line 671
    .line 672
    not-long v12, v12

    .line 673
    and-long/2addr v6, v12

    .line 674
    shl-long v8, v10, v8

    .line 675
    .line 676
    or-long/2addr v6, v8

    .line 677
    aput-wide v6, v3, v5

    .line 678
    .line 679
    add-int/lit8 v5, v14, -0x7

    .line 680
    .line 681
    and-int/2addr v5, v0

    .line 682
    and-int/lit8 v0, v0, 0x7

    .line 683
    .line 684
    add-int/2addr v5, v0

    .line 685
    shr-int/lit8 v0, v5, 0x3

    .line 686
    .line 687
    aput-wide v6, v3, v0

    .line 688
    .line 689
    :goto_b
    iget-object v0, v4, Landroidx/collection/f0;->b:[J

    .line 690
    .line 691
    aput-wide v1, v0, v14

    .line 692
    .line 693
    return v37

    .line 694
    :cond_f
    move/from16 v29, v5

    .line 695
    .line 696
    move/from16 v37, v7

    .line 697
    .line 698
    add-int/lit8 v26, v26, 0x8

    .line 699
    .line 700
    add-int v25, v25, v26

    .line 701
    .line 702
    and-int v25, v25, v6

    .line 703
    .line 704
    move/from16 v10, v28

    .line 705
    .line 706
    move-wide/from16 v15, v33

    .line 707
    .line 708
    goto/16 :goto_0

    .line 709
    .line 710
    :cond_10
    move/from16 v29, v5

    .line 711
    .line 712
    move/from16 v24, v6

    .line 713
    .line 714
    move v8, v7

    .line 715
    move/from16 v28, v10

    .line 716
    .line 717
    move-wide/from16 v33, v15

    .line 718
    .line 719
    const/16 v27, 0x3f

    .line 720
    .line 721
    const/16 v30, 0x7

    .line 722
    .line 723
    const-wide/16 v31, 0xff

    .line 724
    .line 725
    const-wide v35, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    if-ne v3, v8, :cond_16

    .line 731
    .line 732
    iget-object v3, v0, Lc3/l;->f:Landroidx/collection/f0;

    .line 733
    .line 734
    if-eqz v3, :cond_15

    .line 735
    .line 736
    invoke-virtual {v3, v1, v2}, Landroidx/collection/f0;->a(J)Z

    .line 737
    .line 738
    .line 739
    move-result v3

    .line 740
    if-ne v3, v8, :cond_15

    .line 741
    .line 742
    iget-object v0, v0, Lc3/l;->f:Landroidx/collection/f0;

    .line 743
    .line 744
    if-eqz v0, :cond_13

    .line 745
    .line 746
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 747
    .line 748
    .line 749
    move-result v3

    .line 750
    mul-int v3, v3, v28

    .line 751
    .line 752
    shl-int/lit8 v4, v3, 0x10

    .line 753
    .line 754
    xor-int/2addr v3, v4

    .line 755
    and-int/lit8 v4, v3, 0x7f

    .line 756
    .line 757
    iget v5, v0, Landroidx/collection/f0;->c:I

    .line 758
    .line 759
    ushr-int/lit8 v3, v3, 0x7

    .line 760
    .line 761
    :goto_c
    and-int/2addr v3, v5

    .line 762
    iget-object v6, v0, Landroidx/collection/f0;->a:[J

    .line 763
    .line 764
    shr-int/lit8 v7, v3, 0x3

    .line 765
    .line 766
    and-int/lit8 v8, v3, 0x7

    .line 767
    .line 768
    shl-int/lit8 v8, v8, 0x3

    .line 769
    .line 770
    aget-wide v9, v6, v7

    .line 771
    .line 772
    ushr-long/2addr v9, v8

    .line 773
    const/16 v37, 0x1

    .line 774
    .line 775
    add-int/lit8 v7, v7, 0x1

    .line 776
    .line 777
    aget-wide v6, v6, v7

    .line 778
    .line 779
    rsub-int/lit8 v11, v8, 0x40

    .line 780
    .line 781
    shl-long/2addr v6, v11

    .line 782
    int-to-long v11, v8

    .line 783
    neg-long v11, v11

    .line 784
    shr-long v11, v11, v27

    .line 785
    .line 786
    and-long/2addr v6, v11

    .line 787
    or-long/2addr v6, v9

    .line 788
    int-to-long v8, v4

    .line 789
    mul-long v8, v8, v17

    .line 790
    .line 791
    xor-long/2addr v8, v6

    .line 792
    sub-long v10, v8, v17

    .line 793
    .line 794
    not-long v8, v8

    .line 795
    and-long/2addr v8, v10

    .line 796
    and-long v8, v8, v35

    .line 797
    .line 798
    :goto_d
    cmp-long v10, v8, v33

    .line 799
    .line 800
    if-eqz v10, :cond_12

    .line 801
    .line 802
    invoke-static {v8, v9}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 803
    .line 804
    .line 805
    move-result v10

    .line 806
    shr-int/lit8 v10, v10, 0x3

    .line 807
    .line 808
    add-int/2addr v10, v3

    .line 809
    and-int/2addr v10, v5

    .line 810
    iget-object v11, v0, Landroidx/collection/f0;->b:[J

    .line 811
    .line 812
    aget-wide v11, v11, v10

    .line 813
    .line 814
    cmp-long v11, v11, v1

    .line 815
    .line 816
    if-nez v11, :cond_11

    .line 817
    .line 818
    goto :goto_e

    .line 819
    :cond_11
    sub-long v10, v8, v22

    .line 820
    .line 821
    and-long/2addr v8, v10

    .line 822
    goto :goto_d

    .line 823
    :cond_12
    not-long v8, v6

    .line 824
    shl-long v8, v8, p1

    .line 825
    .line 826
    and-long/2addr v6, v8

    .line 827
    and-long v6, v6, v35

    .line 828
    .line 829
    cmp-long v6, v6, v33

    .line 830
    .line 831
    if-eqz v6, :cond_14

    .line 832
    .line 833
    const/4 v10, -0x1

    .line 834
    :goto_e
    if-ltz v10, :cond_13

    .line 835
    .line 836
    iget v1, v0, Landroidx/collection/f0;->d:I

    .line 837
    .line 838
    const/16 v37, 0x1

    .line 839
    .line 840
    add-int/lit8 v1, v1, -0x1

    .line 841
    .line 842
    iput v1, v0, Landroidx/collection/f0;->d:I

    .line 843
    .line 844
    iget-object v1, v0, Landroidx/collection/f0;->a:[J

    .line 845
    .line 846
    iget v0, v0, Landroidx/collection/f0;->c:I

    .line 847
    .line 848
    shr-int/lit8 v2, v10, 0x3

    .line 849
    .line 850
    and-int/lit8 v3, v10, 0x7

    .line 851
    .line 852
    shl-int/lit8 v3, v3, 0x3

    .line 853
    .line 854
    aget-wide v4, v1, v2

    .line 855
    .line 856
    shl-long v6, v31, v3

    .line 857
    .line 858
    not-long v6, v6

    .line 859
    and-long/2addr v4, v6

    .line 860
    shl-long v6, v19, v3

    .line 861
    .line 862
    or-long v3, v4, v6

    .line 863
    .line 864
    aput-wide v3, v1, v2

    .line 865
    .line 866
    add-int/lit8 v10, v10, -0x7

    .line 867
    .line 868
    and-int v2, v10, v0

    .line 869
    .line 870
    and-int/lit8 v0, v0, 0x7

    .line 871
    .line 872
    add-int/2addr v2, v0

    .line 873
    shr-int/lit8 v0, v2, 0x3

    .line 874
    .line 875
    aput-wide v3, v1, v0

    .line 876
    .line 877
    const/16 v37, 0x1

    .line 878
    .line 879
    return v37

    .line 880
    :cond_13
    const/16 v37, 0x1

    .line 881
    .line 882
    goto :goto_f

    .line 883
    :cond_14
    const/16 v37, 0x1

    .line 884
    .line 885
    add-int/lit8 v21, v21, 0x8

    .line 886
    .line 887
    add-int v3, v3, v21

    .line 888
    .line 889
    goto/16 :goto_c

    .line 890
    .line 891
    :cond_15
    return v21

    .line 892
    :cond_16
    move/from16 v37, v8

    .line 893
    .line 894
    :goto_f
    return v37
.end method
