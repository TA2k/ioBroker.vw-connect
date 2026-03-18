.class public final Lhg/x;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lzi/a;

.field public final e:Lbq0/i;

.field public final f:Lh40/w3;

.field public final g:Lh90/d;

.field public final h:Lag/c;

.field public final i:Lh50/p;

.field public final j:Ljava/lang/String;

.field public final k:Lyy0/c2;

.field public final l:Lyy0/l1;


# direct methods
.method public constructor <init>(Lzi/a;Lbq0/i;Lh40/w3;Lh90/d;Lag/c;Lh50/p;)V
    .locals 11

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lhg/x;->d:Lzi/a;

    .line 10
    .line 11
    iput-object p2, p0, Lhg/x;->e:Lbq0/i;

    .line 12
    .line 13
    iput-object p3, p0, Lhg/x;->f:Lh40/w3;

    .line 14
    .line 15
    iput-object p4, p0, Lhg/x;->g:Lh90/d;

    .line 16
    .line 17
    move-object/from16 p2, p5

    .line 18
    .line 19
    iput-object p2, p0, Lhg/x;->h:Lag/c;

    .line 20
    .line 21
    move-object/from16 p2, p6

    .line 22
    .line 23
    iput-object p2, p0, Lhg/x;->i:Lh50/p;

    .line 24
    .line 25
    iget-object v4, p1, Lzi/a;->d:Ljava/lang/String;

    .line 26
    .line 27
    iput-object v4, p0, Lhg/x;->j:Ljava/lang/String;

    .line 28
    .line 29
    iget-object p1, p1, Lzi/a;->e:Ljava/util/ArrayList;

    .line 30
    .line 31
    new-instance v5, Ljava/util/ArrayList;

    .line 32
    .line 33
    const/16 p2, 0xa

    .line 34
    .line 35
    invoke-static {p1, p2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    invoke-direct {v5, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 40
    .line 41
    .line 42
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    if-eqz p2, :cond_0

    .line 51
    .line 52
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    check-cast p2, Lzi/h;

    .line 57
    .line 58
    new-instance p3, Lhg/a;

    .line 59
    .line 60
    iget-object p4, p2, Lzi/h;->d:Ljava/lang/String;

    .line 61
    .line 62
    iget-object p2, p2, Lzi/h;->e:Ljava/lang/String;

    .line 63
    .line 64
    invoke-direct {p3, p4, p2}, Lhg/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v5, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    iget-object p1, p0, Lhg/x;->d:Lzi/a;

    .line 72
    .line 73
    iget-boolean v7, p1, Lzi/a;->i:Z

    .line 74
    .line 75
    iget-object v9, p1, Lzi/a;->g:Ljava/lang/String;

    .line 76
    .line 77
    new-instance v0, Lhg/y;

    .line 78
    .line 79
    const/4 v8, 0x0

    .line 80
    const/4 v10, 0x0

    .line 81
    const/4 v1, 0x1

    .line 82
    const/4 v2, 0x0

    .line 83
    const/4 v3, 0x0

    .line 84
    const/4 v6, 0x0

    .line 85
    invoke-direct/range {v0 .. v10}, Lhg/y;-><init>(ZLhg/c;ZLjava/lang/String;Ljava/util/List;ZZZLjava/lang/String;Z)V

    .line 86
    .line 87
    .line 88
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iput-object p1, p0, Lhg/x;->k:Lyy0/c2;

    .line 93
    .line 94
    new-instance p2, Lag/r;

    .line 95
    .line 96
    const/4 p3, 0x3

    .line 97
    invoke-direct {p2, p1, p3}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 98
    .line 99
    .line 100
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    check-cast p1, Lhg/y;

    .line 109
    .line 110
    invoke-virtual {p1}, Lhg/y;->b()Lhg/m;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    sget-object p4, Lyy0/u1;->a:Lyy0/w1;

    .line 115
    .line 116
    invoke-static {p2, p3, p4, p1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iput-object p1, p0, Lhg/x;->l:Lyy0/l1;

    .line 121
    .line 122
    return-void
.end method

.method public static final a(Lhg/x;Leg/o;Z)V
    .locals 13

    .line 1
    iget-object v0, p0, Lhg/x;->k:Lyy0/c2;

    .line 2
    .line 3
    iget-object v1, p1, Leg/o;->b:Lgz0/p;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Lgz0/p;->a()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v1, 0x0

    .line 17
    :goto_0
    if-eqz v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    iget-object v4, p0, Lhg/x;->i:Lh50/p;

    .line 24
    .line 25
    invoke-virtual {v4}, Lh50/p;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    check-cast v4, Ljava/lang/Number;

    .line 30
    .line 31
    invoke-virtual {v4}, Ljava/lang/Number;->longValue()J

    .line 32
    .line 33
    .line 34
    move-result-wide v4

    .line 35
    cmp-long v2, v2, v4

    .line 36
    .line 37
    if-gtz v2, :cond_2

    .line 38
    .line 39
    :cond_1
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    move-object v1, p0

    .line 44
    check-cast v1, Lhg/y;

    .line 45
    .line 46
    new-instance v3, Lhg/c;

    .line 47
    .line 48
    new-instance p1, Ljava/lang/RuntimeException;

    .line 49
    .line 50
    const-string p2, ""

    .line 51
    .line 52
    invoke-direct {p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    sget-object p2, Lhg/g;->a:Lhg/g;

    .line 60
    .line 61
    invoke-direct {v3, p1, p2}, Lhg/c;-><init>(Llc/l;Lhg/j;)V

    .line 62
    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    const/16 v10, 0x3fc

    .line 66
    .line 67
    const/4 v2, 0x0

    .line 68
    const/4 v4, 0x0

    .line 69
    const/4 v5, 0x0

    .line 70
    const/4 v6, 0x0

    .line 71
    const/4 v7, 0x0

    .line 72
    const/4 v8, 0x0

    .line 73
    invoke-static/range {v1 .. v10}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_1

    .line 82
    .line 83
    return-void

    .line 84
    :cond_2
    :goto_1
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    move-object v3, v2

    .line 89
    check-cast v3, Lhg/y;

    .line 90
    .line 91
    iget-object v4, p1, Leg/o;->a:Ljava/util/List;

    .line 92
    .line 93
    check-cast v4, Ljava/lang/Iterable;

    .line 94
    .line 95
    new-instance v6, Ljava/util/ArrayList;

    .line 96
    .line 97
    const/16 v5, 0xa

    .line 98
    .line 99
    invoke-static {v4, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    invoke-direct {v6, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v5

    .line 114
    if-eqz v5, :cond_3

    .line 115
    .line 116
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    check-cast v5, Leg/i;

    .line 121
    .line 122
    new-instance v7, Lhg/a;

    .line 123
    .line 124
    iget-object v8, v5, Leg/i;->a:Ljava/lang/String;

    .line 125
    .line 126
    iget-object v5, v5, Leg/i;->b:Ljava/lang/String;

    .line 127
    .line 128
    invoke-direct {v7, v8, v5}, Lhg/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_3
    iget-boolean v8, p1, Leg/o;->e:Z

    .line 136
    .line 137
    iget-object v10, p1, Leg/o;->c:Ljava/lang/String;

    .line 138
    .line 139
    const/4 v9, 0x0

    .line 140
    const/16 v12, 0x8e

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    const/4 v5, 0x0

    .line 144
    const/4 v7, 0x0

    .line 145
    move v11, p2

    .line 146
    invoke-static/range {v3 .. v12}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    invoke-virtual {v0, v2, p2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result p2

    .line 154
    if-eqz p2, :cond_4

    .line 155
    .line 156
    const/4 p1, 0x0

    .line 157
    invoke-virtual {p0, v1, p1}, Lhg/x;->f(Ljava/lang/Long;Z)V

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :cond_4
    move p2, v11

    .line 162
    goto :goto_1
.end method

.method public static g(Lyy0/c2;Ljava/lang/Throwable;Lhg/j;)V
    .locals 11

    .line 1
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lhg/y;

    .line 7
    .line 8
    new-instance v3, Lhg/c;

    .line 9
    .line 10
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-direct {v3, v2, p2}, Lhg/c;-><init>(Llc/l;Lhg/j;)V

    .line 15
    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    const/16 v10, 0x3dc

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v8, 0x0

    .line 26
    invoke-static/range {v1 .. v10}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final b(IZ)V
    .locals 12

    .line 1
    if-nez p2, :cond_1

    .line 2
    .line 3
    :cond_0
    iget-object v0, p0, Lhg/x;->k:Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lhg/y;

    .line 11
    .line 12
    const/4 v10, 0x0

    .line 13
    const/16 v11, 0x3fc

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v7, 0x0

    .line 20
    const/4 v8, 0x0

    .line 21
    const/4 v9, 0x0

    .line 22
    invoke-static/range {v2 .. v11}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    :cond_1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v1, Lhg/n;

    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    move-object v2, p0

    .line 41
    move v4, p1

    .line 42
    move v3, p2

    .line 43
    invoke-direct/range {v1 .. v6}, Lhg/n;-><init>(Landroidx/lifecycle/b1;ZILkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    const/4 p0, 0x3

    .line 47
    invoke-static {v0, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public final d()V
    .locals 12

    .line 1
    iget-object v0, p0, Lhg/x;->k:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lhg/y;

    .line 8
    .line 9
    iget-boolean v1, v1, Lhg/y;->g:Z

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    move-object v2, v1

    .line 19
    check-cast v2, Lhg/y;

    .line 20
    .line 21
    const/4 v10, 0x0

    .line 22
    const/16 v11, 0x3dd

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x0

    .line 26
    const/4 v5, 0x0

    .line 27
    const/4 v6, 0x1

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    const/4 v9, 0x0

    .line 31
    invoke-static/range {v2 .. v11}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_0

    .line 40
    .line 41
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    new-instance v1, Lhg/v;

    .line 46
    .line 47
    const/4 v2, 0x1

    .line 48
    const/4 v3, 0x0

    .line 49
    invoke-direct {v1, p0, v3, v2}, Lhg/v;-><init>(Lhg/x;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x3

    .line 53
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final f(Ljava/lang/Long;Z)V
    .locals 10

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iget-object p1, p0, Lhg/x;->i:Lh50/p;

    .line 9
    .line 10
    invoke-virtual {p1}, Lh50/p;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    sub-long v6, v0, v2

    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    new-instance v4, Lc00/r1;

    .line 27
    .line 28
    const/4 v9, 0x0

    .line 29
    move-object v8, p0

    .line 30
    move v5, p2

    .line 31
    invoke-direct/range {v4 .. v9}, Lc00/r1;-><init>(ZJLhg/x;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    const/4 p2, 0x0

    .line 36
    invoke-static {p1, p2, p2, v4, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    return-void
.end method
