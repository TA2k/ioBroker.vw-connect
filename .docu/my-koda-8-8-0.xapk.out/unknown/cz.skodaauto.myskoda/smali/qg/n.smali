.class public final Lqg/n;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lyj/b;

.field public final f:Ljd/b;

.field public final g:Lxh/e;

.field public final h:Lh2/d6;

.field public final i:Lyy0/l1;

.field public final j:Llo0/b;

.field public final k:Lqg/a;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lyj/b;Ljd/b;Lxh/e;Lh2/d6;Lyy0/l1;Llo0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqg/n;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lqg/n;->e:Lyj/b;

    .line 7
    .line 8
    iput-object p3, p0, Lqg/n;->f:Ljd/b;

    .line 9
    .line 10
    iput-object p4, p0, Lqg/n;->g:Lxh/e;

    .line 11
    .line 12
    iput-object p5, p0, Lqg/n;->h:Lh2/d6;

    .line 13
    .line 14
    iput-object p6, p0, Lqg/n;->i:Lyy0/l1;

    .line 15
    .line 16
    iput-object p7, p0, Lqg/n;->j:Llo0/b;

    .line 17
    .line 18
    sget-object p1, Lqg/a;->a:Lqg/a;

    .line 19
    .line 20
    iput-object p1, p0, Lqg/n;->k:Lqg/a;

    .line 21
    .line 22
    new-instance p1, Llc/q;

    .line 23
    .line 24
    sget-object p2, Llc/a;->c:Llc/c;

    .line 25
    .line 26
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iput-object p1, p0, Lqg/n;->l:Lyy0/c2;

    .line 34
    .line 35
    new-instance p2, Lyy0/l1;

    .line 36
    .line 37
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 38
    .line 39
    .line 40
    iput-object p2, p0, Lqg/n;->m:Lyy0/l1;

    .line 41
    .line 42
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance p2, Lna/e;

    .line 47
    .line 48
    const/16 p3, 0x18

    .line 49
    .line 50
    const/4 p4, 0x0

    .line 51
    invoke-direct {p2, p0, p4, p3}, Lna/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    const/4 p0, 0x3

    .line 55
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static final a(Lqg/n;Lkg/d0;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lqg/n;->l:Lyy0/c2;

    .line 6
    .line 7
    iget-object v0, v0, Lqg/n;->k:Lqg/a;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const-string v0, "result"

    .line 13
    .line 14
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, v1, Lkg/d0;->f:Lkg/l;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x1

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    move v5, v4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move v5, v3

    .line 26
    :goto_0
    new-instance v6, Lqg/k;

    .line 27
    .line 28
    iget-boolean v7, v1, Lkg/d0;->e:Z

    .line 29
    .line 30
    sget-object v8, Lqg/a;->a:Lqg/a;

    .line 31
    .line 32
    iget-object v1, v1, Lkg/d0;->d:Lkg/c;

    .line 33
    .line 34
    iget-object v8, v1, Lkg/c;->d:Lkg/p0;

    .line 35
    .line 36
    new-instance v9, Lqg/b;

    .line 37
    .line 38
    iget-object v10, v1, Lkg/c;->e:Lkg/r;

    .line 39
    .line 40
    iget-object v11, v10, Lkg/r;->d:Ljava/lang/String;

    .line 41
    .line 42
    iget-boolean v12, v10, Lkg/r;->f:Z

    .line 43
    .line 44
    iget-object v13, v10, Lkg/r;->h:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v10, v10, Lkg/r;->e:Ljava/lang/String;

    .line 47
    .line 48
    invoke-direct {v9, v12, v11, v13, v10}, Lqg/b;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-static {v8, v9}, Lqg/a;->a(Lkg/p0;Lqg/b;)Lqg/j;

    .line 52
    .line 53
    .line 54
    move-result-object v15

    .line 55
    iget-object v8, v1, Lkg/c;->g:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v1, v1, Lkg/c;->h:Ljava/lang/Boolean;

    .line 58
    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    move/from16 v17, v9

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    move/from16 v17, v3

    .line 69
    .line 70
    :goto_1
    if-eqz v1, :cond_2

    .line 71
    .line 72
    move/from16 v16, v4

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_2
    move/from16 v16, v3

    .line 76
    .line 77
    :goto_2
    xor-int/lit8 v18, v5, 0x1

    .line 78
    .line 79
    new-instance v14, Lqg/h;

    .line 80
    .line 81
    move-object/from16 v19, v8

    .line 82
    .line 83
    invoke-direct/range {v14 .. v19}, Lqg/h;-><init>(Lqg/j;ZZZLjava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const/4 v1, 0x0

    .line 87
    if-eqz v0, :cond_9

    .line 88
    .line 89
    iget-object v8, v0, Lkg/l;->f:Ljava/lang/String;

    .line 90
    .line 91
    new-instance v15, Lqg/i;

    .line 92
    .line 93
    iget-object v9, v0, Lkg/l;->e:Lkg/p0;

    .line 94
    .line 95
    iget-object v10, v0, Lkg/l;->d:Ljava/lang/String;

    .line 96
    .line 97
    new-instance v11, Lqg/b;

    .line 98
    .line 99
    const-string v12, ""

    .line 100
    .line 101
    invoke-direct {v11, v3, v10, v1, v12}, Lqg/b;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-static {v9, v11}, Lqg/a;->a(Lkg/p0;Lqg/b;)Lqg/j;

    .line 105
    .line 106
    .line 107
    move-result-object v16

    .line 108
    iget-object v0, v0, Lkg/l;->g:Ljava/lang/String;

    .line 109
    .line 110
    if-nez v0, :cond_4

    .line 111
    .line 112
    if-eqz v8, :cond_3

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_3
    move/from16 v17, v3

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_4
    :goto_3
    move/from16 v17, v4

    .line 119
    .line 120
    :goto_4
    if-eqz v0, :cond_5

    .line 121
    .line 122
    move/from16 v18, v4

    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_5
    move/from16 v18, v3

    .line 126
    .line 127
    :goto_5
    if-nez v0, :cond_6

    .line 128
    .line 129
    move-object/from16 v19, v12

    .line 130
    .line 131
    goto :goto_6

    .line 132
    :cond_6
    move-object/from16 v19, v0

    .line 133
    .line 134
    :goto_6
    if-eqz v8, :cond_7

    .line 135
    .line 136
    move/from16 v20, v4

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_7
    move/from16 v20, v3

    .line 140
    .line 141
    :goto_7
    if-nez v8, :cond_8

    .line 142
    .line 143
    move-object/from16 v21, v12

    .line 144
    .line 145
    goto :goto_8

    .line 146
    :cond_8
    move-object/from16 v21, v8

    .line 147
    .line 148
    :goto_8
    invoke-direct/range {v15 .. v21}, Lqg/i;-><init>(Lqg/j;ZZLjava/lang/String;ZLjava/lang/String;)V

    .line 149
    .line 150
    .line 151
    goto :goto_9

    .line 152
    :cond_9
    sget-object v15, Lqg/a;->b:Lqg/i;

    .line 153
    .line 154
    :goto_9
    invoke-direct {v6, v7, v14, v5, v15}, Lqg/k;-><init>(ZLqg/h;ZLqg/i;)V

    .line 155
    .line 156
    .line 157
    new-instance v0, Llc/q;

    .line 158
    .line 159
    invoke-direct {v0, v6}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v2, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 6

    .line 1
    new-instance v0, Lqe/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqe/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 9
    .line 10
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 11
    .line 12
    const-class v3, Lqg/n;

    .line 13
    .line 14
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    const/16 v4, 0x24

    .line 19
    .line 20
    invoke-static {v3, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    const/16 v5, 0x2e

    .line 25
    .line 26
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-nez v5, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const-string v3, "Kt"

    .line 38
    .line 39
    invoke-static {v4, v3}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    :goto_0
    const/4 v4, 0x0

    .line 44
    invoke-static {v3, v2, v1, v4, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Llc/q;

    .line 48
    .line 49
    sget-object v1, Llc/a;->c:Llc/c;

    .line 50
    .line 51
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Lqg/n;->l:Lyy0/c2;

    .line 55
    .line 56
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1, v4, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    new-instance v1, Lqg/m;

    .line 67
    .line 68
    const/4 v2, 0x0

    .line 69
    invoke-direct {v1, p0, v4, v2}, Lqg/m;-><init>(Lqg/n;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    const/4 p0, 0x3

    .line 73
    invoke-static {v0, v4, v4, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 74
    .line 75
    .line 76
    return-void
.end method
