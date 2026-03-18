.class public final Lt0/e;
.super Lb0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Lh0/v1;

.field public B:Lh0/w1;

.field public final p:Lt0/f;

.field public final q:Lt0/h;

.field public final r:Lb0/x;

.field public final s:Lb0/x;

.field public t:Lil/g;

.field public u:Landroidx/lifecycle/c1;

.field public v:Lp0/k;

.field public w:Lp0/k;

.field public x:Lp0/k;

.field public y:Lp0/k;

.field public z:Lh0/v1;


# direct methods
.method public constructor <init>(Lh0/b0;Lh0/b0;Lb0/x;Lb0/x;Ljava/util/HashSet;Lh0/r2;)V
    .locals 1

    .line 1
    invoke-static {p5}, Lt0/e;->I(Ljava/util/HashSet;)Lt0/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lb0/z1;-><init>(Lh0/o2;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p5}, Lt0/e;->I(Ljava/util/HashSet;)Lt0/f;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lt0/e;->p:Lt0/f;

    .line 13
    .line 14
    iput-object p3, p0, Lt0/e;->r:Lb0/x;

    .line 15
    .line 16
    iput-object p4, p0, Lt0/e;->s:Lb0/x;

    .line 17
    .line 18
    move-object p3, p2

    .line 19
    move-object p2, p1

    .line 20
    new-instance p1, Lt0/h;

    .line 21
    .line 22
    move-object p4, p5

    .line 23
    move-object p5, p6

    .line 24
    new-instance p6, Lt0/c;

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    invoke-direct {p6, v0}, Lt0/c;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-direct/range {p1 .. p6}, Lt0/h;-><init>(Lh0/b0;Lh0/b0;Ljava/util/HashSet;Lh0/r2;Lt0/c;)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lt0/e;->q:Lt0/h;

    .line 34
    .line 35
    invoke-virtual {p4}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Lb0/z1;

    .line 44
    .line 45
    iget-object p1, p1, Lb0/z1;->f:Ljava/util/HashSet;

    .line 46
    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    new-instance p2, Ljava/util/HashSet;

    .line 50
    .line 51
    invoke-direct {p2, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    const/4 p2, 0x0

    .line 56
    :goto_0
    iput-object p2, p0, Lb0/z1;->f:Ljava/util/HashSet;

    .line 57
    .line 58
    return-void
.end method

.method public static H(Lb0/z1;)Ljava/util/ArrayList;
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    instance-of v1, p0, Lt0/e;

    .line 7
    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p0, Lt0/e;

    .line 11
    .line 12
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 13
    .line 14
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lb0/z1;

    .line 31
    .line 32
    iget-object v1, v1, Lb0/z1;->g:Lh0/o2;

    .line 33
    .line 34
    invoke-interface {v1}, Lh0/o2;->J()Lh0/q2;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    return-object v0

    .line 43
    :cond_1
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 44
    .line 45
    invoke-interface {p0}, Lh0/o2;->J()Lh0/q2;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    return-object v0
.end method

.method public static I(Ljava/util/HashSet;)Lt0/f;
    .locals 5

    .line 1
    new-instance v0, La0/i;

    .line 2
    .line 3
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, La0/i;-><init>(Lh0/j1;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lh0/z0;->C0:Lh0/g;

    .line 11
    .line 12
    const/16 v2, 0x22

    .line 13
    .line 14
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v1, v0, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lb0/z1;

    .line 41
    .line 42
    iget-object v3, v2, Lb0/z1;->g:Lh0/o2;

    .line 43
    .line 44
    sget-object v4, Lh0/o2;->Z0:Lh0/g;

    .line 45
    .line 46
    invoke-interface {v3, v4}, Lh0/t1;->j(Lh0/g;)Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_0

    .line 51
    .line 52
    iget-object v2, v2, Lb0/z1;->g:Lh0/o2;

    .line 53
    .line 54
    invoke-interface {v2}, Lh0/o2;->J()Lh0/q2;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    const-string v2, "StreamSharing"

    .line 63
    .line 64
    const-string v3, "A child does not have capture type."

    .line 65
    .line 66
    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    sget-object p0, Lt0/f;->e:Lh0/g;

    .line 71
    .line 72
    invoke-virtual {v1, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Lh0/a1;->I0:Lh0/g;

    .line 76
    .line 77
    const/4 v0, 0x2

    .line 78
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-virtual {v1, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    sget-object p0, Lh0/o2;->d1:Lh0/g;

    .line 86
    .line 87
    sget-object v0, Lh0/c2;->i:Lh0/c2;

    .line 88
    .line 89
    invoke-virtual {v1, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    new-instance p0, Lt0/f;

    .line 93
    .line 94
    invoke-static {v1}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-direct {p0, v0}, Lt0/f;-><init>(Lh0/n1;)V

    .line 99
    .line 100
    .line 101
    return-object p0
.end method


# virtual methods
.method public final D()V
    .locals 4

    .line 1
    iget-object v0, p0, Lt0/e;->B:Lh0/w1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 7
    .line 8
    .line 9
    iput-object v1, p0, Lt0/e;->B:Lh0/w1;

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lt0/e;->v:Lp0/k;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Lp0/k;->b()V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lt0/e;->v:Lp0/k;

    .line 19
    .line 20
    :cond_1
    iget-object v0, p0, Lt0/e;->w:Lp0/k;

    .line 21
    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {v0}, Lp0/k;->b()V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lt0/e;->w:Lp0/k;

    .line 28
    .line 29
    :cond_2
    iget-object v0, p0, Lt0/e;->x:Lp0/k;

    .line 30
    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    invoke-virtual {v0}, Lp0/k;->b()V

    .line 34
    .line 35
    .line 36
    iput-object v1, p0, Lt0/e;->x:Lp0/k;

    .line 37
    .line 38
    :cond_3
    iget-object v0, p0, Lt0/e;->y:Lp0/k;

    .line 39
    .line 40
    if-eqz v0, :cond_4

    .line 41
    .line 42
    invoke-virtual {v0}, Lp0/k;->b()V

    .line 43
    .line 44
    .line 45
    iput-object v1, p0, Lt0/e;->y:Lp0/k;

    .line 46
    .line 47
    :cond_4
    iget-object v0, p0, Lt0/e;->t:Lil/g;

    .line 48
    .line 49
    if-eqz v0, :cond_5

    .line 50
    .line 51
    iget-object v2, v0, Lil/g;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v2, Lp0/c;

    .line 54
    .line 55
    invoke-virtual {v2}, Lp0/c;->b()V

    .line 56
    .line 57
    .line 58
    new-instance v2, Lm8/o;

    .line 59
    .line 60
    const/4 v3, 0x7

    .line 61
    invoke-direct {v2, v0, v3}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {v2}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 65
    .line 66
    .line 67
    iput-object v1, p0, Lt0/e;->t:Lil/g;

    .line 68
    .line 69
    :cond_5
    iget-object v0, p0, Lt0/e;->u:Landroidx/lifecycle/c1;

    .line 70
    .line 71
    if-eqz v0, :cond_6

    .line 72
    .line 73
    iget-object v2, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v2, Lp0/m;

    .line 76
    .line 77
    invoke-interface {v2}, Lp0/m;->b()V

    .line 78
    .line 79
    .line 80
    new-instance v2, Lm8/o;

    .line 81
    .line 82
    const/16 v3, 0x9

    .line 83
    .line 84
    invoke-direct {v2, v0, v3}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 85
    .line 86
    .line 87
    invoke-static {v2}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 88
    .line 89
    .line 90
    iput-object v1, p0, Lt0/e;->u:Landroidx/lifecycle/c1;

    .line 91
    .line 92
    :cond_6
    return-void
.end method

.method public final E(Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)Ljava/util/List;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p4

    .line 4
    .line 5
    move-object/from16 v3, p5

    .line 6
    .line 7
    iget-object v10, v4, Lh0/k;->c:Lb0/y;

    .line 8
    .line 9
    invoke-static {}, Llp/k1;->a()V

    .line 10
    .line 11
    .line 12
    const-string v11, "   outputConfig = "

    .line 13
    .line 14
    const-string v12, "SurfaceProcessorNode"

    .line 15
    .line 16
    iget-object v6, v0, Lt0/e;->q:Lt0/h;

    .line 17
    .line 18
    if-nez v3, :cond_8

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    move-object/from16 v1, p1

    .line 22
    .line 23
    move-object/from16 v2, p2

    .line 24
    .line 25
    move-object/from16 v3, p3

    .line 26
    .line 27
    invoke-virtual/range {v0 .. v5}, Lt0/e;->F(Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)Lp0/k;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    move-object v15, v0

    .line 32
    invoke-virtual {v15}, Lb0/z1;->c()Lh0/b0;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    new-instance v7, Lil/g;

    .line 40
    .line 41
    new-instance v1, Lp0/c;

    .line 42
    .line 43
    invoke-direct {v1, v10}, Lp0/c;-><init>(Lb0/y;)V

    .line 44
    .line 45
    .line 46
    invoke-direct {v7, v0, v1}, Lil/g;-><init>(Lh0/b0;Lp0/c;)V

    .line 47
    .line 48
    .line 49
    iput-object v7, v15, Lt0/e;->t:Lil/g;

    .line 50
    .line 51
    iget-object v0, v15, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 52
    .line 53
    if-eqz v0, :cond_0

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    const/4 v0, 0x0

    .line 58
    :goto_0
    iget-object v1, v15, Lb0/z1;->g:Lh0/o2;

    .line 59
    .line 60
    check-cast v1, Lh0/a1;

    .line 61
    .line 62
    invoke-interface {v1}, Lh0/a1;->o()I

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    new-instance v8, Ljava/util/HashMap;

    .line 70
    .line 71
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 72
    .line 73
    .line 74
    iget-object v1, v6, Lt0/h;->d:Ljava/util/HashSet;

    .line 75
    .line 76
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_1

    .line 85
    .line 86
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lb0/z1;

    .line 91
    .line 92
    iget-object v2, v6, Lt0/h;->n:Lt0/b;

    .line 93
    .line 94
    iget-object v3, v6, Lt0/h;->i:Lh0/b0;

    .line 95
    .line 96
    move-object/from16 v27, v6

    .line 97
    .line 98
    move v6, v0

    .line 99
    move-object/from16 v0, v27

    .line 100
    .line 101
    invoke-virtual/range {v0 .. v6}, Lt0/h;->s(Lb0/z1;Lt0/b;Lh0/b0;Lp0/k;IZ)Lr0/b;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    iget-object v3, v0, Lt0/h;->i:Lh0/b0;

    .line 106
    .line 107
    iget-object v10, v1, Lb0/z1;->g:Lh0/o2;

    .line 108
    .line 109
    check-cast v10, Lh0/a1;

    .line 110
    .line 111
    invoke-interface {v10}, Lh0/a1;->o()I

    .line 112
    .line 113
    .line 114
    move-result v10

    .line 115
    invoke-interface {v3}, Lh0/b0;->a()Lh0/z;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    invoke-interface {v3, v10}, Lh0/z;->r(I)I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    iget-object v10, v0, Lt0/h;->f:Ljava/util/HashMap;

    .line 124
    .line 125
    invoke-virtual {v10, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v10

    .line 129
    check-cast v10, Lt0/g;

    .line 130
    .line 131
    invoke-static {v10}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    iget-object v10, v10, Lt0/g;->f:Lt0/i;

    .line 135
    .line 136
    iput v3, v10, Lt0/i;->c:I

    .line 137
    .line 138
    invoke-virtual {v8, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move/from16 v27, v6

    .line 142
    .line 143
    move-object v6, v0

    .line 144
    move/from16 v0, v27

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_1
    move-object/from16 v27, v6

    .line 148
    .line 149
    move v6, v0

    .line 150
    move-object/from16 v0, v27

    .line 151
    .line 152
    new-instance v1, Ljava/util/ArrayList;

    .line 153
    .line 154
    invoke-virtual {v8}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 159
    .line 160
    .line 161
    if-eqz v4, :cond_7

    .line 162
    .line 163
    invoke-static {}, Llp/k1;->a()V

    .line 164
    .line 165
    .line 166
    new-instance v2, Ljava/lang/StringBuilder;

    .line 167
    .line 168
    const-string v3, "SurfaceProcessorNode Transform (Processor="

    .line 169
    .line 170
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    iget-object v3, v7, Lil/g;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v3, Lp0/c;

    .line 176
    .line 177
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    const-string v5, "\n   inputEdge = "

    .line 181
    .line 182
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-static {v12, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    if-eqz v5, :cond_2

    .line 204
    .line 205
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    check-cast v5, Lr0/b;

    .line 210
    .line 211
    new-instance v9, Ljava/lang/StringBuilder;

    .line 212
    .line 213
    invoke-direct {v9, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v5

    .line 223
    invoke-static {v12, v5}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_2
    new-instance v2, Lp0/n;

    .line 228
    .line 229
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 230
    .line 231
    .line 232
    iput-object v2, v7, Lil/g;->g:Ljava/lang/Object;

    .line 233
    .line 234
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 239
    .line 240
    .line 241
    move-result v2

    .line 242
    if-eqz v2, :cond_4

    .line 243
    .line 244
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    check-cast v2, Lr0/b;

    .line 249
    .line 250
    iget-object v5, v7, Lil/g;->g:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v5, Lp0/n;

    .line 253
    .line 254
    iget-object v9, v2, Lr0/b;->d:Landroid/graphics/Rect;

    .line 255
    .line 256
    iget v10, v2, Lr0/b;->f:I

    .line 257
    .line 258
    iget-boolean v11, v2, Lr0/b;->g:Z

    .line 259
    .line 260
    new-instance v12, Landroid/graphics/Matrix;

    .line 261
    .line 262
    iget-object v13, v4, Lp0/k;->b:Landroid/graphics/Matrix;

    .line 263
    .line 264
    invoke-direct {v12, v13}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 265
    .line 266
    .line 267
    new-instance v13, Landroid/graphics/RectF;

    .line 268
    .line 269
    invoke-direct {v13, v9}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 270
    .line 271
    .line 272
    iget-object v14, v2, Lr0/b;->e:Landroid/util/Size;

    .line 273
    .line 274
    move-object/from16 p1, v1

    .line 275
    .line 276
    invoke-static {v14}, Li0/f;->h(Landroid/util/Size;)Landroid/graphics/RectF;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    invoke-static {v13, v1, v10, v11}, Li0/f;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;IZ)Landroid/graphics/Matrix;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    invoke-virtual {v12, v1}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 285
    .line 286
    .line 287
    invoke-static {v9}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    invoke-static {v1, v10}, Li0/f;->g(Landroid/util/Size;I)Landroid/util/Size;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    const/4 v9, 0x0

    .line 296
    invoke-static {v1, v9, v14}, Li0/f;->d(Landroid/util/Size;ZLandroid/util/Size;)Z

    .line 297
    .line 298
    .line 299
    move-result v1

    .line 300
    invoke-static {v1}, Ljp/ed;->a(Z)V

    .line 301
    .line 302
    .line 303
    new-instance v1, Landroid/graphics/Rect;

    .line 304
    .line 305
    invoke-virtual {v14}, Landroid/util/Size;->getWidth()I

    .line 306
    .line 307
    .line 308
    move-result v13

    .line 309
    move-object/from16 p2, v8

    .line 310
    .line 311
    invoke-virtual {v14}, Landroid/util/Size;->getHeight()I

    .line 312
    .line 313
    .line 314
    move-result v8

    .line 315
    invoke-direct {v1, v9, v9, v13, v8}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 316
    .line 317
    .line 318
    iget-object v8, v4, Lp0/k;->g:Lh0/k;

    .line 319
    .line 320
    invoke-virtual {v8}, Lh0/k;->b()Lss/b;

    .line 321
    .line 322
    .line 323
    move-result-object v8

    .line 324
    iput-object v14, v8, Lss/b;->e:Ljava/lang/Object;

    .line 325
    .line 326
    invoke-virtual {v8}, Lss/b;->c()Lh0/k;

    .line 327
    .line 328
    .line 329
    move-result-object v19

    .line 330
    new-instance v16, Lp0/k;

    .line 331
    .line 332
    iget v8, v2, Lr0/b;->b:I

    .line 333
    .line 334
    iget v9, v2, Lr0/b;->c:I

    .line 335
    .line 336
    iget v13, v4, Lp0/k;->i:I

    .line 337
    .line 338
    sub-int v23, v13, v10

    .line 339
    .line 340
    iget-boolean v10, v4, Lp0/k;->e:Z

    .line 341
    .line 342
    if-eq v10, v11, :cond_3

    .line 343
    .line 344
    const/16 v25, 0x1

    .line 345
    .line 346
    goto :goto_4

    .line 347
    :cond_3
    const/16 v25, 0x0

    .line 348
    .line 349
    :goto_4
    const/16 v21, 0x0

    .line 350
    .line 351
    const/16 v24, -0x1

    .line 352
    .line 353
    move-object/from16 v22, v1

    .line 354
    .line 355
    move/from16 v17, v8

    .line 356
    .line 357
    move/from16 v18, v9

    .line 358
    .line 359
    move-object/from16 v20, v12

    .line 360
    .line 361
    invoke-direct/range {v16 .. v25}, Lp0/k;-><init>(IILh0/k;Landroid/graphics/Matrix;ZLandroid/graphics/Rect;IIZ)V

    .line 362
    .line 363
    .line 364
    move-object/from16 v1, v16

    .line 365
    .line 366
    invoke-virtual {v5, v2, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-object/from16 v1, p1

    .line 370
    .line 371
    move-object/from16 v8, p2

    .line 372
    .line 373
    goto/16 :goto_3

    .line 374
    .line 375
    :cond_4
    move-object/from16 p2, v8

    .line 376
    .line 377
    iget-object v1, v7, Lil/g;->f:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v1, Lh0/b0;

    .line 380
    .line 381
    const/4 v2, 0x1

    .line 382
    invoke-virtual {v4, v1, v2}, Lp0/k;->c(Lh0/b0;Z)Lb0/x1;

    .line 383
    .line 384
    .line 385
    move-result-object v1

    .line 386
    invoke-virtual {v3, v1}, Lp0/c;->a(Lb0/x1;)V

    .line 387
    .line 388
    .line 389
    iget-object v1, v7, Lil/g;->g:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast v1, Lp0/n;

    .line 392
    .line 393
    invoke-virtual {v1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 398
    .line 399
    .line 400
    move-result-object v1

    .line 401
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 402
    .line 403
    .line 404
    move-result v2

    .line 405
    if-eqz v2, :cond_5

    .line 406
    .line 407
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v2

    .line 411
    check-cast v2, Ljava/util/Map$Entry;

    .line 412
    .line 413
    invoke-virtual {v7, v4, v2}, Lil/g;->p(Lp0/k;Ljava/util/Map$Entry;)V

    .line 414
    .line 415
    .line 416
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object v3

    .line 420
    check-cast v3, Lp0/k;

    .line 421
    .line 422
    new-instance v5, La8/y0;

    .line 423
    .line 424
    const/16 v8, 0xf

    .line 425
    .line 426
    invoke-direct {v5, v7, v4, v2, v8}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 430
    .line 431
    .line 432
    invoke-static {}, Llp/k1;->a()V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v3}, Lp0/k;->a()V

    .line 436
    .line 437
    .line 438
    iget-object v2, v3, Lp0/k;->m:Ljava/util/HashSet;

    .line 439
    .line 440
    invoke-virtual {v2, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    goto :goto_5

    .line 444
    :cond_5
    iget-object v1, v7, Lil/g;->g:Ljava/lang/Object;

    .line 445
    .line 446
    check-cast v1, Lp0/n;

    .line 447
    .line 448
    new-instance v2, Lg0/c;

    .line 449
    .line 450
    const/4 v3, 0x1

    .line 451
    invoke-direct {v2, v1, v3}, Lg0/c;-><init>(Ljava/lang/Object;I)V

    .line 452
    .line 453
    .line 454
    iget-object v1, v4, Lp0/k;->o:Ljava/util/ArrayList;

    .line 455
    .line 456
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 457
    .line 458
    .line 459
    iget-object v1, v7, Lil/g;->g:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast v1, Lp0/n;

    .line 462
    .line 463
    new-instance v2, Ljava/util/HashMap;

    .line 464
    .line 465
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 466
    .line 467
    .line 468
    invoke-virtual/range {p2 .. p2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 469
    .line 470
    .line 471
    move-result-object v3

    .line 472
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 473
    .line 474
    .line 475
    move-result-object v3

    .line 476
    :goto_6
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 477
    .line 478
    .line 479
    move-result v5

    .line 480
    if-eqz v5, :cond_6

    .line 481
    .line 482
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v5

    .line 486
    check-cast v5, Ljava/util/Map$Entry;

    .line 487
    .line 488
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v7

    .line 492
    check-cast v7, Lb0/z1;

    .line 493
    .line 494
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v5

    .line 498
    invoke-virtual {v1, v5}, Ljava/util/AbstractMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v5

    .line 502
    check-cast v5, Lp0/k;

    .line 503
    .line 504
    invoke-virtual {v2, v7, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    goto :goto_6

    .line 508
    :cond_6
    invoke-virtual {v0, v4, v6}, Lt0/h;->v(Lp0/k;Z)Ljava/util/HashMap;

    .line 509
    .line 510
    .line 511
    move-result-object v1

    .line 512
    invoke-virtual {v0, v2, v1}, Lt0/h;->x(Ljava/util/HashMap;Ljava/util/HashMap;)V

    .line 513
    .line 514
    .line 515
    iget-object v0, v15, Lt0/e;->z:Lh0/v1;

    .line 516
    .line 517
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 518
    .line 519
    .line 520
    move-result-object v0

    .line 521
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v0

    .line 525
    new-instance v1, Ljava/util/ArrayList;

    .line 526
    .line 527
    const/4 v2, 0x1

    .line 528
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 529
    .line 530
    .line 531
    const/16 v26, 0x0

    .line 532
    .line 533
    aget-object v0, v0, v26

    .line 534
    .line 535
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 542
    .line 543
    .line 544
    move-result-object v0

    .line 545
    return-object v0

    .line 546
    :cond_7
    new-instance v0, Ljava/lang/NullPointerException;

    .line 547
    .line 548
    const-string v1, "Null surfaceEdge"

    .line 549
    .line 550
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    throw v0

    .line 554
    :cond_8
    move-object v15, v0

    .line 555
    move-object v0, v6

    .line 556
    invoke-virtual/range {p0 .. p5}, Lt0/e;->F(Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)Lp0/k;

    .line 557
    .line 558
    .line 559
    move-result-object v13

    .line 560
    move-object v1, v0

    .line 561
    new-instance v0, Lp0/k;

    .line 562
    .line 563
    iget-object v4, v15, Lb0/z1;->k:Landroid/graphics/Matrix;

    .line 564
    .line 565
    invoke-virtual {v15}, Lb0/z1;->i()Lh0/b0;

    .line 566
    .line 567
    .line 568
    move-result-object v2

    .line 569
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 570
    .line 571
    .line 572
    invoke-interface {v2}, Lh0/b0;->p()Z

    .line 573
    .line 574
    .line 575
    move-result v5

    .line 576
    iget-object v2, v3, Lh0/k;->a:Landroid/util/Size;

    .line 577
    .line 578
    iget-object v6, v15, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 579
    .line 580
    if-eqz v6, :cond_9

    .line 581
    .line 582
    const/4 v9, 0x0

    .line 583
    goto :goto_7

    .line 584
    :cond_9
    new-instance v6, Landroid/graphics/Rect;

    .line 585
    .line 586
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 587
    .line 588
    .line 589
    move-result v7

    .line 590
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 591
    .line 592
    .line 593
    move-result v2

    .line 594
    const/4 v9, 0x0

    .line 595
    invoke-direct {v6, v9, v9, v7, v2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 596
    .line 597
    .line 598
    :goto_7
    invoke-virtual {v15}, Lb0/z1;->i()Lh0/b0;

    .line 599
    .line 600
    .line 601
    move-result-object v2

    .line 602
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    invoke-virtual {v15, v2, v9}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 606
    .line 607
    .line 608
    move-result v7

    .line 609
    invoke-virtual {v15}, Lb0/z1;->i()Lh0/b0;

    .line 610
    .line 611
    .line 612
    move-result-object v2

    .line 613
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 614
    .line 615
    .line 616
    invoke-virtual {v15, v2}, Lb0/z1;->m(Lh0/b0;)Z

    .line 617
    .line 618
    .line 619
    move-result v9

    .line 620
    move-object v2, v1

    .line 621
    const/4 v1, 0x3

    .line 622
    move-object v8, v2

    .line 623
    const/16 v2, 0x22

    .line 624
    .line 625
    move-object v14, v8

    .line 626
    const/4 v8, -0x1

    .line 627
    invoke-direct/range {v0 .. v9}, Lp0/k;-><init>(IILh0/k;Landroid/graphics/Matrix;ZLandroid/graphics/Rect;IIZ)V

    .line 628
    .line 629
    .line 630
    iput-object v0, v15, Lt0/e;->w:Lp0/k;

    .line 631
    .line 632
    invoke-virtual {v15}, Lb0/z1;->i()Lh0/b0;

    .line 633
    .line 634
    .line 635
    move-result-object v1

    .line 636
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    iput-object v0, v15, Lt0/e;->y:Lp0/k;

    .line 640
    .line 641
    iget-object v0, v15, Lt0/e;->w:Lp0/k;

    .line 642
    .line 643
    move-object/from16 v4, p3

    .line 644
    .line 645
    invoke-virtual {v15, v0, v4, v3}, Lt0/e;->G(Lp0/k;Lh0/o2;Lh0/k;)Lh0/v1;

    .line 646
    .line 647
    .line 648
    move-result-object v7

    .line 649
    iput-object v7, v15, Lt0/e;->A:Lh0/v1;

    .line 650
    .line 651
    iget-object v0, v15, Lt0/e;->B:Lh0/w1;

    .line 652
    .line 653
    if-eqz v0, :cond_a

    .line 654
    .line 655
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 656
    .line 657
    .line 658
    :cond_a
    new-instance v8, Lh0/w1;

    .line 659
    .line 660
    new-instance v0, Lt0/d;

    .line 661
    .line 662
    move-object/from16 v2, p1

    .line 663
    .line 664
    move-object/from16 v5, p4

    .line 665
    .line 666
    move-object v6, v3

    .line 667
    move-object v1, v15

    .line 668
    move-object/from16 v3, p2

    .line 669
    .line 670
    invoke-direct/range {v0 .. v6}, Lt0/d;-><init>(Lt0/e;Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)V

    .line 671
    .line 672
    .line 673
    invoke-direct {v8, v0}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 674
    .line 675
    .line 676
    iput-object v8, v15, Lt0/e;->B:Lh0/w1;

    .line 677
    .line 678
    iput-object v8, v7, Lh0/u1;->f:Lh0/w1;

    .line 679
    .line 680
    iget-object v7, v15, Lt0/e;->y:Lp0/k;

    .line 681
    .line 682
    invoke-virtual {v15}, Lb0/z1;->c()Lh0/b0;

    .line 683
    .line 684
    .line 685
    move-result-object v0

    .line 686
    invoke-virtual {v15}, Lb0/z1;->i()Lh0/b0;

    .line 687
    .line 688
    .line 689
    move-result-object v1

    .line 690
    new-instance v2, Landroidx/lifecycle/c1;

    .line 691
    .line 692
    new-instance v3, Lq0/e;

    .line 693
    .line 694
    iget-object v4, v15, Lt0/e;->r:Lb0/x;

    .line 695
    .line 696
    iget-object v5, v15, Lt0/e;->s:Lb0/x;

    .line 697
    .line 698
    invoke-direct {v3, v10, v4, v5}, Lq0/e;-><init>(Lb0/y;Lb0/x;Lb0/x;)V

    .line 699
    .line 700
    .line 701
    invoke-direct {v2, v0, v1, v3}, Landroidx/lifecycle/c1;-><init>(Lh0/b0;Lh0/b0;Lp0/m;)V

    .line 702
    .line 703
    .line 704
    iput-object v2, v15, Lt0/e;->u:Landroidx/lifecycle/c1;

    .line 705
    .line 706
    iget-object v0, v15, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 707
    .line 708
    if-eqz v0, :cond_b

    .line 709
    .line 710
    const/4 v6, 0x1

    .line 711
    goto :goto_8

    .line 712
    :cond_b
    const/4 v6, 0x0

    .line 713
    :goto_8
    iget-object v0, v15, Lb0/z1;->g:Lh0/o2;

    .line 714
    .line 715
    check-cast v0, Lh0/a1;

    .line 716
    .line 717
    invoke-interface {v0}, Lh0/a1;->o()I

    .line 718
    .line 719
    .line 720
    move-result v5

    .line 721
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 722
    .line 723
    .line 724
    new-instance v8, Ljava/util/HashMap;

    .line 725
    .line 726
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 727
    .line 728
    .line 729
    iget-object v0, v14, Lt0/h;->d:Ljava/util/HashSet;

    .line 730
    .line 731
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 732
    .line 733
    .line 734
    move-result-object v9

    .line 735
    :goto_9
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 736
    .line 737
    .line 738
    move-result v0

    .line 739
    if-eqz v0, :cond_c

    .line 740
    .line 741
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v0

    .line 745
    move-object v1, v0

    .line 746
    check-cast v1, Lb0/z1;

    .line 747
    .line 748
    iget-object v2, v14, Lt0/h;->n:Lt0/b;

    .line 749
    .line 750
    iget-object v3, v14, Lt0/h;->i:Lh0/b0;

    .line 751
    .line 752
    move-object v4, v13

    .line 753
    move-object v0, v14

    .line 754
    invoke-virtual/range {v0 .. v6}, Lt0/h;->s(Lb0/z1;Lt0/b;Lh0/b0;Lp0/k;IZ)Lr0/b;

    .line 755
    .line 756
    .line 757
    move-result-object v10

    .line 758
    iget-object v2, v0, Lt0/h;->o:Lt0/b;

    .line 759
    .line 760
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    iget-object v3, v0, Lt0/h;->j:Lh0/b0;

    .line 764
    .line 765
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 766
    .line 767
    .line 768
    move-object v4, v7

    .line 769
    invoke-virtual/range {v0 .. v6}, Lt0/h;->s(Lb0/z1;Lt0/b;Lh0/b0;Lp0/k;IZ)Lr0/b;

    .line 770
    .line 771
    .line 772
    move-result-object v2

    .line 773
    iget-object v3, v0, Lt0/h;->i:Lh0/b0;

    .line 774
    .line 775
    iget-object v7, v1, Lb0/z1;->g:Lh0/o2;

    .line 776
    .line 777
    check-cast v7, Lh0/a1;

    .line 778
    .line 779
    invoke-interface {v7}, Lh0/a1;->o()I

    .line 780
    .line 781
    .line 782
    move-result v7

    .line 783
    invoke-interface {v3}, Lh0/b0;->a()Lh0/z;

    .line 784
    .line 785
    .line 786
    move-result-object v3

    .line 787
    invoke-interface {v3, v7}, Lh0/z;->r(I)I

    .line 788
    .line 789
    .line 790
    move-result v3

    .line 791
    iget-object v7, v0, Lt0/h;->f:Ljava/util/HashMap;

    .line 792
    .line 793
    invoke-virtual {v7, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v7

    .line 797
    check-cast v7, Lt0/g;

    .line 798
    .line 799
    invoke-static {v7}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    iget-object v7, v7, Lt0/g;->f:Lt0/i;

    .line 803
    .line 804
    iput v3, v7, Lt0/i;->c:I

    .line 805
    .line 806
    new-instance v3, Lq0/a;

    .line 807
    .line 808
    invoke-direct {v3, v10, v2}, Lq0/a;-><init>(Lr0/b;Lr0/b;)V

    .line 809
    .line 810
    .line 811
    invoke-virtual {v8, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 812
    .line 813
    .line 814
    move-object v7, v4

    .line 815
    goto :goto_9

    .line 816
    :cond_c
    move-object v4, v7

    .line 817
    move-object v0, v14

    .line 818
    iget-object v1, v15, Lt0/e;->u:Landroidx/lifecycle/c1;

    .line 819
    .line 820
    new-instance v2, Ljava/util/ArrayList;

    .line 821
    .line 822
    invoke-virtual {v8}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 823
    .line 824
    .line 825
    move-result-object v3

    .line 826
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 827
    .line 828
    .line 829
    new-instance v3, Lq0/b;

    .line 830
    .line 831
    invoke-direct {v3, v13, v4, v2}, Lq0/b;-><init>(Lp0/k;Lp0/k;Ljava/util/ArrayList;)V

    .line 832
    .line 833
    .line 834
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 835
    .line 836
    .line 837
    invoke-static {}, Llp/k1;->a()V

    .line 838
    .line 839
    .line 840
    new-instance v5, Ljava/lang/StringBuilder;

    .line 841
    .line 842
    const-string v7, "DualSurfaceProcessorNode Transform Processor = "

    .line 843
    .line 844
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 845
    .line 846
    .line 847
    iget-object v7, v1, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 848
    .line 849
    check-cast v7, Lp0/m;

    .line 850
    .line 851
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 852
    .line 853
    .line 854
    const-string v9, "\n   primary input = "

    .line 855
    .line 856
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 857
    .line 858
    .line 859
    invoke-virtual {v5, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 860
    .line 861
    .line 862
    const-string v9, "\n   secondary input = "

    .line 863
    .line 864
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 865
    .line 866
    .line 867
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 868
    .line 869
    .line 870
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 871
    .line 872
    .line 873
    move-result-object v4

    .line 874
    const-string v5, "DualSurfaceProcessorNode"

    .line 875
    .line 876
    invoke-static {v5, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 877
    .line 878
    .line 879
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 880
    .line 881
    .line 882
    move-result-object v2

    .line 883
    :goto_a
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 884
    .line 885
    .line 886
    move-result v4

    .line 887
    if-eqz v4, :cond_d

    .line 888
    .line 889
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 890
    .line 891
    .line 892
    move-result-object v4

    .line 893
    check-cast v4, Lq0/a;

    .line 894
    .line 895
    new-instance v5, Ljava/lang/StringBuilder;

    .line 896
    .line 897
    invoke-direct {v5, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 901
    .line 902
    .line 903
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 904
    .line 905
    .line 906
    move-result-object v4

    .line 907
    invoke-static {v12, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    goto :goto_a

    .line 911
    :cond_d
    iput-object v3, v1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 912
    .line 913
    new-instance v2, Lp0/n;

    .line 914
    .line 915
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 916
    .line 917
    .line 918
    iput-object v2, v1, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 919
    .line 920
    iget-object v2, v1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 921
    .line 922
    check-cast v2, Lq0/b;

    .line 923
    .line 924
    iget-object v3, v2, Lq0/b;->a:Lp0/k;

    .line 925
    .line 926
    iget-object v4, v2, Lq0/b;->b:Lp0/k;

    .line 927
    .line 928
    iget-object v2, v2, Lq0/b;->c:Ljava/util/ArrayList;

    .line 929
    .line 930
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 931
    .line 932
    .line 933
    move-result-object v2

    .line 934
    :goto_b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 935
    .line 936
    .line 937
    move-result v5

    .line 938
    if-eqz v5, :cond_f

    .line 939
    .line 940
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 941
    .line 942
    .line 943
    move-result-object v5

    .line 944
    check-cast v5, Lq0/a;

    .line 945
    .line 946
    iget-object v9, v1, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 947
    .line 948
    check-cast v9, Lp0/n;

    .line 949
    .line 950
    iget-object v10, v5, Lq0/a;->a:Lr0/b;

    .line 951
    .line 952
    iget-object v11, v10, Lr0/b;->d:Landroid/graphics/Rect;

    .line 953
    .line 954
    iget v12, v10, Lr0/b;->f:I

    .line 955
    .line 956
    iget-boolean v14, v10, Lr0/b;->g:Z

    .line 957
    .line 958
    move-object/from16 p1, v2

    .line 959
    .line 960
    new-instance v2, Landroid/graphics/Matrix;

    .line 961
    .line 962
    move-object/from16 p2, v8

    .line 963
    .line 964
    iget-object v8, v3, Lp0/k;->b:Landroid/graphics/Matrix;

    .line 965
    .line 966
    invoke-direct {v2, v8}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 967
    .line 968
    .line 969
    new-instance v8, Landroid/graphics/RectF;

    .line 970
    .line 971
    invoke-direct {v8, v11}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 972
    .line 973
    .line 974
    move-object/from16 v16, v11

    .line 975
    .line 976
    iget-object v11, v10, Lr0/b;->e:Landroid/util/Size;

    .line 977
    .line 978
    invoke-static {v11}, Li0/f;->h(Landroid/util/Size;)Landroid/graphics/RectF;

    .line 979
    .line 980
    .line 981
    move-result-object v15

    .line 982
    invoke-static {v8, v15, v12, v14}, Li0/f;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;IZ)Landroid/graphics/Matrix;

    .line 983
    .line 984
    .line 985
    move-result-object v8

    .line 986
    invoke-virtual {v2, v8}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 987
    .line 988
    .line 989
    invoke-static/range {v16 .. v16}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 990
    .line 991
    .line 992
    move-result-object v8

    .line 993
    invoke-static {v8, v12}, Li0/f;->g(Landroid/util/Size;I)Landroid/util/Size;

    .line 994
    .line 995
    .line 996
    move-result-object v8

    .line 997
    const/4 v15, 0x0

    .line 998
    invoke-static {v8, v15, v11}, Li0/f;->d(Landroid/util/Size;ZLandroid/util/Size;)Z

    .line 999
    .line 1000
    .line 1001
    move-result v8

    .line 1002
    invoke-static {v8}, Ljp/ed;->a(Z)V

    .line 1003
    .line 1004
    .line 1005
    new-instance v8, Landroid/graphics/Rect;

    .line 1006
    .line 1007
    move-object/from16 v20, v2

    .line 1008
    .line 1009
    invoke-virtual {v11}, Landroid/util/Size;->getWidth()I

    .line 1010
    .line 1011
    .line 1012
    move-result v2

    .line 1013
    move/from16 v16, v12

    .line 1014
    .line 1015
    invoke-virtual {v11}, Landroid/util/Size;->getHeight()I

    .line 1016
    .line 1017
    .line 1018
    move-result v12

    .line 1019
    invoke-direct {v8, v15, v15, v2, v12}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 1020
    .line 1021
    .line 1022
    iget-object v2, v3, Lp0/k;->g:Lh0/k;

    .line 1023
    .line 1024
    invoke-virtual {v2}, Lh0/k;->b()Lss/b;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v2

    .line 1028
    iput-object v11, v2, Lss/b;->e:Ljava/lang/Object;

    .line 1029
    .line 1030
    invoke-virtual {v2}, Lss/b;->c()Lh0/k;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v19

    .line 1034
    move/from16 v2, v16

    .line 1035
    .line 1036
    new-instance v16, Lp0/k;

    .line 1037
    .line 1038
    iget v11, v10, Lr0/b;->b:I

    .line 1039
    .line 1040
    iget v10, v10, Lr0/b;->c:I

    .line 1041
    .line 1042
    iget v12, v3, Lp0/k;->i:I

    .line 1043
    .line 1044
    sub-int v23, v12, v2

    .line 1045
    .line 1046
    iget-boolean v2, v3, Lp0/k;->e:Z

    .line 1047
    .line 1048
    if-eq v2, v14, :cond_e

    .line 1049
    .line 1050
    const/16 v25, 0x1

    .line 1051
    .line 1052
    goto :goto_c

    .line 1053
    :cond_e
    const/16 v25, 0x0

    .line 1054
    .line 1055
    :goto_c
    const/16 v21, 0x0

    .line 1056
    .line 1057
    const/16 v24, -0x1

    .line 1058
    .line 1059
    move-object/from16 v22, v8

    .line 1060
    .line 1061
    move/from16 v18, v10

    .line 1062
    .line 1063
    move/from16 v17, v11

    .line 1064
    .line 1065
    invoke-direct/range {v16 .. v25}, Lp0/k;-><init>(IILh0/k;Landroid/graphics/Matrix;ZLandroid/graphics/Rect;IIZ)V

    .line 1066
    .line 1067
    .line 1068
    move-object/from16 v2, v16

    .line 1069
    .line 1070
    invoke-virtual {v9, v5, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1071
    .line 1072
    .line 1073
    move-object/from16 v15, p0

    .line 1074
    .line 1075
    move-object/from16 v2, p1

    .line 1076
    .line 1077
    move-object/from16 v8, p2

    .line 1078
    .line 1079
    goto/16 :goto_b

    .line 1080
    .line 1081
    :cond_f
    move-object/from16 p2, v8

    .line 1082
    .line 1083
    iget-object v2, v1, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 1084
    .line 1085
    check-cast v2, Lh0/b0;

    .line 1086
    .line 1087
    const/4 v5, 0x1

    .line 1088
    invoke-virtual {v3, v2, v5}, Lp0/k;->c(Lh0/b0;Z)Lb0/x1;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v2

    .line 1092
    invoke-interface {v7, v2}, Lp0/m;->a(Lb0/x1;)V

    .line 1093
    .line 1094
    .line 1095
    iget-object v2, v1, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 1096
    .line 1097
    check-cast v2, Lh0/b0;

    .line 1098
    .line 1099
    const/4 v9, 0x0

    .line 1100
    invoke-virtual {v4, v2, v9}, Lp0/k;->c(Lh0/b0;Z)Lb0/x1;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v2

    .line 1104
    invoke-interface {v7, v2}, Lp0/m;->a(Lb0/x1;)V

    .line 1105
    .line 1106
    .line 1107
    iget-object v2, v1, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 1108
    .line 1109
    move-object/from16 v17, v2

    .line 1110
    .line 1111
    check-cast v17, Lh0/b0;

    .line 1112
    .line 1113
    iget-object v2, v1, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 1114
    .line 1115
    move-object/from16 v18, v2

    .line 1116
    .line 1117
    check-cast v18, Lh0/b0;

    .line 1118
    .line 1119
    iget-object v2, v1, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 1120
    .line 1121
    check-cast v2, Lp0/n;

    .line 1122
    .line 1123
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 1124
    .line 1125
    .line 1126
    move-result-object v2

    .line 1127
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v2

    .line 1131
    :goto_d
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1132
    .line 1133
    .line 1134
    move-result v5

    .line 1135
    if-eqz v5, :cond_10

    .line 1136
    .line 1137
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v5

    .line 1141
    move-object/from16 v21, v5

    .line 1142
    .line 1143
    check-cast v21, Ljava/util/Map$Entry;

    .line 1144
    .line 1145
    move-object/from16 v16, v1

    .line 1146
    .line 1147
    move-object/from16 v19, v3

    .line 1148
    .line 1149
    move-object/from16 v20, v4

    .line 1150
    .line 1151
    invoke-virtual/range {v16 .. v21}, Landroidx/lifecycle/c1;->m(Lh0/b0;Lh0/b0;Lp0/k;Lp0/k;Ljava/util/Map$Entry;)V

    .line 1152
    .line 1153
    .line 1154
    invoke-interface/range {v21 .. v21}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v1

    .line 1158
    check-cast v1, Lp0/k;

    .line 1159
    .line 1160
    move-object/from16 v22, v21

    .line 1161
    .line 1162
    move-object/from16 v21, v20

    .line 1163
    .line 1164
    move-object/from16 v20, v19

    .line 1165
    .line 1166
    move-object/from16 v19, v18

    .line 1167
    .line 1168
    move-object/from16 v18, v17

    .line 1169
    .line 1170
    move-object/from16 v17, v16

    .line 1171
    .line 1172
    new-instance v16, Lq0/f;

    .line 1173
    .line 1174
    const/16 v23, 0x0

    .line 1175
    .line 1176
    invoke-direct/range {v16 .. v23}, Lq0/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1177
    .line 1178
    .line 1179
    move-object/from16 v4, v16

    .line 1180
    .line 1181
    move-object/from16 v3, v17

    .line 1182
    .line 1183
    move-object/from16 v17, v18

    .line 1184
    .line 1185
    move-object/from16 v18, v19

    .line 1186
    .line 1187
    move-object/from16 v19, v20

    .line 1188
    .line 1189
    move-object/from16 v20, v21

    .line 1190
    .line 1191
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1192
    .line 1193
    .line 1194
    invoke-static {}, Llp/k1;->a()V

    .line 1195
    .line 1196
    .line 1197
    invoke-virtual {v1}, Lp0/k;->a()V

    .line 1198
    .line 1199
    .line 1200
    iget-object v1, v1, Lp0/k;->m:Ljava/util/HashSet;

    .line 1201
    .line 1202
    invoke-virtual {v1, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 1203
    .line 1204
    .line 1205
    move-object v1, v3

    .line 1206
    move-object/from16 v3, v19

    .line 1207
    .line 1208
    move-object/from16 v4, v20

    .line 1209
    .line 1210
    goto :goto_d

    .line 1211
    :cond_10
    move-object v3, v1

    .line 1212
    iget-object v1, v3, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 1213
    .line 1214
    check-cast v1, Lp0/n;

    .line 1215
    .line 1216
    new-instance v2, Ljava/util/HashMap;

    .line 1217
    .line 1218
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 1219
    .line 1220
    .line 1221
    invoke-virtual/range {p2 .. p2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v3

    .line 1225
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v3

    .line 1229
    :goto_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1230
    .line 1231
    .line 1232
    move-result v4

    .line 1233
    if-eqz v4, :cond_11

    .line 1234
    .line 1235
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v4

    .line 1239
    check-cast v4, Ljava/util/Map$Entry;

    .line 1240
    .line 1241
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v5

    .line 1245
    check-cast v5, Lb0/z1;

    .line 1246
    .line 1247
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v4

    .line 1251
    invoke-virtual {v1, v4}, Ljava/util/AbstractMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v4

    .line 1255
    check-cast v4, Lp0/k;

    .line 1256
    .line 1257
    invoke-virtual {v2, v5, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1258
    .line 1259
    .line 1260
    goto :goto_e

    .line 1261
    :cond_11
    invoke-virtual {v0, v13, v6}, Lt0/h;->v(Lp0/k;Z)Ljava/util/HashMap;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v1

    .line 1265
    invoke-virtual {v0, v2, v1}, Lt0/h;->x(Ljava/util/HashMap;Ljava/util/HashMap;)V

    .line 1266
    .line 1267
    .line 1268
    move-object/from16 v15, p0

    .line 1269
    .line 1270
    iget-object v0, v15, Lt0/e;->z:Lh0/v1;

    .line 1271
    .line 1272
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 1273
    .line 1274
    .line 1275
    move-result-object v0

    .line 1276
    iget-object v1, v15, Lt0/e;->A:Lh0/v1;

    .line 1277
    .line 1278
    invoke-virtual {v1}, Lh0/v1;->c()Lh0/z1;

    .line 1279
    .line 1280
    .line 1281
    move-result-object v1

    .line 1282
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v0

    .line 1286
    new-instance v1, Ljava/util/ArrayList;

    .line 1287
    .line 1288
    const/4 v2, 0x2

    .line 1289
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1290
    .line 1291
    .line 1292
    move v14, v9

    .line 1293
    :goto_f
    if-ge v14, v2, :cond_12

    .line 1294
    .line 1295
    aget-object v3, v0, v14

    .line 1296
    .line 1297
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1298
    .line 1299
    .line 1300
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1301
    .line 1302
    .line 1303
    add-int/lit8 v14, v14, 0x1

    .line 1304
    .line 1305
    goto :goto_f

    .line 1306
    :cond_12
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v0

    .line 1310
    return-object v0
.end method

.method public final F(Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)Lp0/k;
    .locals 10

    .line 1
    new-instance v0, Lp0/k;

    .line 2
    .line 3
    iget-object v4, p0, Lb0/z1;->k:Landroid/graphics/Matrix;

    .line 4
    .line 5
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lh0/b0;->p()Z

    .line 13
    .line 14
    .line 15
    move-result v5

    .line 16
    iget-object v1, p4, Lh0/k;->a:Landroid/util/Size;

    .line 17
    .line 18
    iget-object v2, p0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 19
    .line 20
    const/4 v6, 0x0

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Landroid/graphics/Rect;

    .line 25
    .line 26
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    invoke-direct {v2, v6, v6, v7, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 35
    .line 36
    .line 37
    :goto_0
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, v1, v6}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, v1}, Lb0/z1;->m(Lh0/b0;)Z

    .line 56
    .line 57
    .line 58
    move-result v9

    .line 59
    const/4 v1, 0x3

    .line 60
    move-object v6, v2

    .line 61
    const/16 v2, 0x22

    .line 62
    .line 63
    const/4 v8, -0x1

    .line 64
    move-object v3, p4

    .line 65
    invoke-direct/range {v0 .. v9}, Lp0/k;-><init>(IILh0/k;Landroid/graphics/Matrix;ZLandroid/graphics/Rect;IIZ)V

    .line 66
    .line 67
    .line 68
    iput-object v0, p0, Lt0/e;->v:Lp0/k;

    .line 69
    .line 70
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    iput-object v0, p0, Lt0/e;->x:Lp0/k;

    .line 78
    .line 79
    iget-object v0, p0, Lt0/e;->v:Lp0/k;

    .line 80
    .line 81
    invoke-virtual {p0, v0, p3, p4}, Lt0/e;->G(Lp0/k;Lh0/o2;Lh0/k;)Lh0/v1;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    iput-object v7, p0, Lt0/e;->z:Lh0/v1;

    .line 86
    .line 87
    iget-object v0, p0, Lt0/e;->B:Lh0/w1;

    .line 88
    .line 89
    if-eqz v0, :cond_1

    .line 90
    .line 91
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 92
    .line 93
    .line 94
    :cond_1
    new-instance v8, Lh0/w1;

    .line 95
    .line 96
    new-instance v0, Lt0/d;

    .line 97
    .line 98
    move-object v1, p0

    .line 99
    move-object v2, p1

    .line 100
    move-object v3, p2

    .line 101
    move-object v4, p3

    .line 102
    move-object v5, p4

    .line 103
    move-object v6, p5

    .line 104
    invoke-direct/range {v0 .. v6}, Lt0/d;-><init>(Lt0/e;Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)V

    .line 105
    .line 106
    .line 107
    invoke-direct {v8, v0}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 108
    .line 109
    .line 110
    iput-object v8, p0, Lt0/e;->B:Lh0/w1;

    .line 111
    .line 112
    iput-object v8, v7, Lh0/u1;->f:Lh0/w1;

    .line 113
    .line 114
    iget-object p0, p0, Lt0/e;->x:Lp0/k;

    .line 115
    .line 116
    return-object p0
.end method

.method public final G(Lp0/k;Lh0/o2;Lh0/k;)Lh0/v1;
    .locals 11

    .line 1
    iget-object v0, p3, Lh0/k;->a:Landroid/util/Size;

    .line 2
    .line 3
    invoke-static {p2, v0}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    iget-object v0, p2, Lh0/u1;->b:Lb0/n1;

    .line 8
    .line 9
    iget-object v1, p0, Lt0/e;->q:Lt0/h;

    .line 10
    .line 11
    iget-object v2, v1, Lt0/h;->d:Ljava/util/HashSet;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const/4 v3, -0x1

    .line 18
    move v4, v3

    .line 19
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    if-eqz v5, :cond_1

    .line 24
    .line 25
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    check-cast v5, Lb0/z1;

    .line 30
    .line 31
    iget-object v5, v5, Lb0/z1;->g:Lh0/o2;

    .line 32
    .line 33
    sget-object v6, Lh0/o2;->P0:Lh0/g;

    .line 34
    .line 35
    invoke-interface {v5, v6}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    check-cast v5, Lh0/z1;

    .line 40
    .line 41
    iget-object v5, v5, Lh0/z1;->g:Lh0/o0;

    .line 42
    .line 43
    iget v5, v5, Lh0/o0;->c:I

    .line 44
    .line 45
    sget-object v6, Lh0/z1;->j:Ljava/util/List;

    .line 46
    .line 47
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    invoke-interface {v6, v7}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    invoke-interface {v6, v8}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-lt v7, v6, :cond_0

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    move v4, v5

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    if-eq v4, v3, :cond_2

    .line 69
    .line 70
    iput v4, v0, Lb0/n1;->d:I

    .line 71
    .line 72
    :cond_2
    iget-object v2, p3, Lh0/k;->a:Landroid/util/Size;

    .line 73
    .line 74
    iget-object v4, v1, Lt0/h;->d:Ljava/util/HashSet;

    .line 75
    .line 76
    invoke-virtual {v4}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_9

    .line 85
    .line 86
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    check-cast v5, Lb0/z1;

    .line 91
    .line 92
    iget-object v5, v5, Lb0/z1;->g:Lh0/o2;

    .line 93
    .line 94
    invoke-static {v5, v2}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    invoke-virtual {v5}, Lh0/v1;->c()Lh0/z1;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    iget-object v6, v5, Lh0/z1;->g:Lh0/o0;

    .line 103
    .line 104
    iget-object v7, v6, Lh0/o0;->d:Ljava/util/List;

    .line 105
    .line 106
    invoke-virtual {v0, v7}, Lb0/n1;->a(Ljava/util/Collection;)V

    .line 107
    .line 108
    .line 109
    iget-object v7, v5, Lh0/z1;->e:Ljava/util/List;

    .line 110
    .line 111
    iget-object v8, p2, Lh0/u1;->e:Ljava/util/ArrayList;

    .line 112
    .line 113
    invoke-interface {v7}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    :cond_3
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 118
    .line 119
    .line 120
    move-result v9

    .line 121
    if-eqz v9, :cond_4

    .line 122
    .line 123
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    check-cast v9, Lh0/m;

    .line 128
    .line 129
    invoke-virtual {v0, v9}, Lb0/n1;->c(Lh0/m;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v10

    .line 136
    if-nez v10, :cond_3

    .line 137
    .line 138
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_4
    iget-object v7, v5, Lh0/z1;->d:Ljava/util/List;

    .line 143
    .line 144
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    if-eqz v8, :cond_6

    .line 153
    .line 154
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v8

    .line 158
    check-cast v8, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 159
    .line 160
    iget-object v9, p2, Lh0/u1;->d:Ljava/util/ArrayList;

    .line 161
    .line 162
    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v10

    .line 166
    if-eqz v10, :cond_5

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_5
    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_6
    iget-object v5, v5, Lh0/z1;->c:Ljava/util/List;

    .line 174
    .line 175
    check-cast v5, Ljava/util/List;

    .line 176
    .line 177
    invoke-interface {v5}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 182
    .line 183
    .line 184
    move-result v7

    .line 185
    if-eqz v7, :cond_8

    .line 186
    .line 187
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v7

    .line 191
    check-cast v7, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 192
    .line 193
    iget-object v8, p2, Lh0/u1;->c:Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-virtual {v8, v7}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v9

    .line 199
    if-eqz v9, :cond_7

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_7
    invoke-virtual {v8, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_8
    iget-object v5, v6, Lh0/o0;->b:Lh0/n1;

    .line 207
    .line 208
    invoke-virtual {v0, v5}, Lb0/n1;->i(Lh0/q0;)V

    .line 209
    .line 210
    .line 211
    goto/16 :goto_1

    .line 212
    .line 213
    :cond_9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    invoke-static {}, Llp/k1;->a()V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p1}, Lp0/k;->a()V

    .line 220
    .line 221
    .line 222
    iget-boolean v2, p1, Lp0/k;->j:Z

    .line 223
    .line 224
    const/4 v4, 0x1

    .line 225
    xor-int/2addr v2, v4

    .line 226
    const-string v5, "Consumer can only be linked once."

    .line 227
    .line 228
    invoke-static {v5, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 229
    .line 230
    .line 231
    iput-boolean v4, p1, Lp0/k;->j:Z

    .line 232
    .line 233
    iget-object p1, p1, Lp0/k;->l:Lp0/j;

    .line 234
    .line 235
    iget-object v2, p3, Lh0/k;->c:Lb0/y;

    .line 236
    .line 237
    invoke-virtual {p2, p1, v2, v3}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 238
    .line 239
    .line 240
    iget-object p1, v1, Lt0/h;->k:Lb0/e1;

    .line 241
    .line 242
    invoke-virtual {v0, p1}, Lb0/n1;->c(Lh0/m;)V

    .line 243
    .line 244
    .line 245
    iget-object p1, p3, Lh0/k;->f:Lh0/q0;

    .line 246
    .line 247
    if-eqz p1, :cond_a

    .line 248
    .line 249
    invoke-virtual {v0, p1}, Lb0/n1;->i(Lh0/q0;)V

    .line 250
    .line 251
    .line 252
    :cond_a
    iget p1, p3, Lh0/k;->d:I

    .line 253
    .line 254
    iput p1, p2, Lh0/u1;->h:I

    .line 255
    .line 256
    invoke-virtual {p0, p2, p3}, Lb0/z1;->a(Lh0/v1;Lh0/k;)V

    .line 257
    .line 258
    .line 259
    return-object p2
.end method

.method public final f(ZLh0/r2;)Lh0/o2;
    .locals 3

    .line 1
    iget-object v0, p0, Lt0/e;->p:Lt0/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lh0/o2;->J()Lh0/q2;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-interface {p2, v1, v2}, Lh0/r2;->a(Lh0/q2;I)Lh0/q0;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p1, v0, Lt0/f;->d:Lh0/n1;

    .line 15
    .line 16
    invoke-static {p2, p1}, Lh0/q0;->w(Lh0/q0;Lh0/q0;)Lh0/n1;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    :cond_0
    if-nez p2, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    return-object p0

    .line 24
    :cond_1
    invoke-virtual {p0, p2}, Lt0/e;->l(Lh0/q0;)Lh0/n2;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, La0/i;

    .line 29
    .line 30
    invoke-virtual {p0}, La0/i;->b()Lh0/o2;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public final j(Lh0/z;)Ljava/util/Set;
    .locals 2

    .line 1
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 2
    .line 3
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    return-object v1

    .line 13
    :cond_0
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_3

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lb0/z1;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Lb0/z1;->j(Lh0/z;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-nez v0, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    if-nez v1, :cond_2

    .line 37
    .line 38
    new-instance v1, Ljava/util/HashSet;

    .line 39
    .line 40
    invoke-direct {v1, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    invoke-interface {v1, v0}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    return-object v1
.end method

.method public final k()Ljava/util/Set;
    .locals 1

    .line 1
    new-instance p0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x3

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final l(Lh0/q0;)Lh0/n2;
    .locals 0

    .line 1
    new-instance p0, La0/i;

    .line 2
    .line 3
    invoke-static {p1}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {p0, p1}, La0/i;-><init>(Lh0/j1;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public final r()V
    .locals 5

    .line 1
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 2
    .line 3
    iget-object v0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lb0/z1;

    .line 20
    .line 21
    iget-object v2, p0, Lt0/h;->f:Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lt0/g;

    .line 28
    .line 29
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    iget-object v4, p0, Lt0/h;->h:Lh0/r2;

    .line 34
    .line 35
    invoke-virtual {v1, v3, v4}, Lb0/z1;->f(ZLh0/r2;)Lh0/o2;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-virtual {v1, v2, v4, v4, v3}, Lb0/z1;->b(Lh0/b0;Lh0/b0;Lh0/o2;Lh0/o2;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    return-void
.end method

.method public final s()V
    .locals 1

    .line 1
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 2
    .line 3
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lb0/z1;

    .line 20
    .line 21
    invoke-virtual {v0}, Lb0/z1;->s()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public final t(Lh0/z;Lh0/n2;)Lh0/o2;
    .locals 17

    .line 1
    invoke-interface/range {p2 .. p2}, Lb0/z;->a()Lh0/i1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object/from16 v1, p0

    .line 6
    .line 7
    iget-object v1, v1, Lt0/e;->q:Lt0/h;

    .line 8
    .line 9
    iget-object v2, v1, Lt0/h;->l:Ljava/util/HashSet;

    .line 10
    .line 11
    iget-object v3, v1, Lt0/h;->n:Lt0/b;

    .line 12
    .line 13
    iget-object v4, v3, Lt0/b;->f:Lh0/z;

    .line 14
    .line 15
    const/16 v5, 0x22

    .line 16
    .line 17
    invoke-interface {v4, v5}, Lh0/z;->k(I)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    const/4 v6, 0x0

    .line 22
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    iget-object v8, v3, Lt0/b;->d:Ljava/util/HashSet;

    .line 27
    .line 28
    invoke-virtual {v8}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v9

    .line 32
    :cond_0
    :goto_0
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v10

    .line 36
    const/4 v11, 0x0

    .line 37
    if-eqz v10, :cond_2

    .line 38
    .line 39
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v10

    .line 43
    check-cast v10, Lh0/o2;

    .line 44
    .line 45
    sget-object v12, Lh0/o2;->Y0:Lh0/g;

    .line 46
    .line 47
    sget-object v13, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-interface {v10, v12, v13}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v12

    .line 53
    check-cast v12, Ljava/lang/Boolean;

    .line 54
    .line 55
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    if-eqz v12, :cond_1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    instance-of v12, v10, Lh0/a1;

    .line 63
    .line 64
    if-eqz v12, :cond_0

    .line 65
    .line 66
    check-cast v10, Lh0/a1;

    .line 67
    .line 68
    sget-object v12, Lh0/a1;->N0:Lh0/g;

    .line 69
    .line 70
    invoke-interface {v10, v12, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v10

    .line 74
    check-cast v10, Ls0/b;

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_2
    sget-object v9, Lh0/a1;->M0:Lh0/g;

    .line 78
    .line 79
    move-object v10, v0

    .line 80
    check-cast v10, Lh0/n1;

    .line 81
    .line 82
    invoke-virtual {v10, v9, v11}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v9

    .line 86
    check-cast v9, Ljava/util/List;

    .line 87
    .line 88
    if-eqz v9, :cond_5

    .line 89
    .line 90
    invoke-interface {v9}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    :cond_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v9

    .line 98
    if-eqz v9, :cond_4

    .line 99
    .line 100
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v9

    .line 104
    check-cast v9, Landroid/util/Pair;

    .line 105
    .line 106
    iget-object v10, v9, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v10, Ljava/lang/Integer;

    .line 109
    .line 110
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v12

    .line 114
    invoke-virtual {v10, v12}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v10

    .line 118
    if-eqz v10, :cond_3

    .line 119
    .line 120
    iget-object v4, v9, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v4, [Landroid/util/Size;

    .line 123
    .line 124
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    goto :goto_1

    .line 129
    :cond_4
    new-instance v4, Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 132
    .line 133
    .line 134
    :cond_5
    :goto_1
    iget-object v5, v3, Lt0/b;->c:Landroid/util/Rational;

    .line 135
    .line 136
    new-instance v9, Ljava/util/ArrayList;

    .line 137
    .line 138
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 139
    .line 140
    .line 141
    new-instance v10, Ljava/util/HashSet;

    .line 142
    .line 143
    invoke-direct {v10}, Ljava/util/HashSet;-><init>()V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v8}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 147
    .line 148
    .line 149
    move-result-object v12

    .line 150
    :goto_2
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 151
    .line 152
    .line 153
    move-result v13

    .line 154
    if-eqz v13, :cond_6

    .line 155
    .line 156
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v13

    .line 160
    check-cast v13, Lh0/o2;

    .line 161
    .line 162
    invoke-virtual {v3, v13}, Lt0/b;->c(Lh0/o2;)Ljava/util/List;

    .line 163
    .line 164
    .line 165
    move-result-object v13

    .line 166
    invoke-interface {v10, v13}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 167
    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_6
    invoke-virtual {v10}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 171
    .line 172
    .line 173
    move-result-object v10

    .line 174
    :cond_7
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 175
    .line 176
    .line 177
    move-result v12

    .line 178
    if-eqz v12, :cond_8

    .line 179
    .line 180
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v12

    .line 184
    check-cast v12, Landroid/util/Size;

    .line 185
    .line 186
    invoke-static {v5, v12}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 187
    .line 188
    .line 189
    move-result v12

    .line 190
    if-nez v12, :cond_7

    .line 191
    .line 192
    iget-object v10, v3, Lt0/b;->b:Landroid/util/Rational;

    .line 193
    .line 194
    invoke-virtual {v3, v10, v4, v6}, Lt0/b;->g(Landroid/util/Rational;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 195
    .line 196
    .line 197
    move-result-object v10

    .line 198
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 199
    .line 200
    .line 201
    :cond_8
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 202
    .line 203
    .line 204
    move-result v10

    .line 205
    invoke-virtual {v8}, Ljava/util/HashSet;->isEmpty()Z

    .line 206
    .line 207
    .line 208
    move-result v12

    .line 209
    const/4 v13, 0x1

    .line 210
    if-eqz v12, :cond_9

    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_9
    invoke-virtual {v8}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 214
    .line 215
    .line 216
    move-result-object v8

    .line 217
    :goto_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 218
    .line 219
    .line 220
    move-result v12

    .line 221
    if-eqz v12, :cond_f

    .line 222
    .line 223
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v12

    .line 227
    check-cast v12, Lh0/o2;

    .line 228
    .line 229
    invoke-virtual {v3, v12}, Lt0/b;->c(Lh0/o2;)Ljava/util/List;

    .line 230
    .line 231
    .line 232
    move-result-object v12

    .line 233
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 234
    .line 235
    .line 236
    move-result-object v12

    .line 237
    move v14, v6

    .line 238
    move v15, v14

    .line 239
    :goto_4
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 240
    .line 241
    .line 242
    move-result v16

    .line 243
    if-eqz v16, :cond_d

    .line 244
    .line 245
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v16

    .line 249
    move-object/from16 v11, v16

    .line 250
    .line 251
    check-cast v11, Landroid/util/Size;

    .line 252
    .line 253
    invoke-static {v5, v11}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 254
    .line 255
    .line 256
    move-result v11

    .line 257
    if-eqz v11, :cond_a

    .line 258
    .line 259
    move v14, v13

    .line 260
    :cond_a
    if-eqz v15, :cond_b

    .line 261
    .line 262
    if-eqz v11, :cond_b

    .line 263
    .line 264
    goto :goto_5

    .line 265
    :cond_b
    if-nez v11, :cond_c

    .line 266
    .line 267
    move v15, v13

    .line 268
    :cond_c
    const/4 v11, 0x0

    .line 269
    goto :goto_4

    .line 270
    :cond_d
    if-nez v14, :cond_e

    .line 271
    .line 272
    goto :goto_5

    .line 273
    :cond_e
    const/4 v11, 0x0

    .line 274
    goto :goto_3

    .line 275
    :cond_f
    move v10, v6

    .line 276
    :goto_5
    invoke-virtual {v3, v5, v4, v6}, Lt0/b;->g(Landroid/util/Rational;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    invoke-virtual {v9, v10, v5}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    .line 281
    .line 282
    .line 283
    invoke-virtual {v3, v4, v6}, Lt0/b;->f(Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 284
    .line 285
    .line 286
    move-result-object v5

    .line 287
    invoke-virtual {v9, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 288
    .line 289
    .line 290
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 291
    .line 292
    .line 293
    move-result v5

    .line 294
    const-string v8, "ResolutionsMerger"

    .line 295
    .line 296
    if-eqz v5, :cond_10

    .line 297
    .line 298
    const-string v5, "Failed to find a parent resolution that does not result in double-cropping, this might due to camera not supporting 4:3 and 16:9resolutions or a strict ResolutionSelector settings. Starting resolution selection process with resolutions that might have a smaller FOV."

    .line 299
    .line 300
    invoke-static {v8, v5}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v3, v4, v13}, Lt0/b;->f(Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 308
    .line 309
    .line 310
    :cond_10
    new-instance v3, Ljava/lang/StringBuilder;

    .line 311
    .line 312
    const-string v4, "Parent resolutions: "

    .line 313
    .line 314
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v3, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 318
    .line 319
    .line 320
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    invoke-static {v8, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    sget-object v3, Lh0/a1;->O0:Lh0/g;

    .line 328
    .line 329
    check-cast v0, Lh0/j1;

    .line 330
    .line 331
    invoke-virtual {v0, v3, v9}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    sget-object v3, Lh0/o2;->T0:Lh0/g;

    .line 335
    .line 336
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    move v5, v6

    .line 341
    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 342
    .line 343
    .line 344
    move-result v8

    .line 345
    if-eqz v8, :cond_11

    .line 346
    .line 347
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v8

    .line 351
    check-cast v8, Lh0/o2;

    .line 352
    .line 353
    sget-object v9, Lh0/o2;->T0:Lh0/g;

    .line 354
    .line 355
    invoke-interface {v8, v9, v7}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v8

    .line 359
    check-cast v8, Ljava/lang/Integer;

    .line 360
    .line 361
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 362
    .line 363
    .line 364
    move-result v8

    .line 365
    invoke-static {v5, v8}, Ljava/lang/Math;->max(II)I

    .line 366
    .line 367
    .line 368
    move-result v5

    .line 369
    goto :goto_6

    .line 370
    :cond_11
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 371
    .line 372
    .line 373
    move-result-object v4

    .line 374
    invoke-virtual {v0, v3, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 375
    .line 376
    .line 377
    new-instance v3, Ljava/util/ArrayList;

    .line 378
    .line 379
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 383
    .line 384
    .line 385
    move-result-object v4

    .line 386
    :goto_7
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 387
    .line 388
    .line 389
    move-result v5

    .line 390
    if-eqz v5, :cond_12

    .line 391
    .line 392
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v5

    .line 396
    check-cast v5, Lh0/o2;

    .line 397
    .line 398
    sget-object v8, Lh0/z0;->E0:Lh0/g;

    .line 399
    .line 400
    sget-object v9, Lb0/y;->c:Lb0/y;

    .line 401
    .line 402
    invoke-interface {v5, v8, v9}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v5

    .line 406
    check-cast v5, Lb0/y;

    .line 407
    .line 408
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 409
    .line 410
    .line 411
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    goto :goto_7

    .line 415
    :cond_12
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 416
    .line 417
    .line 418
    move-result v4

    .line 419
    if-eqz v4, :cond_13

    .line 420
    .line 421
    goto/16 :goto_c

    .line 422
    .line 423
    :cond_13
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v4

    .line 427
    check-cast v4, Lb0/y;

    .line 428
    .line 429
    iget v5, v4, Lb0/y;->a:I

    .line 430
    .line 431
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 432
    .line 433
    .line 434
    move-result-object v5

    .line 435
    iget v4, v4, Lb0/y;->b:I

    .line 436
    .line 437
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 438
    .line 439
    .line 440
    move-result-object v4

    .line 441
    move v6, v13

    .line 442
    :goto_8
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 443
    .line 444
    .line 445
    move-result v8

    .line 446
    if-ge v6, v8, :cond_1e

    .line 447
    .line 448
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v8

    .line 452
    check-cast v8, Lb0/y;

    .line 453
    .line 454
    iget v9, v8, Lb0/y;->a:I

    .line 455
    .line 456
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 457
    .line 458
    .line 459
    move-result-object v9

    .line 460
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 461
    .line 462
    .line 463
    move-result-object v10

    .line 464
    const/4 v11, 0x2

    .line 465
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 466
    .line 467
    .line 468
    move-result-object v11

    .line 469
    invoke-virtual {v5, v7}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    move-result v12

    .line 473
    if-eqz v12, :cond_14

    .line 474
    .line 475
    :goto_9
    move-object v5, v9

    .line 476
    goto :goto_a

    .line 477
    :cond_14
    invoke-virtual {v9, v7}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v12

    .line 481
    if-eqz v12, :cond_15

    .line 482
    .line 483
    goto :goto_a

    .line 484
    :cond_15
    invoke-virtual {v5, v11}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 485
    .line 486
    .line 487
    move-result v12

    .line 488
    if-eqz v12, :cond_16

    .line 489
    .line 490
    invoke-virtual {v9, v10}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 491
    .line 492
    .line 493
    move-result v12

    .line 494
    if-nez v12, :cond_16

    .line 495
    .line 496
    goto :goto_9

    .line 497
    :cond_16
    invoke-virtual {v9, v11}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 498
    .line 499
    .line 500
    move-result v11

    .line 501
    if-eqz v11, :cond_17

    .line 502
    .line 503
    invoke-virtual {v5, v10}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 504
    .line 505
    .line 506
    move-result v10

    .line 507
    if-nez v10, :cond_17

    .line 508
    .line 509
    goto :goto_a

    .line 510
    :cond_17
    invoke-virtual {v5, v9}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 511
    .line 512
    .line 513
    move-result v9

    .line 514
    if-eqz v9, :cond_18

    .line 515
    .line 516
    goto :goto_a

    .line 517
    :cond_18
    const/4 v5, 0x0

    .line 518
    :goto_a
    iget v8, v8, Lb0/y;->b:I

    .line 519
    .line 520
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 521
    .line 522
    .line 523
    move-result-object v8

    .line 524
    invoke-virtual {v4, v7}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 525
    .line 526
    .line 527
    move-result v9

    .line 528
    if-eqz v9, :cond_19

    .line 529
    .line 530
    move-object v4, v8

    .line 531
    goto :goto_b

    .line 532
    :cond_19
    invoke-virtual {v8, v7}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 533
    .line 534
    .line 535
    move-result v9

    .line 536
    if-eqz v9, :cond_1a

    .line 537
    .line 538
    goto :goto_b

    .line 539
    :cond_1a
    invoke-virtual {v4, v8}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 540
    .line 541
    .line 542
    move-result v8

    .line 543
    if-eqz v8, :cond_1b

    .line 544
    .line 545
    goto :goto_b

    .line 546
    :cond_1b
    const/4 v4, 0x0

    .line 547
    :goto_b
    if-eqz v5, :cond_1d

    .line 548
    .line 549
    if-nez v4, :cond_1c

    .line 550
    .line 551
    goto :goto_c

    .line 552
    :cond_1c
    add-int/lit8 v6, v6, 0x1

    .line 553
    .line 554
    goto :goto_8

    .line 555
    :cond_1d
    :goto_c
    const/4 v11, 0x0

    .line 556
    goto :goto_d

    .line 557
    :cond_1e
    new-instance v11, Lb0/y;

    .line 558
    .line 559
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 560
    .line 561
    .line 562
    move-result v3

    .line 563
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 564
    .line 565
    .line 566
    move-result v4

    .line 567
    invoke-direct {v11, v3, v4}, Lb0/y;-><init>(II)V

    .line 568
    .line 569
    .line 570
    :goto_d
    if-eqz v11, :cond_24

    .line 571
    .line 572
    sget-object v3, Lh0/z0;->E0:Lh0/g;

    .line 573
    .line 574
    invoke-virtual {v0, v3, v11}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 575
    .line 576
    .line 577
    sget-object v3, Lh0/o2;->V0:Lh0/g;

    .line 578
    .line 579
    sget-object v4, Lh0/k;->h:Landroid/util/Range;

    .line 580
    .line 581
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 582
    .line 583
    .line 584
    move-result-object v2

    .line 585
    :goto_e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 586
    .line 587
    .line 588
    move-result v5

    .line 589
    if-eqz v5, :cond_20

    .line 590
    .line 591
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v5

    .line 595
    check-cast v5, Lh0/o2;

    .line 596
    .line 597
    sget-object v6, Lh0/o2;->V0:Lh0/g;

    .line 598
    .line 599
    invoke-interface {v5, v6, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v5

    .line 603
    check-cast v5, Landroid/util/Range;

    .line 604
    .line 605
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    sget-object v6, Lh0/k;->h:Landroid/util/Range;

    .line 609
    .line 610
    invoke-virtual {v6, v4}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 611
    .line 612
    .line 613
    move-result v6

    .line 614
    if-eqz v6, :cond_1f

    .line 615
    .line 616
    move-object v4, v5

    .line 617
    goto :goto_e

    .line 618
    :cond_1f
    :try_start_0
    invoke-virtual {v4, v5}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 619
    .line 620
    .line 621
    move-result-object v4
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 622
    goto :goto_e

    .line 623
    :catch_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 624
    .line 625
    const-string v6, "No intersected frame rate can be found from the target frame rate settings of the UseCases! Resolved: "

    .line 626
    .line 627
    invoke-direct {v2, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 628
    .line 629
    .line 630
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 631
    .line 632
    .line 633
    const-string v6, " <<>> "

    .line 634
    .line 635
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 636
    .line 637
    .line 638
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 639
    .line 640
    .line 641
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 642
    .line 643
    .line 644
    move-result-object v2

    .line 645
    const-string v6, "VirtualCameraAdapter"

    .line 646
    .line 647
    invoke-static {v6, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 648
    .line 649
    .line 650
    invoke-virtual {v4, v5}, Landroid/util/Range;->extend(Landroid/util/Range;)Landroid/util/Range;

    .line 651
    .line 652
    .line 653
    move-result-object v4

    .line 654
    :cond_20
    invoke-virtual {v0, v3, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 655
    .line 656
    .line 657
    iget-object v2, v1, Lt0/h;->d:Ljava/util/HashSet;

    .line 658
    .line 659
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 660
    .line 661
    .line 662
    move-result-object v2

    .line 663
    :cond_21
    :goto_f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 664
    .line 665
    .line 666
    move-result v3

    .line 667
    if-eqz v3, :cond_23

    .line 668
    .line 669
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v3

    .line 673
    check-cast v3, Lb0/z1;

    .line 674
    .line 675
    iget-object v4, v1, Lt0/h;->m:Ljava/util/HashMap;

    .line 676
    .line 677
    invoke-virtual {v4, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 678
    .line 679
    .line 680
    move-result-object v3

    .line 681
    check-cast v3, Lh0/o2;

    .line 682
    .line 683
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 684
    .line 685
    .line 686
    sget-object v4, Lh0/o2;->b1:Lh0/g;

    .line 687
    .line 688
    invoke-interface {v3, v4, v7}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 689
    .line 690
    .line 691
    move-result-object v5

    .line 692
    check-cast v5, Ljava/lang/Integer;

    .line 693
    .line 694
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 695
    .line 696
    .line 697
    move-result v5

    .line 698
    if-eqz v5, :cond_22

    .line 699
    .line 700
    invoke-interface {v3, v4, v7}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    move-result-object v5

    .line 704
    check-cast v5, Ljava/lang/Integer;

    .line 705
    .line 706
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 707
    .line 708
    .line 709
    invoke-virtual {v0, v4, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 710
    .line 711
    .line 712
    :cond_22
    invoke-interface {v3}, Lh0/o2;->v()I

    .line 713
    .line 714
    .line 715
    move-result v4

    .line 716
    if-eqz v4, :cond_21

    .line 717
    .line 718
    sget-object v4, Lh0/o2;->a1:Lh0/g;

    .line 719
    .line 720
    invoke-interface {v3}, Lh0/o2;->v()I

    .line 721
    .line 722
    .line 723
    move-result v3

    .line 724
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 725
    .line 726
    .line 727
    move-result-object v3

    .line 728
    invoke-virtual {v0, v4, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 729
    .line 730
    .line 731
    goto :goto_f

    .line 732
    :cond_23
    invoke-interface/range {p2 .. p2}, Lh0/n2;->b()Lh0/o2;

    .line 733
    .line 734
    .line 735
    move-result-object v0

    .line 736
    return-object v0

    .line 737
    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 738
    .line 739
    const-string v1, "Failed to merge child dynamic ranges, can not find a dynamic range that satisfies all children."

    .line 740
    .line 741
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    throw v0
.end method

.method public final u()V
    .locals 1

    .line 1
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 2
    .line 3
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lb0/z1;

    .line 20
    .line 21
    invoke-virtual {v0}, Lb0/z1;->u()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public final v()V
    .locals 1

    .line 1
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 2
    .line 3
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lb0/z1;

    .line 20
    .line 21
    invoke-virtual {v0}, Lb0/z1;->v()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public final w(Lh0/q0;)Lh0/k;
    .locals 3

    .line 1
    iget-object v0, p0, Lt0/e;->z:Lh0/v1;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lh0/v1;->a(Lh0/q0;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lt0/e;->z:Lh0/v1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    aget-object v0, v0, v2

    .line 24
    .line 25
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lb0/z1;->h:Lh0/k;

    .line 39
    .line 40
    invoke-virtual {p0}, Lh0/k;->b()Lss/b;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iput-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {p0}, Lss/b;->c()Lh0/k;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public final x(Lh0/k;Lh0/k;)Lh0/k;
    .locals 8

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onSuggestedStreamSpecUpdated: primaryStreamSpec = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, ", secondaryStreamSpec "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "StreamSharing"

    .line 24
    .line 25
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lb0/z1;->e()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {p0}, Lb0/z1;->i()Lh0/b0;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    :goto_0
    move-object v4, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    invoke-virtual {p0}, Lb0/z1;->i()Lh0/b0;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-interface {v0}, Lh0/z;->f()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    goto :goto_0

    .line 54
    :goto_1
    iget-object v5, p0, Lb0/z1;->g:Lh0/o2;

    .line 55
    .line 56
    move-object v2, p0

    .line 57
    move-object v6, p1

    .line 58
    move-object v7, p2

    .line 59
    invoke-virtual/range {v2 .. v7}, Lt0/e;->E(Ljava/lang/String;Ljava/lang/String;Lh0/o2;Lh0/k;Lh0/k;)Ljava/util/List;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {v2, p0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Lb0/z1;->o()V

    .line 67
    .line 68
    .line 69
    return-object v6
.end method

.method public final y()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lt0/e;->D()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lt0/e;->q:Lt0/h;

    .line 5
    .line 6
    iget-object v0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lb0/z1;

    .line 23
    .line 24
    iget-object v2, p0, Lt0/h;->f:Ljava/util/HashMap;

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Lt0/g;

    .line 31
    .line 32
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, v2}, Lb0/z1;->B(Lh0/b0;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    return-void
.end method
