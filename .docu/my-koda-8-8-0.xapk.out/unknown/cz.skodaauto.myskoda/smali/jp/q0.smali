.class public abstract Ljp/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lz9/k;Lu2/c;Lt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0xdf2283d

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p4

    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    and-int/lit16 v0, v0, 0x93

    .line 32
    .line 33
    const/16 v1, 0x92

    .line 34
    .line 35
    if-ne v0, v1, :cond_3

    .line 36
    .line 37
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_3
    :goto_2
    sget-object v0, Lq7/a;->a:Ll2/e0;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v1, Ln7/c;->a:Ll2/s1;

    .line 55
    .line 56
    invoke-virtual {v1, p0}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    sget-object v2, Lsa/a;->a:Ll2/s1;

    .line 61
    .line 62
    invoke-virtual {v2, p0}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    filled-new-array {v0, v1, v2}, [Ll2/t1;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    new-instance v1, Laa/p;

    .line 71
    .line 72
    const/4 v2, 0x1

    .line 73
    invoke-direct {v1, v2, p1, p2}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    const v2, 0x6bd29b7d

    .line 77
    .line 78
    .line 79
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    const/16 v2, 0x38

    .line 84
    .line 85
    invoke-static {v0, v1, p3, v2}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 86
    .line 87
    .line 88
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    if-eqz p3, :cond_4

    .line 93
    .line 94
    new-instance v0, Laa/w;

    .line 95
    .line 96
    const/4 v2, 0x0

    .line 97
    move-object v3, p0

    .line 98
    move-object v4, p1

    .line 99
    move-object v5, p2

    .line 100
    move v1, p4

    .line 101
    invoke-direct/range {v0 .. v5}, Laa/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 105
    .line 106
    :cond_4
    return-void
.end method

.method public static final b(Lu2/c;Lt2/b;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v5, p2

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p2, 0x31a55716

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p2, 0x2

    .line 19
    :goto_0
    or-int/2addr p2, p3

    .line 20
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    const/16 v0, 0x20

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/16 v0, 0x10

    .line 30
    .line 31
    :goto_1
    or-int/2addr p2, v0

    .line 32
    and-int/lit8 v0, p2, 0x13

    .line 33
    .line 34
    const/16 v1, 0x12

    .line 35
    .line 36
    if-ne v0, v1, :cond_3

    .line 37
    .line 38
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-nez v0, :cond_2

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 46
    .line 47
    .line 48
    goto :goto_5

    .line 49
    :cond_3
    :goto_2
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 54
    .line 55
    if-ne v0, v1, :cond_4

    .line 56
    .line 57
    new-instance v0, La00/a;

    .line 58
    .line 59
    const/4 v1, 0x6

    .line 60
    invoke-direct {v0, v1}, La00/a;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v5, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_4
    check-cast v0, Lay0/k;

    .line 67
    .line 68
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    if-eqz v1, :cond_7

    .line 73
    .line 74
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 75
    .line 76
    const-class v3, Laa/a;

    .line 77
    .line 78
    move-object v4, v0

    .line 79
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    new-instance v6, Lfb/k;

    .line 84
    .line 85
    const/4 v7, 0x4

    .line 86
    invoke-direct {v6, v7}, Lfb/k;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-virtual {v6, v2, v4}, Lfb/k;->b(Lhy0/d;Lay0/k;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v6}, Lfb/k;->d()Lp7/d;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    instance-of v2, v1, Landroidx/lifecycle/k;

    .line 101
    .line 102
    if-eqz v2, :cond_5

    .line 103
    .line 104
    move-object v2, v1

    .line 105
    check-cast v2, Landroidx/lifecycle/k;

    .line 106
    .line 107
    invoke-interface {v2}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    :goto_3
    move-object v4, v2

    .line 112
    goto :goto_4

    .line 113
    :cond_5
    sget-object v2, Lp7/a;->b:Lp7/a;

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :goto_4
    const/4 v2, 0x0

    .line 117
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    check-cast v0, Laa/a;

    .line 122
    .line 123
    new-instance v1, La0/j;

    .line 124
    .line 125
    invoke-direct {v1, p0}, La0/j;-><init>(Lu2/c;)V

    .line 126
    .line 127
    .line 128
    iput-object v1, v0, Laa/a;->e:La0/j;

    .line 129
    .line 130
    iget-object v0, v0, Laa/a;->d:Ljava/lang/String;

    .line 131
    .line 132
    and-int/lit8 v1, p2, 0x70

    .line 133
    .line 134
    shl-int/lit8 p2, p2, 0x6

    .line 135
    .line 136
    and-int/lit16 p2, p2, 0x380

    .line 137
    .line 138
    or-int/2addr p2, v1

    .line 139
    invoke-interface {p0, v0, p1, v5, p2}, Lu2/c;->b(Ljava/lang/Object;Lt2/b;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    :goto_5
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    if-eqz p2, :cond_6

    .line 147
    .line 148
    new-instance v0, Laa/m;

    .line 149
    .line 150
    const/4 v1, 0x1

    .line 151
    invoke-direct {v0, p3, v1, p0, p1}, Laa/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 155
    .line 156
    :cond_6
    return-void

    .line 157
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 158
    .line 159
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 160
    .line 161
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p0
.end method

.method public static c(Lca/d;I)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const v0, 0xffffff

    .line 7
    .line 8
    .line 9
    if-gt p1, v0, :cond_0

    .line 10
    .line 11
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    :try_start_0
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 17
    .line 18
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :catch_0
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public static d(Lz9/u;)Lky0/j;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lz70/e0;

    .line 7
    .line 8
    const/4 v1, 0x7

    .line 9
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final e(Ll70/w;)F
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const p0, 0x3f333333    # 0.7f

    .line 19
    .line 20
    .line 21
    return p0

    .line 22
    :cond_0
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    const p0, 0x3ea8f5c3    # 0.33f

    .line 29
    .line 30
    .line 31
    return p0
.end method

.method public static final f(Ll70/w;Ljava/util/Locale;I)Ljava/util/ArrayList;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/16 v0, 0xa

    .line 11
    .line 12
    if-eqz p0, :cond_4

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-eq p0, v1, :cond_2

    .line 16
    .line 17
    const/4 p2, 0x2

    .line 18
    if-ne p0, p2, :cond_1

    .line 19
    .line 20
    sget-object p0, Lm70/h1;->b:Lsx0/b;

    .line 21
    .line 22
    new-instance p2, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-direct {p2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Landroidx/collection/d1;

    .line 32
    .line 33
    const/4 v1, 0x6

    .line 34
    invoke-direct {v0, p0, v1}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 35
    .line 36
    .line 37
    :goto_0
    invoke-virtual {v0}, Landroidx/collection/d1;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_0

    .line 42
    .line 43
    invoke-virtual {v0}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Ljava/time/Month;

    .line 48
    .line 49
    sget-object v1, Ljava/time/format/TextStyle;->NARROW:Ljava/time/format/TextStyle;

    .line 50
    .line 51
    invoke-virtual {p0, v1, p1}, Ljava/time/Month;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    return-object p2

    .line 60
    :cond_1
    new-instance p0, La8/r0;

    .line 61
    .line 62
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    const/high16 p0, 0x40800000    # 4.0f

    .line 67
    .line 68
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    int-to-float p1, p2

    .line 73
    const p2, 0x3ecccccd    # 0.4f

    .line 74
    .line 75
    .line 76
    mul-float/2addr p2, p1

    .line 77
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    const v1, 0x3f28f5c3    # 0.66f

    .line 82
    .line 83
    .line 84
    mul-float/2addr v1, p1

    .line 85
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    const v2, 0x3f6b851f    # 0.92f

    .line 90
    .line 91
    .line 92
    mul-float/2addr p1, v2

    .line 93
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    filled-new-array {p0, p2, v1, p1}, [Ljava/lang/Float;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Ljava/lang/Iterable;

    .line 106
    .line 107
    new-instance p1, Ljava/util/ArrayList;

    .line 108
    .line 109
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 114
    .line 115
    .line 116
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 121
    .line 122
    .line 123
    move-result p2

    .line 124
    if-eqz p2, :cond_3

    .line 125
    .line 126
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p2

    .line 130
    check-cast p2, Ljava/lang/Number;

    .line 131
    .line 132
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 133
    .line 134
    .line 135
    move-result p2

    .line 136
    float-to-int p2, p2

    .line 137
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_3
    return-object p1

    .line 146
    :cond_4
    sget-object p0, Lm70/h1;->a:Lsx0/b;

    .line 147
    .line 148
    new-instance p2, Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    invoke-direct {p2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 155
    .line 156
    .line 157
    new-instance v0, Landroidx/collection/d1;

    .line 158
    .line 159
    const/4 v1, 0x6

    .line 160
    invoke-direct {v0, p0, v1}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 161
    .line 162
    .line 163
    :goto_2
    invoke-virtual {v0}, Landroidx/collection/d1;->hasNext()Z

    .line 164
    .line 165
    .line 166
    move-result p0

    .line 167
    if-eqz p0, :cond_5

    .line 168
    .line 169
    invoke-virtual {v0}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    check-cast p0, Ljava/time/DayOfWeek;

    .line 174
    .line 175
    sget-object v1, Ljava/time/format/TextStyle;->SHORT:Ljava/time/format/TextStyle;

    .line 176
    .line 177
    invoke-virtual {p0, v1, p1}, Ljava/time/DayOfWeek;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_5
    return-object p2
.end method
