.class public abstract Lkp/j7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ly6/q;Lf7/c;Lt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x74c75949

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    goto :goto_4

    .line 48
    :cond_3
    :goto_2
    sget-object v0, Lf7/d;->d:Lf7/d;

    .line 49
    .line 50
    const v1, 0x227c4e56

    .line 51
    .line 52
    .line 53
    invoke-virtual {p3, v1}, Ll2/t;->Z(I)V

    .line 54
    .line 55
    .line 56
    const v1, -0x20ad3f64

    .line 57
    .line 58
    .line 59
    invoke-virtual {p3, v1}, Ll2/t;->Z(I)V

    .line 60
    .line 61
    .line 62
    iget-object v1, p3, Ll2/t;->a:Leb/j0;

    .line 63
    .line 64
    instance-of v1, v1, Ly6/b;

    .line 65
    .line 66
    if-eqz v1, :cond_6

    .line 67
    .line 68
    invoke-virtual {p3}, Ll2/t;->W()V

    .line 69
    .line 70
    .line 71
    iget-boolean v1, p3, Ll2/t;->S:Z

    .line 72
    .line 73
    if-eqz v1, :cond_4

    .line 74
    .line 75
    invoke-virtual {p3, v0}, Ll2/t;->l(Lay0/a;)V

    .line 76
    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 80
    .line 81
    .line 82
    :goto_3
    sget-object v0, Lf7/e;->g:Lf7/e;

    .line 83
    .line 84
    invoke-static {v0, p0, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 85
    .line 86
    .line 87
    sget-object v0, Lf7/e;->h:Lf7/e;

    .line 88
    .line 89
    invoke-static {v0, p1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 90
    .line 91
    .line 92
    const/4 v0, 0x6

    .line 93
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-virtual {p2, p3, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    const/4 v0, 0x1

    .line 101
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 109
    .line 110
    .line 111
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 112
    .line 113
    .line 114
    move-result-object p3

    .line 115
    if-eqz p3, :cond_5

    .line 116
    .line 117
    new-instance v0, Lf7/f;

    .line 118
    .line 119
    const/4 v2, 0x0

    .line 120
    move-object v3, p0

    .line 121
    move-object v4, p1

    .line 122
    move-object v5, p2

    .line 123
    move v1, p4

    .line 124
    invoke-direct/range {v0 .. v5}, Lf7/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 128
    .line 129
    :cond_5
    return-void

    .line 130
    :cond_6
    invoke-static {}, Ll2/b;->l()V

    .line 131
    .line 132
    .line 133
    const/4 p0, 0x0

    .line 134
    throw p0
.end method

.method public static b(Landroid/content/Context;)Ls6/p;
    .locals 12

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "Package manager required to locate emoji font provider"

    .line 6
    .line 7
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Landroid/content/Intent;

    .line 11
    .line 12
    const-string v2, "androidx.content.action.LOAD_EMOJI_FONT"

    .line 13
    .line 14
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->queryIntentContentProviders(Landroid/content/Intent;I)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    const/4 v4, 0x0

    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    check-cast v3, Landroid/content/pm/ResolveInfo;

    .line 38
    .line 39
    iget-object v3, v3, Landroid/content/pm/ResolveInfo;->providerInfo:Landroid/content/pm/ProviderInfo;

    .line 40
    .line 41
    if-eqz v3, :cond_0

    .line 42
    .line 43
    iget-object v5, v3, Landroid/content/pm/ProviderInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 44
    .line 45
    if-eqz v5, :cond_0

    .line 46
    .line 47
    iget v5, v5, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 48
    .line 49
    const/4 v6, 0x1

    .line 50
    and-int/2addr v5, v6

    .line 51
    if-ne v5, v6, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    move-object v3, v4

    .line 55
    :goto_0
    if-nez v3, :cond_2

    .line 56
    .line 57
    :goto_1
    move-object v5, v4

    .line 58
    goto :goto_3

    .line 59
    :cond_2
    :try_start_0
    iget-object v6, v3, Landroid/content/pm/ProviderInfo;->authority:Ljava/lang/String;

    .line 60
    .line 61
    iget-object v7, v3, Landroid/content/pm/ProviderInfo;->packageName:Ljava/lang/String;

    .line 62
    .line 63
    const/16 v1, 0x40

    .line 64
    .line 65
    invoke-virtual {v0, v7, v1}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 70
    .line 71
    new-instance v1, Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 74
    .line 75
    .line 76
    array-length v3, v0

    .line 77
    :goto_2
    if-ge v2, v3, :cond_3

    .line 78
    .line 79
    aget-object v5, v0, v2

    .line 80
    .line 81
    invoke-virtual {v5}, Landroid/content/pm/Signature;->toByteArray()[B

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    add-int/lit8 v2, v2, 0x1

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_3
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 92
    .line 93
    .line 94
    move-result-object v11

    .line 95
    new-instance v5, Lz5/c;

    .line 96
    .line 97
    const-string v8, "emojicompat-emoji-font"

    .line 98
    .line 99
    const/4 v9, 0x0

    .line 100
    const/4 v10, 0x0

    .line 101
    invoke-direct/range {v5 .. v11}, Lz5/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :catch_0
    move-exception v0

    .line 106
    const-string v1, "emoji2.text.DefaultEmojiConfig"

    .line 107
    .line 108
    invoke-static {v1, v0}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :goto_3
    if-nez v5, :cond_4

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_4
    new-instance v4, Ls6/p;

    .line 116
    .line 117
    new-instance v0, Ls6/o;

    .line 118
    .line 119
    invoke-direct {v0, p0, v5}, Ls6/o;-><init>(Landroid/content/Context;Lz5/c;)V

    .line 120
    .line 121
    .line 122
    invoke-direct {v4, v0}, Lka/u;-><init>(Ls6/g;)V

    .line 123
    .line 124
    .line 125
    :goto_4
    return-object v4
.end method
