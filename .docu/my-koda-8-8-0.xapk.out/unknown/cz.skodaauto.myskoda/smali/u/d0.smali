.class public final Lu/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/d1;


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/util/HashMap;

.field public final c:Lmb/e;

.field public final d:Lv/d;

.field public final e:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/Object;Ljava/util/LinkedHashSet;)V
    .locals 3

    .line 1
    new-instance v0, Lmb/e;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lmb/e;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lu/d0;->a:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v1, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v1, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 24
    .line 25
    iput-object v0, p0, Lu/d0;->c:Lmb/e;

    .line 26
    .line 27
    iput-object p1, p0, Lu/d0;->e:Landroid/content/Context;

    .line 28
    .line 29
    instance-of v0, p2, Lv/d;

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    check-cast p2, Lv/d;

    .line 34
    .line 35
    iput-object p2, p0, Lu/d0;->d:Lv/d;

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    invoke-static {}, Li0/d;->c()Landroid/os/Handler;

    .line 39
    .line 40
    .line 41
    new-instance p2, Lv/d;

    .line 42
    .line 43
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 44
    .line 45
    const/16 v1, 0x1e

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    if-lt v0, v1, :cond_1

    .line 49
    .line 50
    new-instance v0, Lv/f;

    .line 51
    .line 52
    invoke-direct {v0, p1, v2}, Lh/w;-><init>(Landroid/content/Context;Llp/ta;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    new-instance v0, Lv/e;

    .line 57
    .line 58
    invoke-direct {v0, p1, v2}, Lh/w;-><init>(Landroid/content/Context;Llp/ta;)V

    .line 59
    .line 60
    .line 61
    :goto_0
    invoke-direct {p2, v0}, Lv/d;-><init>(Lv/e;)V

    .line 62
    .line 63
    .line 64
    iput-object p2, p0, Lu/d0;->d:Lv/d;

    .line 65
    .line 66
    :goto_1
    :try_start_0
    new-instance p1, Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-direct {p1, p3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0, p1}, Lu/d0;->a(Ljava/util/List;)V
    :try_end_0
    .catch Lh0/l0; {:try_start_0 .. :try_end_0} :catch_0

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :catch_0
    move-exception p0

    .line 76
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    instance-of p1, p1, Lb0/s;

    .line 81
    .line 82
    if-eqz p1, :cond_2

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    check-cast p0, Lb0/s;

    .line 89
    .line 90
    throw p0

    .line 91
    :cond_2
    new-instance p1, Lb0/s;

    .line 92
    .line 93
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 94
    .line 95
    .line 96
    throw p1
.end method


# virtual methods
.method public final a(Ljava/util/List;)V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lu/d0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    new-instance v2, Ljava/util/HashSet;

    .line 10
    .line 11
    invoke-direct {v2, p1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 12
    .line 13
    .line 14
    iget-object v3, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-interface {v2, v3}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 21
    .line 22
    .line 23
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 24
    :try_start_1
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Lu/d0;->b(Ljava/lang/String;)Lu/c1;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Lb0/s; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    iget-object v1, p0, Lu/d0;->a:Ljava/lang/Object;

    .line 49
    .line 50
    monitor-enter v1

    .line 51
    :try_start_2
    new-instance v2, Ljava/util/HashMap;

    .line 52
    .line 53
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 54
    .line 55
    .line 56
    check-cast p1, Ljava/util/ArrayList;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-eqz v3, :cond_2

    .line 67
    .line 68
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    check-cast v3, Ljava/lang/String;

    .line 73
    .line 74
    iget-object v4, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 75
    .line 76
    invoke-virtual {v4, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_1

    .line 81
    .line 82
    iget-object v4, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 83
    .line 84
    invoke-virtual {v4, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    check-cast v4, Lu/c1;

    .line 89
    .line 90
    invoke-virtual {v2, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    goto :goto_2

    .line 96
    :cond_1
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    check-cast v4, Lu/c1;

    .line 101
    .line 102
    invoke-virtual {v2, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_2
    iget-object p1, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 107
    .line 108
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 109
    .line 110
    .line 111
    iget-object p0, p0, Lu/d0;->b:Ljava/util/HashMap;

    .line 112
    .line 113
    invoke-virtual {p0, v2}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 114
    .line 115
    .line 116
    monitor-exit v1

    .line 117
    return-void

    .line 118
    :goto_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 119
    throw p0

    .line 120
    :catch_0
    move-exception p0

    .line 121
    new-instance p1, Lh0/l0;

    .line 122
    .line 123
    const-string v0, "Failed to create SupportedSurfaceCombination"

    .line 124
    .line 125
    invoke-direct {p1, v0, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 126
    .line 127
    .line 128
    throw p1

    .line 129
    :catchall_1
    move-exception p0

    .line 130
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 131
    throw p0
.end method

.method public final b(Ljava/lang/String;)Lu/c1;
    .locals 7

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x23

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    new-instance v0, Lt/e;

    .line 8
    .line 9
    iget-object v1, p0, Lu/d0;->e:Landroid/content/Context;

    .line 10
    .line 11
    iget-object v2, p0, Lu/d0;->d:Lv/d;

    .line 12
    .line 13
    invoke-direct {v0, v1, p1, v2}, Lt/e;-><init>(Landroid/content/Context;Ljava/lang/String;Lv/d;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    move-object v6, v0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    sget-object v0, Ld0/b;->u0:Lfv/b;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :goto_1
    new-instance v1, Lu/c1;

    .line 22
    .line 23
    iget-object v4, p0, Lu/d0;->d:Lv/d;

    .line 24
    .line 25
    iget-object v5, p0, Lu/d0;->c:Lmb/e;

    .line 26
    .line 27
    iget-object v2, p0, Lu/d0;->e:Landroid/content/Context;

    .line 28
    .line 29
    move-object v3, p1

    .line 30
    invoke-direct/range {v1 .. v6}, Lu/c1;-><init>(Landroid/content/Context;Ljava/lang/String;Lv/d;Lu/e;Ld0/b;)V

    .line 31
    .line 32
    .line 33
    return-object v1
.end method
