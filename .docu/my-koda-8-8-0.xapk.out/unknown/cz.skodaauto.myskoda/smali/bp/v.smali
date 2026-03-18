.class public final Lbp/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static b:Ljava/lang/ref/WeakReference;


# instance fields
.field public final a:Lbp/u;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 7

    .line 1
    new-instance v0, Lbp/q;

    .line 2
    .line 3
    sget-object v3, Lbp/w;->z:Lc2/k;

    .line 4
    .line 5
    sget-object v4, Lko/b;->a:Lko/a;

    .line 6
    .line 7
    sget-object v5, Lko/h;->c:Lko/h;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    move-object v1, p1

    .line 11
    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Lbp/f;->b:Lbp/d;

    .line 15
    .line 16
    if-nez p1, :cond_8

    .line 17
    .line 18
    sget-object p1, Lbp/f;->a:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object v2, Lbp/f;->b:Lbp/d;

    .line 22
    .line 23
    if-nez v2, :cond_7

    .line 24
    .line 25
    monitor-enter p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 26
    :try_start_1
    sget-object v2, Lbp/f;->b:Lbp/d;

    .line 27
    .line 28
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move-object v1, v3

    .line 35
    :cond_0
    if-eqz v2, :cond_1

    .line 36
    .line 37
    iget-object v2, v2, Lbp/d;->a:Landroid/content/Context;

    .line 38
    .line 39
    if-eq v2, v1, :cond_2

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception v0

    .line 43
    move-object p0, v0

    .line 44
    goto/16 :goto_3

    .line 45
    .line 46
    :cond_1
    :goto_0
    sget-object v2, Lbp/e;->a:Landroidx/collection/f;

    .line 47
    .line 48
    const-class v2, Lbp/e;

    .line 49
    .line 50
    monitor-enter v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    :try_start_2
    sget-object v3, Lbp/e;->a:Landroidx/collection/f;

    .line 52
    .line 53
    invoke-interface {v3}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    const/4 v6, 0x0

    .line 66
    if-nez v5, :cond_5

    .line 67
    .line 68
    invoke-interface {v3}, Ljava/util/Map;->clear()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 69
    .line 70
    .line 71
    :try_start_3
    monitor-exit v2

    .line 72
    sget-object v2, Lbp/g;->a:Landroidx/collection/f;

    .line 73
    .line 74
    const-class v2, Lbp/g;

    .line 75
    .line 76
    monitor-enter v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 77
    :try_start_4
    sget-object v3, Lbp/g;->a:Landroidx/collection/f;

    .line 78
    .line 79
    invoke-interface {v3}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    if-nez v5, :cond_3

    .line 92
    .line 93
    invoke-interface {v3}, Ljava/util/Map;->clear()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 94
    .line 95
    .line 96
    :try_start_5
    monitor-exit v2

    .line 97
    new-instance v2, Lpy/a;

    .line 98
    .line 99
    const/4 v3, 0x2

    .line 100
    invoke-direct {v2, v3}, Lpy/a;-><init>(I)V

    .line 101
    .line 102
    .line 103
    new-instance v3, Lbp/i;

    .line 104
    .line 105
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    iput-object v2, v3, Lbp/i;->a:Lpy/a;

    .line 109
    .line 110
    new-instance v2, Lbp/d;

    .line 111
    .line 112
    invoke-direct {v2, v1, v3}, Lbp/d;-><init>(Landroid/content/Context;Lbp/i;)V

    .line 113
    .line 114
    .line 115
    sput-object v2, Lbp/f;->b:Lbp/d;

    .line 116
    .line 117
    sget-object v1, Lbp/f;->c:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 118
    .line 119
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 120
    .line 121
    .line 122
    :cond_2
    monitor-exit p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 123
    goto :goto_4

    .line 124
    :catchall_1
    move-exception v0

    .line 125
    move-object p0, v0

    .line 126
    goto :goto_1

    .line 127
    :cond_3
    :try_start_6
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    if-nez p0, :cond_4

    .line 132
    .line 133
    throw v6

    .line 134
    :cond_4
    new-instance p0, Ljava/lang/ClassCastException;

    .line 135
    .line 136
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :goto_1
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 141
    :try_start_7
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 142
    :catchall_2
    move-exception v0

    .line 143
    move-object p0, v0

    .line 144
    goto :goto_2

    .line 145
    :cond_5
    :try_start_8
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    if-nez p0, :cond_6

    .line 150
    .line 151
    throw v6

    .line 152
    :cond_6
    new-instance p0, Ljava/lang/ClassCastException;

    .line 153
    .line 154
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 155
    .line 156
    .line 157
    throw p0

    .line 158
    :goto_2
    monitor-exit v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 159
    :try_start_9
    throw p0

    .line 160
    :goto_3
    monitor-exit p1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 161
    :try_start_a
    throw p0

    .line 162
    :catchall_3
    move-exception v0

    .line 163
    move-object p0, v0

    .line 164
    goto :goto_5

    .line 165
    :cond_7
    :goto_4
    monitor-exit p1

    .line 166
    goto :goto_6

    .line 167
    :goto_5
    monitor-exit p1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 168
    throw p0

    .line 169
    :cond_8
    :goto_6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 170
    .line 171
    .line 172
    new-instance p1, Lbp/u;

    .line 173
    .line 174
    invoke-direct {p1, v0}, Lbp/u;-><init>(Lbp/q;)V

    .line 175
    .line 176
    .line 177
    iput-object p1, p0, Lbp/v;->a:Lbp/u;

    .line 178
    .line 179
    return-void
.end method
