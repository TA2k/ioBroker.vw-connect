.class public final Lcu/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Ltr/c;

.field public final c:Ljava/util/concurrent/Executor;

.field public final d:Ldu/c;

.field public final e:Ldu/c;

.field public final f:Ldu/c;

.field public final g:Ldu/i;

.field public final h:Ldu/j;

.field public final i:Ldu/n;

.field public final j:Lvp/y1;

.field public final k:Lcom/google/firebase/messaging/w;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltr/c;Ljava/util/concurrent/Executor;Ldu/c;Ldu/c;Ldu/c;Ldu/i;Ldu/j;Ldu/n;Lvp/y1;Lcom/google/firebase/messaging/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcu/b;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lcu/b;->b:Ltr/c;

    .line 7
    .line 8
    iput-object p3, p0, Lcu/b;->c:Ljava/util/concurrent/Executor;

    .line 9
    .line 10
    iput-object p4, p0, Lcu/b;->d:Ldu/c;

    .line 11
    .line 12
    iput-object p5, p0, Lcu/b;->e:Ldu/c;

    .line 13
    .line 14
    iput-object p6, p0, Lcu/b;->f:Ldu/c;

    .line 15
    .line 16
    iput-object p7, p0, Lcu/b;->g:Ldu/i;

    .line 17
    .line 18
    iput-object p8, p0, Lcu/b;->h:Ldu/j;

    .line 19
    .line 20
    iput-object p9, p0, Lcu/b;->i:Ldu/n;

    .line 21
    .line 22
    iput-object p10, p0, Lcu/b;->j:Lvp/y1;

    .line 23
    .line 24
    iput-object p11, p0, Lcu/b;->k:Lcom/google/firebase/messaging/w;

    .line 25
    .line 26
    return-void
.end method

.method public static e(Lorg/json/JSONArray;)Ljava/util/ArrayList;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    invoke-virtual {p0}, Lorg/json/JSONArray;->length()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-ge v1, v2, :cond_1

    .line 12
    .line 13
    new-instance v2, Ljava/util/HashMap;

    .line 14
    .line 15
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-virtual {v3}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_0

    .line 31
    .line 32
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    check-cast v5, Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    invoke-virtual {v2, v5, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_0
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    return-object v0
.end method


# virtual methods
.method public final a()Ljava/util/HashMap;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcu/b;->h:Ldu/j;

    .line 7
    .line 8
    iget-object v1, p0, Ldu/j;->c:Ldu/c;

    .line 9
    .line 10
    invoke-static {v1}, Ldu/j;->a(Ldu/c;)Ljava/util/HashSet;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-interface {v0, v1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Ldu/j;->d:Ldu/c;

    .line 18
    .line 19
    invoke-static {v1}, Ldu/j;->a(Ldu/c;)Ljava/util/HashSet;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {v0, v1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 24
    .line 25
    .line 26
    new-instance v1, Ljava/util/HashMap;

    .line 27
    .line 28
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Ldu/j;->b(Ljava/lang/String;)Ldu/p;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v1, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    return-object v1
.end method

.method public final b()Lc1/l2;
    .locals 9

    .line 1
    iget-object p0, p0, Lcu/b;->i:Ldu/n;

    .line 2
    .line 3
    iget-object v0, p0, Ldu/n;->b:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 7
    .line 8
    const-string v2, "last_fetch_time_in_millis"

    .line 9
    .line 10
    const-wide/16 v3, -0x1

    .line 11
    .line 12
    invoke-interface {v1, v2, v3, v4}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 16
    .line 17
    const-string v2, "last_fetch_status"

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    sget-wide v2, Ldu/i;->i:J

    .line 25
    .line 26
    iget-object v4, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 27
    .line 28
    const-string v5, "fetch_timeout_in_seconds"

    .line 29
    .line 30
    const-wide/16 v6, 0x3c

    .line 31
    .line 32
    invoke-interface {v4, v5, v6, v7}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 33
    .line 34
    .line 35
    move-result-wide v4

    .line 36
    const-wide/16 v6, 0x0

    .line 37
    .line 38
    cmp-long v8, v4, v6

    .line 39
    .line 40
    if-ltz v8, :cond_1

    .line 41
    .line 42
    iget-object p0, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 43
    .line 44
    const-string v4, "minimum_fetch_interval_in_seconds"

    .line 45
    .line 46
    invoke-interface {p0, v4, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 47
    .line 48
    .line 49
    move-result-wide v2

    .line 50
    cmp-long p0, v2, v6

    .line 51
    .line 52
    if-ltz p0, :cond_0

    .line 53
    .line 54
    new-instance p0, Lc1/l2;

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    invoke-direct {p0, v1, v2}, Lc1/l2;-><init>(II)V

    .line 58
    .line 59
    .line 60
    monitor-exit v0

    .line 61
    return-object p0

    .line 62
    :catchall_0
    move-exception p0

    .line 63
    goto :goto_0

    .line 64
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    new-instance v1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    const-string v4, "Minimum interval between fetches has to be a non-negative number. "

    .line 69
    .line 70
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v2, " is an invalid argument"

    .line 77
    .line 78
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 90
    .line 91
    const-string v1, "Fetch connection timeout has to be a non-negative number. %d is an invalid argument"

    .line 92
    .line 93
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    invoke-static {v1, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0

    .line 109
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 110
    throw p0
.end method

.method public final c(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Lcu/b;->j:Lvp/y1;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v0, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Ldu/l;

    .line 7
    .line 8
    iget-object v1, v0, Ldu/l;->r:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 11
    :try_start_1
    iput-boolean p1, v0, Ldu/l;->e:Z

    .line 12
    .line 13
    iget-object v2, v0, Ldu/l;->g:Lc8/f;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iput-boolean p1, v2, Lc8/f;->a:Z

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p1

    .line 21
    goto :goto_4

    .line 22
    :cond_0
    :goto_0
    if-eqz p1, :cond_1

    .line 23
    .line 24
    iget-object v0, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 29
    .line 30
    .line 31
    :cond_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    if-nez p1, :cond_3

    .line 33
    .line 34
    :try_start_2
    monitor-enter p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 35
    :try_start_3
    iget-object p1, p0, Lvp/y1;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Ljava/util/LinkedHashSet;

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Set;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-nez p1, :cond_2

    .line 44
    .line 45
    iget-object p1, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p1, Ldu/l;

    .line 48
    .line 49
    const-wide/16 v0, 0x0

    .line 50
    .line 51
    invoke-virtual {p1, v0, v1}, Ldu/l;->e(J)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :catchall_1
    move-exception p1

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    :goto_1
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 58
    goto :goto_3

    .line 59
    :goto_2
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 60
    :try_start_6
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 61
    :cond_3
    :goto_3
    monitor-exit p0

    .line 62
    return-void

    .line 63
    :goto_4
    :try_start_7
    monitor-exit v1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 64
    :try_start_8
    throw p1

    .line 65
    :goto_5
    monitor-exit p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 66
    throw p1

    .line 67
    :catchall_2
    move-exception p1

    .line 68
    goto :goto_5
.end method

.method public final d()Laq/t;
    .locals 9

    .line 1
    iget-object v0, p0, Lcu/b;->a:Landroid/content/Context;

    .line 2
    .line 3
    const-string v1, "FirebaseRemoteConfig"

    .line 4
    .line 5
    new-instance v2, Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    :try_start_0
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    const-string v0, "Could not find the resources of the current context while trying to set defaults from an XML."

    .line 18
    .line 19
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    goto/16 :goto_5

    .line 23
    .line 24
    :catch_0
    move-exception v0

    .line 25
    goto/16 :goto_4

    .line 26
    .line 27
    :cond_0
    const v4, 0x7f15000b

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v4}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    move-object v5, v3

    .line 39
    move-object v6, v5

    .line 40
    move-object v7, v6

    .line 41
    :goto_0
    const/4 v8, 0x1

    .line 42
    if-eq v4, v8, :cond_9

    .line 43
    .line 44
    const/4 v8, 0x2

    .line 45
    if-ne v4, v8, :cond_1

    .line 46
    .line 47
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    goto :goto_3

    .line 52
    :cond_1
    const/4 v8, 0x3

    .line 53
    if-ne v4, v8, :cond_4

    .line 54
    .line 55
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    const-string v5, "entry"

    .line 60
    .line 61
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_3

    .line 66
    .line 67
    if-eqz v6, :cond_2

    .line 68
    .line 69
    if-eqz v7, :cond_2

    .line 70
    .line 71
    invoke-virtual {v2, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    const-string v4, "An entry in the defaults XML has an invalid key and/or value tag."

    .line 76
    .line 77
    invoke-static {v1, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 78
    .line 79
    .line 80
    :goto_1
    move-object v6, v3

    .line 81
    move-object v7, v6

    .line 82
    :cond_3
    move-object v5, v3

    .line 83
    goto :goto_3

    .line 84
    :cond_4
    const/4 v8, 0x4

    .line 85
    if-ne v4, v8, :cond_8

    .line 86
    .line 87
    if-eqz v5, :cond_8

    .line 88
    .line 89
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    const v8, 0x19e5f

    .line 94
    .line 95
    .line 96
    if-eq v4, v8, :cond_6

    .line 97
    .line 98
    const v8, 0x6ac9171

    .line 99
    .line 100
    .line 101
    if-eq v4, v8, :cond_5

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_5
    const-string v4, "value"

    .line 105
    .line 106
    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-eqz v4, :cond_7

    .line 111
    .line 112
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    goto :goto_3

    .line 117
    :cond_6
    const-string v4, "key"

    .line 118
    .line 119
    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_7

    .line 124
    .line 125
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    goto :goto_3

    .line 130
    :cond_7
    :goto_2
    const-string v4, "Encountered an unexpected tag while parsing the defaults XML."

    .line 131
    .line 132
    invoke-static {v1, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 133
    .line 134
    .line 135
    :cond_8
    :goto_3
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 136
    .line 137
    .line 138
    move-result v4
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 139
    goto :goto_0

    .line 140
    :goto_4
    const-string v4, "Encountered an error while parsing the defaults XML file."

    .line 141
    .line 142
    invoke-static {v1, v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 143
    .line 144
    .line 145
    :cond_9
    :goto_5
    :try_start_1
    invoke-static {}, Ldu/e;->c()Ldu/d;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    new-instance v4, Lorg/json/JSONObject;

    .line 150
    .line 151
    invoke-direct {v4, v2}, Lorg/json/JSONObject;-><init>(Ljava/util/Map;)V

    .line 152
    .line 153
    .line 154
    iput-object v4, v0, Ldu/d;->b:Ljava/lang/Object;

    .line 155
    .line 156
    invoke-virtual {v0}, Ldu/d;->a()Ldu/e;

    .line 157
    .line 158
    .line 159
    move-result-object v0
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_1

    .line 160
    iget-object p0, p0, Lcu/b;->f:Ldu/c;

    .line 161
    .line 162
    invoke-virtual {p0, v0}, Ldu/c;->d(Ldu/e;)Laq/t;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    new-instance v0, Lc1/y;

    .line 167
    .line 168
    const/16 v1, 0x11

    .line 169
    .line 170
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 171
    .line 172
    .line 173
    sget-object v1, Lhs/i;->d:Lhs/i;

    .line 174
    .line 175
    invoke-virtual {p0, v1, v0}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    goto :goto_6

    .line 180
    :catch_1
    move-exception p0

    .line 181
    const-string v0, "The provided defaults map could not be processed."

    .line 182
    .line 183
    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 184
    .line 185
    .line 186
    invoke-static {v3}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    :goto_6
    return-object p0
.end method
