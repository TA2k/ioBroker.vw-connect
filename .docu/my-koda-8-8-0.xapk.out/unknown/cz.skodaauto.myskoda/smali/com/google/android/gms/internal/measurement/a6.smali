.class public final Lcom/google/android/gms/internal/measurement/a6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/measurement/e6;


# static fields
.field public static final b:Lcom/google/android/gms/internal/measurement/j5;


# instance fields
.field public final a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/j5;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/j5;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/internal/measurement/a6;->b:Lcom/google/android/gms/internal/measurement/j5;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(I)V
    .locals 3

    packed-switch p1, :pswitch_data_0

    .line 2
    new-instance p1, Lcom/google/android/gms/internal/measurement/a6;

    sget-object v0, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    const/4 v0, 0x2

    new-array v0, v0, [Lcom/google/android/gms/internal/measurement/e6;

    sget-object v1, Lcom/google/android/gms/internal/measurement/j5;->b:Lcom/google/android/gms/internal/measurement/j5;

    const/4 v2, 0x0

    aput-object v1, v0, v2

    sget-object v1, Lcom/google/android/gms/internal/measurement/a6;->b:Lcom/google/android/gms/internal/measurement/j5;

    const/4 v2, 0x1

    aput-object v1, v0, v2

    invoke-direct {p1, v0}, Lcom/google/android/gms/internal/measurement/a6;-><init>(Ljava/lang/Object;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    sget-object v0, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    return-void

    .line 4
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/b5;)V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    iput-object p0, p1, Lcom/google/android/gms/internal/measurement/b5;->a:Lcom/google/android/gms/internal/measurement/a6;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Class;)Z
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    const/4 v2, 0x2

    .line 4
    if-ge v1, v2, :cond_1

    .line 5
    .line 6
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v2, [Lcom/google/android/gms/internal/measurement/e6;

    .line 9
    .line 10
    aget-object v2, v2, v1

    .line 11
    .line 12
    invoke-interface {v2, p1}, Lcom/google/android/gms/internal/measurement/e6;->a(Ljava/lang/Class;)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    return v0
.end method

.method public b(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/m6;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    const/4 v1, 0x2

    .line 3
    if-ge v0, v1, :cond_1

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, [Lcom/google/android/gms/internal/measurement/e6;

    .line 8
    .line 9
    aget-object v1, v1, v0

    .line 10
    .line 11
    invoke-interface {v1, p1}, Lcom/google/android/gms/internal/measurement/e6;->a(Ljava/lang/Class;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-interface {v1, p1}, Lcom/google/android/gms/internal/measurement/e6;->b(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/m6;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    const-string v0, "No factory is available for message type: "

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0
.end method

.method public c()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/f4;

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/f4;->a:Landroid/content/ContentResolver;

    .line 6
    .line 7
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/f4;->b:Landroid/net/Uri;

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Landroid/content/ContentResolver;->acquireUnstableContentProviderClient(Landroid/net/Uri;)Landroid/content/ContentProviderClient;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string p0, "ConfigurationContentLdr"

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    const-string v0, "Unable to acquire ContentProviderClient, using default values"

    .line 18
    .line 19
    invoke-static {p0, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    :try_start_0
    sget-object v3, Lcom/google/android/gms/internal/measurement/f4;->j:[Ljava/lang/String;

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v4, 0x0

    .line 30
    invoke-virtual/range {v1 .. v6}, Landroid/content/ContentProviderClient;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 31
    .line 32
    .line 33
    move-result-object v2
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 34
    if-nez v2, :cond_1

    .line 35
    .line 36
    :try_start_1
    const-string v0, "ContentProvider query returned null cursor, using default values"

    .line 37
    .line 38
    invoke-static {p0, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    .line 43
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :catchall_0
    move-exception v0

    .line 48
    move-object v3, v0

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    :try_start_2
    invoke-interface {v2}, Landroid/database/Cursor;->getCount()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_2

    .line 55
    .line 56
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 57
    .line 58
    :try_start_3
    invoke-interface {v2}, Landroid/database/Cursor;->close()V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 62
    .line 63
    .line 64
    return-object v0

    .line 65
    :catchall_1
    move-exception v0

    .line 66
    move-object p0, v0

    .line 67
    goto :goto_4

    .line 68
    :catch_0
    move-exception v0

    .line 69
    goto :goto_3

    .line 70
    :cond_2
    const/16 v3, 0x100

    .line 71
    .line 72
    if-gt v0, v3, :cond_3

    .line 73
    .line 74
    :try_start_4
    new-instance v3, Landroidx/collection/f;

    .line 75
    .line 76
    invoke-direct {v3, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    new-instance v3, Ljava/util/HashMap;

    .line 81
    .line 82
    const/high16 v4, 0x3f800000    # 1.0f

    .line 83
    .line 84
    invoke-direct {v3, v0, v4}, Ljava/util/HashMap;-><init>(IF)V

    .line 85
    .line 86
    .line 87
    :goto_0
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_4

    .line 92
    .line 93
    const/4 v0, 0x0

    .line 94
    invoke-interface {v2, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    const/4 v4, 0x1

    .line 99
    invoke-interface {v2, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-interface {v3, v0, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_4
    invoke-interface {v2}, Landroid/database/Cursor;->isAfterLast()Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-nez v0, :cond_5

    .line 112
    .line 113
    const-string v0, "Cursor read incomplete (ContentProvider dead?), using default values"

    .line 114
    .line 115
    invoke-static {p0, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 116
    .line 117
    .line 118
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 119
    .line 120
    :try_start_5
    invoke-interface {v2}, Landroid/database/Cursor;->close()V
    :try_end_5
    .catch Landroid/os/RemoteException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 124
    .line 125
    .line 126
    return-object v0

    .line 127
    :cond_5
    :try_start_6
    invoke-interface {v2}, Landroid/database/Cursor;->close()V
    :try_end_6
    .catch Landroid/os/RemoteException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 131
    .line 132
    .line 133
    return-object v3

    .line 134
    :goto_1
    if-eqz v2, :cond_6

    .line 135
    .line 136
    :try_start_7
    invoke-interface {v2}, Landroid/database/Cursor;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 137
    .line 138
    .line 139
    goto :goto_2

    .line 140
    :catchall_2
    move-exception v0

    .line 141
    :try_start_8
    invoke-virtual {v3, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 142
    .line 143
    .line 144
    :cond_6
    :goto_2
    throw v3
    :try_end_8
    .catch Landroid/os/RemoteException; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 145
    :goto_3
    :try_start_9
    const-string v2, "ContentProvider query failed, using default values"

    .line 146
    .line 147
    invoke-static {p0, v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 148
    .line 149
    .line 150
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 151
    .line 152
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 153
    .line 154
    .line 155
    return-object p0

    .line 156
    :goto_4
    invoke-virtual {v1}, Landroid/content/ContentProviderClient;->release()Z

    .line 157
    .line 158
    .line 159
    throw p0
.end method

.method public d(ILjava/lang/Object;Lcom/google/android/gms/internal/measurement/n6;)V
    .locals 0

    .line 1
    check-cast p2, Lcom/google/android/gms/internal/measurement/t4;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lcom/google/android/gms/internal/measurement/b5;

    .line 6
    .line 7
    shl-int/lit8 p1, p1, 0x3

    .line 8
    .line 9
    or-int/lit8 p1, p1, 0x2

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/measurement/t4;->b(Lcom/google/android/gms/internal/measurement/n6;)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/b5;->a:Lcom/google/android/gms/internal/measurement/a6;

    .line 22
    .line 23
    invoke-interface {p3, p2, p0}, Lcom/google/android/gms/internal/measurement/n6;->b(Ljava/lang/Object;Lcom/google/android/gms/internal/measurement/a6;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public e(ILjava/lang/Object;Lcom/google/android/gms/internal/measurement/n6;)V
    .locals 1

    .line 1
    check-cast p2, Lcom/google/android/gms/internal/measurement/t4;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lcom/google/android/gms/internal/measurement/b5;

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    invoke-virtual {p0, p1, v0}, Lcom/google/android/gms/internal/measurement/b5;->e(II)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/b5;->a:Lcom/google/android/gms/internal/measurement/a6;

    .line 12
    .line 13
    invoke-interface {p3, p2, v0}, Lcom/google/android/gms/internal/measurement/n6;->b(Ljava/lang/Object;Lcom/google/android/gms/internal/measurement/a6;)V

    .line 14
    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->e(II)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
