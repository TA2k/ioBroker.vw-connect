.class public abstract Lkp/z5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Landroid/content/Context;

.field public static b:Lrp/e;


# direct methods
.method public static final a(Le91/a;)Ljava/lang/Throwable;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Le91/a;->getContext()Le91/b;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p0, p0, Le91/b;->a:Ljava/util/Map;

    .line 11
    .line 12
    sget-object v0, Le91/c;->c:Le91/c;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    instance-of v0, p0, Ljava/lang/Throwable;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    check-cast p0, Ljava/lang/Throwable;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public static b(Landroid/content/Context;)Lrp/e;
    .locals 5

    .line 1
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    const-string v0, "null"

    .line 5
    .line 6
    const-string v1, "preferredRenderer: "

    .line 7
    .line 8
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "z5"

    .line 13
    .line 14
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    sget-object v0, Lkp/z5;->b:Lrp/e;

    .line 18
    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    sget-object v0, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 22
    .line 23
    const v0, 0xcc77c0

    .line 24
    .line 25
    .line 26
    invoke-static {p0, v0}, Ljo/h;->b(Landroid/content/Context;I)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-static {p0, v0}, Lkp/z5;->d(Landroid/content/Context;I)Lrp/e;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    sput-object v2, Lkp/z5;->b:Lrp/e;

    .line 38
    .line 39
    :try_start_0
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    const/16 v4, 0x9

    .line 44
    .line 45
    invoke-virtual {v2, v3, v4}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-virtual {v2}, Landroid/os/Parcel;->readInt()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-virtual {v2}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_3

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    const/4 v4, 0x2

    .line 61
    if-ne v3, v4, :cond_0

    .line 62
    .line 63
    const-string v3, "com.google.android.apps.photos"

    .line 64
    .line 65
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-nez v2, :cond_0

    .line 70
    .line 71
    const-string v2, "early loading native code"

    .line 72
    .line 73
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 74
    .line 75
    .line 76
    :try_start_1
    sget-object v2, Lkp/z5;->b:Lrp/e;

    .line 77
    .line 78
    invoke-static {p0, v0}, Lkp/z5;->c(Landroid/content/Context;I)Landroid/content/Context;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    new-instance v4, Lyo/b;

    .line 83
    .line 84
    invoke-direct {v4, v3}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-static {v3, v4}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 92
    .line 93
    .line 94
    const/16 v4, 0xb

    .line 95
    .line 96
    invoke-virtual {v2, v3, v4}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_1 .. :try_end_1} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :catch_0
    move-exception p0

    .line 101
    new-instance v0, La8/r0;

    .line 102
    .line 103
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 104
    .line 105
    .line 106
    throw v0

    .line 107
    :catch_1
    const-string v2, "Caught UnsatisfiedLinkError attempting to load the LATEST renderer\'s native library. Attempting to use the LEGACY renderer instead."

    .line 108
    .line 109
    invoke-static {v1, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    const/4 v1, 0x0

    .line 113
    sput-object v1, Lkp/z5;->a:Landroid/content/Context;

    .line 114
    .line 115
    const/4 v1, 0x1

    .line 116
    invoke-static {p0, v1}, Lkp/z5;->d(Landroid/content/Context;I)Lrp/e;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    sput-object v1, Lkp/z5;->b:Lrp/e;

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_0
    const-string v2, "not early loading native code"

    .line 124
    .line 125
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 126
    .line 127
    .line 128
    :goto_0
    :try_start_2
    sget-object v1, Lkp/z5;->b:Lrp/e;

    .line 129
    .line 130
    invoke-static {p0, v0}, Lkp/z5;->c(Landroid/content/Context;I)Landroid/content/Context;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    new-instance v0, Lyo/b;

    .line 139
    .line 140
    invoke-direct {v0, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-static {p0, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 148
    .line 149
    .line 150
    const v0, 0x12238e0

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 154
    .line 155
    .line 156
    const/4 v0, 0x6

    .line 157
    invoke-virtual {v1, p0, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_2

    .line 158
    .line 159
    .line 160
    sget-object p0, Lkp/z5;->b:Lrp/e;

    .line 161
    .line 162
    return-object p0

    .line 163
    :catch_2
    move-exception p0

    .line 164
    new-instance v0, La8/r0;

    .line 165
    .line 166
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :catch_3
    move-exception p0

    .line 171
    new-instance v0, La8/r0;

    .line 172
    .line 173
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 174
    .line 175
    .line 176
    throw v0

    .line 177
    :cond_1
    new-instance p0, Ljo/g;

    .line 178
    .line 179
    invoke-direct {p0, v0}, Ljo/g;-><init>(I)V

    .line 180
    .line 181
    .line 182
    throw p0

    .line 183
    :cond_2
    return-object v0
.end method

.method public static c(Landroid/content/Context;I)Landroid/content/Context;
    .locals 7

    .line 1
    sget-object v0, Lkp/z5;->a:Landroid/content/Context;

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    if-ne p1, v0, :cond_0

    .line 7
    .line 8
    const-string p1, "com.google.android.gms.maps_legacy_dynamite"

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-string p1, "com.google.android.gms.maps_core_dynamite"

    .line 12
    .line 13
    :goto_0
    :try_start_0
    sget-object v0, Lzo/d;->b:Lrb0/a;

    .line 14
    .line 15
    invoke-static {p0, v0, p1}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object p0, v0, Lzo/d;->a:Landroid/content/Context;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :catch_0
    move-exception v0

    .line 23
    const-string v1, "com.google.android.gms.maps_dynamite"

    .line 24
    .line 25
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x3

    .line 31
    const-string v4, "com.google.android.gms"

    .line 32
    .line 33
    const-string v5, "Failed to load maps module, use pre-Chimera"

    .line 34
    .line 35
    const-string v6, "z5"

    .line 36
    .line 37
    if-nez p1, :cond_1

    .line 38
    .line 39
    :try_start_1
    const-string p1, "Attempting to load maps_dynamite again."

    .line 40
    .line 41
    invoke-static {v6, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    sget-object p1, Lzo/d;->b:Lrb0/a;

    .line 45
    .line 46
    invoke-static {p0, p1, v1}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    iget-object p0, p1, Lzo/d;->a:Landroid/content/Context;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :catch_1
    move-exception p1

    .line 54
    invoke-static {v6, v5, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 55
    .line 56
    .line 57
    sget-object p1, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 58
    .line 59
    :try_start_2
    invoke-virtual {p0, v4, v3}, Landroid/content/Context;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    .line 60
    .line 61
    .line 62
    move-result-object p0
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_2

    .line 63
    goto :goto_1

    .line 64
    :catch_2
    move-object p0, v2

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    invoke-static {v6, v5, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 67
    .line 68
    .line 69
    sget-object p1, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 70
    .line 71
    :try_start_3
    invoke-virtual {p0, v4, v3}, Landroid/content/Context;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    .line 72
    .line 73
    .line 74
    move-result-object p0
    :try_end_3
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_3 .. :try_end_3} :catch_2

    .line 75
    :goto_1
    sput-object p0, Lkp/z5;->a:Landroid/content/Context;

    .line 76
    .line 77
    if-eqz p0, :cond_2

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_2
    new-instance p0, Ljava/lang/RuntimeException;

    .line 81
    .line 82
    const-string p1, "Unable to load maps module, maps container context is null"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_3
    return-object v0
.end method

.method public static d(Landroid/content/Context;I)Lrp/e;
    .locals 2

    .line 1
    const-string v0, "z5"

    .line 2
    .line 3
    const-string v1, "Making Creator dynamically"

    .line 4
    .line 5
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    invoke-static {p0, p1}, Lkp/z5;->c(Landroid/content/Context;I)Landroid/content/Context;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string p1, "com.google.android.gms.maps.internal.CreatorImpl"

    .line 17
    .line 18
    :try_start_0
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_2

    .line 25
    :try_start_1
    invoke-virtual {p0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/InstantiationException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_2

    .line 29
    check-cast p0, Landroid/os/IBinder;

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    const-string p1, "com.google.android.gms.maps.internal.ICreator"

    .line 34
    .line 35
    invoke-interface {p0, p1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    instance-of v1, v0, Lrp/e;

    .line 40
    .line 41
    if-eqz v1, :cond_0

    .line 42
    .line 43
    check-cast v0, Lrp/e;

    .line 44
    .line 45
    return-object v0

    .line 46
    :cond_0
    new-instance v0, Lrp/e;

    .line 47
    .line 48
    const/4 v1, 0x5

    .line 49
    invoke-direct {v0, p0, p1, v1}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 50
    .line 51
    .line 52
    return-object v0

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/RuntimeException;

    .line 54
    .line 55
    const-string p1, "Unable to load maps module, IBinder for com.google.android.gms.maps.internal.CreatorImpl is null"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :catch_0
    move-exception p1

    .line 62
    :try_start_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    const-string v1, "Unable to call the default constructor of "

    .line 69
    .line 70
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-direct {v0, p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 75
    .line 76
    .line 77
    throw v0

    .line 78
    :catch_1
    move-exception p1

    .line 79
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    const-string v1, "Unable to instantiate the dynamic class "

    .line 86
    .line 87
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-direct {v0, p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 92
    .line 93
    .line 94
    throw v0
    :try_end_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_2

    .line 95
    :catch_2
    move-exception p0

    .line 96
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    const-string v0, "Unable to find dynamic class com.google.android.gms.maps.internal.CreatorImpl"

    .line 99
    .line 100
    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 101
    .line 102
    .line 103
    throw p1
.end method
