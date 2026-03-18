.class public final Lot/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lst/a;


# instance fields
.field public final a:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lot/b;->b:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lsr/f;Lgt/b;Lht/d;Lgt/b;Lcom/google/firebase/perf/config/RemoteConfigManager;Lqt/a;Lcom/google/firebase/perf/session/SessionManager;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lot/b;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    new-instance p0, Lzt/c;

    .line 14
    .line 15
    new-instance p1, Landroid/os/Bundle;

    .line 16
    .line 17
    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, p1}, Lzt/c;-><init>(Landroid/os/Bundle;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    iget-object p0, p1, Lsr/f;->c:Lsr/i;

    .line 25
    .line 26
    sget-object v0, Lyt/h;->v:Lyt/h;

    .line 27
    .line 28
    iput-object p1, v0, Lyt/h;->g:Lsr/f;

    .line 29
    .line 30
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 31
    .line 32
    .line 33
    iget-object v1, p0, Lsr/i;->g:Ljava/lang/String;

    .line 34
    .line 35
    iput-object v1, v0, Lyt/h;->s:Ljava/lang/String;

    .line 36
    .line 37
    iput-object p3, v0, Lyt/h;->i:Lht/d;

    .line 38
    .line 39
    iput-object p4, v0, Lyt/h;->j:Lgt/b;

    .line 40
    .line 41
    iget-object p3, v0, Lyt/h;->l:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 42
    .line 43
    new-instance p4, Lyt/e;

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    invoke-direct {p4, v0, v1}, Lyt/e;-><init>(Lyt/h;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p3, p4}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 53
    .line 54
    .line 55
    iget-object p3, p1, Lsr/f;->a:Landroid/content/Context;

    .line 56
    .line 57
    :try_start_0
    invoke-virtual {p3}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 58
    .line 59
    .line 60
    move-result-object p4

    .line 61
    invoke-virtual {p3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const/16 v1, 0x80

    .line 66
    .line 67
    invoke-virtual {p4, v0, v1}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 68
    .line 69
    .line 70
    move-result-object p4

    .line 71
    iget-object p4, p4, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :catch_0
    move-exception p4

    .line 75
    new-instance v0, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string v1, "No perf enable meta data found "

    .line 78
    .line 79
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p4}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p4

    .line 86
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p4

    .line 93
    const-string v0, "isEnabled"

    .line 94
    .line 95
    invoke-static {v0, p4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    const/4 p4, 0x0

    .line 99
    :goto_0
    new-instance v0, Lzt/c;

    .line 100
    .line 101
    if-eqz p4, :cond_1

    .line 102
    .line 103
    invoke-direct {v0, p4}, Lzt/c;-><init>(Landroid/os/Bundle;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_1
    invoke-direct {v0}, Lzt/c;-><init>()V

    .line 108
    .line 109
    .line 110
    :goto_1
    invoke-virtual {p5, p2}, Lcom/google/firebase/perf/config/RemoteConfigManager;->setFirebaseRemoteConfigProvider(Lgt/b;)V

    .line 111
    .line 112
    .line 113
    iput-object v0, p6, Lqt/a;->b:Lzt/c;

    .line 114
    .line 115
    sget-object p2, Lqt/a;->d:Lst/a;

    .line 116
    .line 117
    invoke-static {p3}, Ljp/m1;->d(Landroid/content/Context;)Z

    .line 118
    .line 119
    .line 120
    move-result p4

    .line 121
    iput-boolean p4, p2, Lst/a;->b:Z

    .line 122
    .line 123
    iget-object p2, p6, Lqt/a;->c:Lqt/v;

    .line 124
    .line 125
    invoke-virtual {p2, p3}, Lqt/v;->c(Landroid/content/Context;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p7, p3}, Lcom/google/firebase/perf/session/SessionManager;->setApplicationContext(Landroid/content/Context;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p6}, Lqt/a;->g()Ljava/lang/Boolean;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    sget-object p4, Lot/b;->b:Lst/a;

    .line 136
    .line 137
    iget-boolean p5, p4, Lst/a;->b:Z

    .line 138
    .line 139
    if-eqz p5, :cond_3

    .line 140
    .line 141
    if-eqz p2, :cond_2

    .line 142
    .line 143
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    goto :goto_2

    .line 148
    :cond_2
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    invoke-virtual {p2}, Lsr/f;->h()Z

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    :goto_2
    if-eqz p2, :cond_3

    .line 157
    .line 158
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 159
    .line 160
    .line 161
    iget-object p0, p0, Lsr/i;->g:Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {p3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    invoke-static {p0, p1}, Lkp/q8;->c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    const-string p1, "/trends?utm_source=perf-android-sdk&utm_medium=android-ide"

    .line 172
    .line 173
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    const-string p1, "Firebase Performance Monitoring is successfully initialized! In a minute, visit the Firebase console to view your data: "

    .line 178
    .line 179
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    iget-boolean p1, p4, Lst/a;->b:Z

    .line 184
    .line 185
    if-eqz p1, :cond_3

    .line 186
    .line 187
    iget-object p1, p4, Lst/a;->a:Lst/b;

    .line 188
    .line 189
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    const-string p1, "FirebasePerformance"

    .line 193
    .line 194
    invoke-static {p1, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 195
    .line 196
    .line 197
    :cond_3
    return-void
.end method
