.class public final Lno/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Landroid/net/Uri;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroid/net/Uri$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/net/Uri$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "content"

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "com.google.android.gms.chimera"

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lno/k0;->d:Landroid/net/Uri;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lno/k0;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iput-object p2, p0, Lno/k0;->b:Ljava/lang/String;

    .line 13
    .line 14
    iput-boolean p3, p0, Lno/k0;->c:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;)Landroid/content/Intent;
    .locals 5

    .line 1
    const-string v0, "ConnectionStatusConfig"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lno/k0;->a:Ljava/lang/String;

    .line 5
    .line 6
    if-eqz v2, :cond_5

    .line 7
    .line 8
    iget-boolean v3, p0, Lno/k0;->c:Z

    .line 9
    .line 10
    if-eqz v3, :cond_3

    .line 11
    .line 12
    new-instance v3, Landroid/os/Bundle;

    .line 13
    .line 14
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    .line 15
    .line 16
    .line 17
    const-string v4, "serviceActionBundleKey"

    .line 18
    .line 19
    invoke-virtual {v3, v4, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :try_start_0
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    sget-object v4, Lno/k0;->d:Landroid/net/Uri;

    .line 27
    .line 28
    invoke-virtual {p1, v4}, Landroid/content/ContentResolver;->acquireUnstableContentProviderClient(Landroid/net/Uri;)Landroid/content/ContentProviderClient;

    .line 29
    .line 30
    .line 31
    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    :try_start_1
    const-string v4, "serviceIntentCall"

    .line 35
    .line 36
    invoke-virtual {p1, v4, v1, v3}, Landroid/content/ContentProviderClient;->call(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 37
    .line 38
    .line 39
    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    :try_start_2
    invoke-virtual {p1}, Landroid/content/ContentProviderClient;->release()Z
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_0

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :catch_0
    move-exception p1

    .line 45
    goto :goto_1

    .line 46
    :catchall_0
    move-exception v3

    .line 47
    :try_start_3
    invoke-virtual {p1}, Landroid/content/ContentProviderClient;->release()Z

    .line 48
    .line 49
    .line 50
    throw v3

    .line 51
    :catch_1
    move-exception p1

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    new-instance p1, Landroid/os/RemoteException;

    .line 54
    .line 55
    const-string v3, "Failed to acquire ContentProviderClient"

    .line 56
    .line 57
    invoke-direct {p1, v3}, Landroid/os/RemoteException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p1
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_1

    .line 61
    :goto_0
    move-object v3, v1

    .line 62
    :goto_1
    const-string v4, "Dynamic intent resolution failed: "

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-virtual {v4, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    :goto_2
    if-eqz v3, :cond_2

    .line 76
    .line 77
    const-string p1, "serviceResponseIntentKey"

    .line 78
    .line 79
    invoke-virtual {v3, p1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    move-object v1, p1

    .line 84
    check-cast v1, Landroid/content/Intent;

    .line 85
    .line 86
    if-nez v1, :cond_2

    .line 87
    .line 88
    const-string p1, "serviceMissingResolutionIntentKey"

    .line 89
    .line 90
    invoke-virtual {v3, p1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    check-cast p1, Landroid/app/PendingIntent;

    .line 95
    .line 96
    if-nez p1, :cond_1

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    const-string v1, "Dynamic lookup for intent failed for action "

    .line 102
    .line 103
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, " but has possible resolution"

    .line 110
    .line 111
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    new-instance p0, Lno/d0;

    .line 122
    .line 123
    new-instance v0, Ljo/b;

    .line 124
    .line 125
    const/16 v1, 0x19

    .line 126
    .line 127
    invoke-direct {v0, v1, p1}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 128
    .line 129
    .line 130
    invoke-direct {p0, v0}, Lno/d0;-><init>(Ljo/b;)V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_2
    :goto_3
    if-nez v1, :cond_3

    .line 135
    .line 136
    const-string p1, "Dynamic lookup for intent failed for action: "

    .line 137
    .line 138
    invoke-virtual {p1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 143
    .line 144
    .line 145
    :cond_3
    if-nez v1, :cond_4

    .line 146
    .line 147
    new-instance p1, Landroid/content/Intent;

    .line 148
    .line 149
    invoke-direct {p1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    iget-object p0, p0, Lno/k0;->b:Ljava/lang/String;

    .line 153
    .line 154
    invoke-virtual {p1, p0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :cond_4
    return-object v1

    .line 160
    :cond_5
    new-instance p0, Landroid/content/Intent;

    .line 161
    .line 162
    invoke-direct {p0}, Landroid/content/Intent;-><init>()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0, v1}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lno/k0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lno/k0;

    .line 12
    .line 13
    iget-object v1, p0, Lno/k0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lno/k0;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v1, p0, Lno/k0;->b:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v3, p1, Lno/k0;->b:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v1, v3}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-static {v1, v1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    iget-boolean p0, p0, Lno/k0;->c:Z

    .line 41
    .line 42
    iget-boolean p1, p1, Lno/k0;->c:Z

    .line 43
    .line 44
    if-ne p0, p1, :cond_2

    .line 45
    .line 46
    return v0

    .line 47
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/16 v0, 0x1081

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-boolean v1, p0, Lno/k0;->c:Z

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object v2, p0, Lno/k0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p0, p0, Lno/k0;->b:Ljava/lang/String;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    filled-new-array {v2, p0, v3, v0, v1}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/k0;->a:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const/4 p0, 0x0

    .line 7
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    throw p0
.end method
