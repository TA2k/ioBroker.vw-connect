.class public final Llo/b0;
.super Lyp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/j;
.implements Lko/k;


# static fields
.field public static final k:Lbp/l;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Landroid/os/Handler;

.field public final f:Lbp/l;

.field public final g:Ljava/util/Set;

.field public final h:Lin/z1;

.field public i:Lyp/a;

.field public j:Lh8/o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lxp/b;->a:Lbp/l;

    .line 2
    .line 3
    sput-object v0, Llo/b0;->k:Lbp/l;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lbp/c;Lin/z1;)V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.signin.internal.ISignInCallbacks"

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Llo/b0;->d:Landroid/content/Context;

    .line 8
    .line 9
    iput-object p2, p0, Llo/b0;->e:Landroid/os/Handler;

    .line 10
    .line 11
    iput-object p3, p0, Llo/b0;->h:Lin/z1;

    .line 12
    .line 13
    iget-object p1, p3, Lin/z1;->a:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Ljava/util/Set;

    .line 16
    .line 17
    iput-object p1, p0, Llo/b0;->g:Ljava/util/Set;

    .line 18
    .line 19
    sget-object p1, Llo/b0;->k:Lbp/l;

    .line 20
    .line 21
    iput-object p1, p0, Llo/b0;->f:Lbp/l;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 8

    .line 1
    iget-object v0, p0, Llo/b0;->i:Lyp/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v1, "<<default account>>"

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    const/4 v3, 0x0

    .line 10
    :try_start_0
    iget-object v4, v0, Lyp/a;->A:Lin/z1;

    .line 11
    .line 12
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    new-instance v4, Landroid/accounts/Account;

    .line 16
    .line 17
    const-string v5, "com.google"

    .line 18
    .line 19
    invoke-direct {v4, v1, v5}, Landroid/accounts/Account;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v5, v4, Landroid/accounts/Account;->name:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_2

    .line 29
    .line 30
    iget-object v1, v0, Lno/e;->c:Landroid/content/Context;

    .line 31
    .line 32
    sget-object v5, Lho/a;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 33
    .line 34
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    sget-object v5, Lho/a;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 38
    .line 39
    invoke-virtual {v5}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    :try_start_1
    sget-object v6, Lho/a;->d:Lho/a;

    .line 43
    .line 44
    if-nez v6, :cond_0

    .line 45
    .line 46
    new-instance v6, Lho/a;

    .line 47
    .line 48
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-direct {v6, v1}, Lho/a;-><init>(Landroid/content/Context;)V

    .line 53
    .line 54
    .line 55
    sput-object v6, Lho/a;->d:Lho/a;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception v0

    .line 59
    goto :goto_1

    .line 60
    :cond_0
    :goto_0
    sget-object v1, Lho/a;->d:Lho/a;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    :try_start_2
    invoke-virtual {v5}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 63
    .line 64
    .line 65
    const-string v5, "defaultGoogleSignInAccount"

    .line 66
    .line 67
    invoke-virtual {v1, v5}, Lho/a;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 72
    .line 73
    .line 74
    move-result v6

    .line 75
    if-eqz v6, :cond_1

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_1
    new-instance v6, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v7, "googleSignInAccount:"

    .line 81
    .line 82
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    invoke-virtual {v1, v5}, Lho/a;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v1
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0

    .line 96
    if-eqz v1, :cond_2

    .line 97
    .line 98
    :try_start_3
    invoke-static {v1}, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;->x0(Ljava/lang/String;)Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;

    .line 99
    .line 100
    .line 101
    move-result-object v1
    :try_end_3
    .catch Lorg/json/JSONException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0

    .line 102
    goto :goto_3

    .line 103
    :goto_1
    :try_start_4
    invoke-virtual {v5}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 104
    .line 105
    .line 106
    throw v0

    .line 107
    :catch_0
    move-exception v0

    .line 108
    goto :goto_4

    .line 109
    :catch_1
    :cond_2
    :goto_2
    move-object v1, v3

    .line 110
    :goto_3
    new-instance v5, Lno/u;

    .line 111
    .line 112
    iget-object v6, v0, Lyp/a;->C:Ljava/lang/Integer;

    .line 113
    .line 114
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    const/4 v7, 0x2

    .line 122
    invoke-direct {v5, v7, v4, v6, v1}, Lno/u;-><init>(ILandroid/accounts/Account;ILcom/google/android/gms/auth/api/signin/GoogleSignInAccount;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0}, Lno/e;->r()Landroid/os/IInterface;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    check-cast v0, Lyp/d;

    .line 130
    .line 131
    new-instance v1, Lyp/f;

    .line 132
    .line 133
    invoke-direct {v1, v2, v5}, Lyp/f;-><init>(ILno/u;)V

    .line 134
    .line 135
    .line 136
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    iget-object v5, v0, Lbp/a;->e:Ljava/lang/String;

    .line 141
    .line 142
    invoke-virtual {v4, v5}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-static {v4, v1}, Lcp/a;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v4, p0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 149
    .line 150
    .line 151
    const/16 v1, 0xc

    .line 152
    .line 153
    invoke-virtual {v0, v4, v1}, Lbp/a;->a(Landroid/os/Parcel;I)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_0

    .line 154
    .line 155
    .line 156
    goto :goto_5

    .line 157
    :goto_4
    const-string v1, "Remote service probably died when signIn is called"

    .line 158
    .line 159
    const-string v4, "SignInClientImpl"

    .line 160
    .line 161
    invoke-static {v4, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 162
    .line 163
    .line 164
    :try_start_5
    new-instance v1, Lyp/g;

    .line 165
    .line 166
    new-instance v5, Ljo/b;

    .line 167
    .line 168
    const/16 v6, 0x8

    .line 169
    .line 170
    invoke-direct {v5, v6, v3}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 171
    .line 172
    .line 173
    invoke-direct {v1, v2, v5, v3}, Lyp/g;-><init>(ILjo/b;Lno/v;)V

    .line 174
    .line 175
    .line 176
    new-instance v2, Lk0/g;

    .line 177
    .line 178
    const/16 v3, 0xb

    .line 179
    .line 180
    const/4 v5, 0x0

    .line 181
    invoke-direct {v2, p0, v1, v5, v3}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 182
    .line 183
    .line 184
    iget-object p0, p0, Llo/b0;->e:Landroid/os/Handler;

    .line 185
    .line 186
    invoke-virtual {p0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    :try_end_5
    .catch Landroid/os/RemoteException; {:try_start_5 .. :try_end_5} :catch_2

    .line 187
    .line 188
    .line 189
    goto :goto_5

    .line 190
    :catch_2
    const-string p0, "ISignInCallbacks#onSignInComplete should be executed from the same process, unexpected RemoteException."

    .line 191
    .line 192
    invoke-static {v4, p0, v0}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 193
    .line 194
    .line 195
    :goto_5
    return-void
.end method

.method public final b(Ljo/b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Llo/b0;->j:Lh8/o;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lh8/o;->e(Ljo/b;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Llo/b0;->j:Lh8/o;

    .line 2
    .line 3
    iget-object v0, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Llo/g;

    .line 6
    .line 7
    iget-object v0, v0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 8
    .line 9
    iget-object p0, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Llo/b;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Llo/s;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    iget-boolean v0, p0, Llo/s;->k:Z

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    new-instance p1, Ljo/b;

    .line 26
    .line 27
    const/16 v0, 0x11

    .line 28
    .line 29
    invoke-direct {p1, v0}, Ljo/b;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, p1}, Llo/s;->q(Ljo/b;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    invoke-virtual {p0, p1}, Llo/s;->c(I)V

    .line 37
    .line 38
    .line 39
    :cond_1
    return-void
.end method
