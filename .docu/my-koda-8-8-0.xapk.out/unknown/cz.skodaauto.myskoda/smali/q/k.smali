.class public Lq/k;
.super Landroidx/fragment/app/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroid/os/Handler;

.field public e:Lq/s;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/fragment/app/j0;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/os/Handler;

    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lq/k;->d:Landroid/os/Handler;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final i(I)V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    if-eq p1, v0, :cond_0

    .line 3
    .line 4
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 5
    .line 6
    iget-boolean p1, p1, Lq/s;->o:Z

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    goto :goto_2

    .line 11
    :cond_0
    invoke-virtual {p0}, Lq/k;->k()V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 15
    .line 16
    iget-object p1, p0, Lq/s;->i:Lb81/c;

    .line 17
    .line 18
    if-nez p1, :cond_1

    .line 19
    .line 20
    new-instance p1, Lb81/c;

    .line 21
    .line 22
    const/16 v0, 0x15

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {p1, v0, v1}, Lb81/c;-><init>(IZ)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lq/s;->i:Lb81/c;

    .line 29
    .line 30
    :cond_1
    iget-object p0, p0, Lq/s;->i:Lb81/c;

    .line 31
    .line 32
    iget-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Landroid/os/CancellationSignal;

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    const-string v1, "CancelSignalProvider"

    .line 38
    .line 39
    if-eqz p1, :cond_2

    .line 40
    .line 41
    :try_start_0
    invoke-static {p1}, Lq/t;->a(Landroid/os/CancellationSignal;)V
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    move-exception p1

    .line 46
    const-string v2, "Got NPE while canceling biometric authentication."

    .line 47
    .line 48
    invoke-static {v1, v2, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 49
    .line 50
    .line 51
    :goto_0
    iput-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 52
    .line 53
    :cond_2
    iget-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p1, Lg11/k;

    .line 56
    .line 57
    if-eqz p1, :cond_3

    .line 58
    .line 59
    :try_start_1
    invoke-virtual {p1}, Lg11/k;->a()V
    :try_end_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_1

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :catch_1
    move-exception p1

    .line 64
    const-string v2, "Got NPE while canceling fingerprint authentication."

    .line 65
    .line 66
    invoke-static {v1, v2, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 67
    .line 68
    .line 69
    :goto_1
    iput-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 70
    .line 71
    :cond_3
    :goto_2
    return-void
.end method

.method public final j()V
    .locals 6

    .line 1
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-boolean v1, v0, Lq/s;->k:Z

    .line 5
    .line 6
    iput-boolean v1, v0, Lq/s;->k:Z

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->isAdded()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v2, 0x1

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v3, "androidx.biometric.FingerprintDialogFragment"

    .line 20
    .line 21
    invoke-virtual {v0, v3}, Landroidx/fragment/app/j1;->D(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    check-cast v3, Lq/z;

    .line 26
    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->isAdded()Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-eqz v4, :cond_0

    .line 34
    .line 35
    invoke-virtual {v3, v2, v1}, Landroidx/fragment/app/x;->i(ZZ)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    new-instance v4, Landroidx/fragment/app/a;

    .line 40
    .line 41
    invoke-direct {v4, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4, v3}, Landroidx/fragment/app/a;->h(Landroidx/fragment/app/j0;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v4, v2, v2}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 48
    .line 49
    .line 50
    :cond_1
    :goto_0
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 51
    .line 52
    iget-boolean v0, v0, Lq/s;->m:Z

    .line 53
    .line 54
    if-nez v0, :cond_2

    .line 55
    .line 56
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->isAdded()Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    new-instance v3, Landroidx/fragment/app/a;

    .line 70
    .line 71
    invoke-direct {v3, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3, p0}, Landroidx/fragment/app/a;->h(Landroidx/fragment/app/j0;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v3, v2, v2}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 78
    .line 79
    .line 80
    :cond_2
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    if-eqz v0, :cond_6

    .line 85
    .line 86
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 87
    .line 88
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 89
    .line 90
    const/16 v5, 0x1d

    .line 91
    .line 92
    if-eq v4, v5, :cond_3

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_3
    if-nez v3, :cond_4

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_4
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    const v4, 0x7f030003

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v4}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    array-length v4, v0

    .line 110
    :goto_1
    if-ge v1, v4, :cond_6

    .line 111
    .line 112
    aget-object v5, v0, v1

    .line 113
    .line 114
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    if-eqz v5, :cond_5

    .line 119
    .line 120
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 121
    .line 122
    iput-boolean v2, v0, Lq/s;->n:Z

    .line 123
    .line 124
    new-instance v1, Lq/j;

    .line 125
    .line 126
    const/4 v2, 0x1

    .line 127
    invoke-direct {v1, v0, v2}, Lq/j;-><init>(Lq/s;I)V

    .line 128
    .line 129
    .line 130
    const-wide/16 v2, 0x258

    .line 131
    .line 132
    iget-object p0, p0, Lq/k;->d:Landroid/os/Handler;

    .line 133
    .line 134
    invoke-virtual {p0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 135
    .line 136
    .line 137
    return-void

    .line 138
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_6
    :goto_2
    return-void
.end method

.method public final k()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lq/k;->e:Lq/s;

    .line 8
    .line 9
    iget-object p0, p0, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    sget-object p0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 14
    .line 15
    sget-object p0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final l(ILjava/lang/CharSequence;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 2
    .line 3
    iget-boolean v1, v0, Lq/s;->m:Z

    .line 4
    .line 5
    const-string v2, "BiometricFragment"

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    const-string p1, "Error not sent to client. User is confirming their device credential."

    .line 10
    .line 11
    invoke-static {v2, p1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-boolean v1, v0, Lq/s;->l:Z

    .line 16
    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    const-string p1, "Error not sent to client. Client is not awaiting a result."

    .line 20
    .line 21
    invoke-static {v2, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 22
    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    const/4 v1, 0x0

    .line 26
    iput-boolean v1, v0, Lq/s;->l:Z

    .line 27
    .line 28
    iget-object v0, v0, Lq/s;->d:Ljava/util/concurrent/Executor;

    .line 29
    .line 30
    if-eqz v0, :cond_2

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    new-instance v0, Lq/q;

    .line 34
    .line 35
    invoke-direct {v0}, Lq/q;-><init>()V

    .line 36
    .line 37
    .line 38
    :goto_0
    new-instance v1, Liq/a;

    .line 39
    .line 40
    const/4 v2, 0x3

    .line 41
    invoke-direct {v1, p1, v2, p0, p2}, Liq/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 45
    .line 46
    .line 47
    :goto_1
    invoke-virtual {p0}, Lq/k;->j()V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public final m(Lq/n;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 2
    .line 3
    iget-boolean v1, v0, Lq/s;->l:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const-string p1, "BiometricFragment"

    .line 8
    .line 9
    const-string v0, "Success not sent to client. Client is not awaiting a result."

    .line 10
    .line 11
    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    const/4 v1, 0x0

    .line 16
    iput-boolean v1, v0, Lq/s;->l:Z

    .line 17
    .line 18
    iget-object v0, v0, Lq/s;->d:Ljava/util/concurrent/Executor;

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    new-instance v0, Lq/q;

    .line 24
    .line 25
    invoke-direct {v0}, Lq/q;-><init>()V

    .line 26
    .line 27
    .line 28
    :goto_0
    new-instance v1, Llr/b;

    .line 29
    .line 30
    const/16 v2, 0x10

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-direct {v1, p0, p1, v3, v2}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 37
    .line 38
    .line 39
    :goto_1
    invoke-virtual {p0}, Lq/k;->j()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final n()V
    .locals 11

    .line 1
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 2
    .line 3
    iget-boolean v0, v0, Lq/s;->k:Z

    .line 4
    .line 5
    if-nez v0, :cond_18

    .line 6
    .line 7
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "BiometricFragment"

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const-string p0, "Not showing biometric prompt. Context is null."

    .line 16
    .line 17
    invoke-static {v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    iput-boolean v2, v0, Lq/s;->k:Z

    .line 25
    .line 26
    iput-boolean v2, v0, Lq/s;->l:Z

    .line 27
    .line 28
    invoke-virtual {p0}, Lq/k;->k()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0}, Lq/g;->d(Landroid/content/Context;)Landroid/hardware/biometrics/BiometricPrompt$Builder;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iget-object v3, p0, Lq/k;->e:Lq/s;

    .line 44
    .line 45
    iget-object v4, v3, Lq/s;->f:Lil/g;

    .line 46
    .line 47
    const/4 v5, 0x0

    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    iget-object v4, v4, Lil/g;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v4, Ljava/lang/CharSequence;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    move-object v4, v5

    .line 56
    :goto_0
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    iget-object v3, p0, Lq/k;->e:Lq/s;

    .line 60
    .line 61
    iget-object v3, v3, Lq/s;->f:Lil/g;

    .line 62
    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    iget-object v3, v3, Lil/g;->f:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v3, Ljava/lang/CharSequence;

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    move-object v3, v5

    .line 71
    :goto_1
    if-eqz v4, :cond_3

    .line 72
    .line 73
    invoke-static {v0, v4}, Lq/g;->g(Landroid/hardware/biometrics/BiometricPrompt$Builder;Ljava/lang/CharSequence;)V

    .line 74
    .line 75
    .line 76
    :cond_3
    if-eqz v3, :cond_4

    .line 77
    .line 78
    invoke-static {v0, v3}, Lq/g;->e(Landroid/hardware/biometrics/BiometricPrompt$Builder;Ljava/lang/CharSequence;)V

    .line 79
    .line 80
    .line 81
    :cond_4
    iget-object v3, p0, Lq/k;->e:Lq/s;

    .line 82
    .line 83
    iget-object v3, v3, Lq/s;->f:Lil/g;

    .line 84
    .line 85
    const-string v4, ""

    .line 86
    .line 87
    if-eqz v3, :cond_6

    .line 88
    .line 89
    iget-object v3, v3, Lil/g;->g:Ljava/lang/Object;

    .line 90
    .line 91
    move-object v5, v3

    .line 92
    check-cast v5, Ljava/lang/CharSequence;

    .line 93
    .line 94
    if-eqz v5, :cond_5

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    move-object v5, v4

    .line 98
    :cond_6
    :goto_2
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-nez v3, :cond_9

    .line 103
    .line 104
    iget-object v3, p0, Lq/k;->e:Lq/s;

    .line 105
    .line 106
    iget-object v3, v3, Lq/s;->d:Ljava/util/concurrent/Executor;

    .line 107
    .line 108
    if-eqz v3, :cond_7

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_7
    new-instance v3, Lq/q;

    .line 112
    .line 113
    invoke-direct {v3}, Lq/q;-><init>()V

    .line 114
    .line 115
    .line 116
    :goto_3
    iget-object v6, p0, Lq/k;->e:Lq/s;

    .line 117
    .line 118
    iget-object v7, v6, Lq/s;->j:Lq/r;

    .line 119
    .line 120
    if-nez v7, :cond_8

    .line 121
    .line 122
    new-instance v7, Lq/r;

    .line 123
    .line 124
    invoke-direct {v7, v6}, Lq/r;-><init>(Lq/s;)V

    .line 125
    .line 126
    .line 127
    iput-object v7, v6, Lq/s;->j:Lq/r;

    .line 128
    .line 129
    :cond_8
    iget-object v6, v6, Lq/s;->j:Lq/r;

    .line 130
    .line 131
    invoke-static {v0, v5, v3, v6}, Lq/g;->f(Landroid/hardware/biometrics/BiometricPrompt$Builder;Ljava/lang/CharSequence;Ljava/util/concurrent/Executor;Landroid/content/DialogInterface$OnClickListener;)V

    .line 132
    .line 133
    .line 134
    :cond_9
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 135
    .line 136
    iget-object v5, p0, Lq/k;->e:Lq/s;

    .line 137
    .line 138
    iget-object v5, v5, Lq/s;->f:Lil/g;

    .line 139
    .line 140
    invoke-static {v0, v2}, Lq/h;->a(Landroid/hardware/biometrics/BiometricPrompt$Builder;Z)V

    .line 141
    .line 142
    .line 143
    iget-object v5, p0, Lq/k;->e:Lq/s;

    .line 144
    .line 145
    iget-object v6, v5, Lq/s;->f:Lil/g;

    .line 146
    .line 147
    if-eqz v6, :cond_b

    .line 148
    .line 149
    iget-object v5, v5, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 150
    .line 151
    if-eqz v5, :cond_a

    .line 152
    .line 153
    const/16 v5, 0xf

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_a
    const/16 v5, 0xff

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_b
    const/4 v5, 0x0

    .line 160
    :goto_4
    const/16 v6, 0x1e

    .line 161
    .line 162
    if-lt v3, v6, :cond_c

    .line 163
    .line 164
    invoke-static {v0, v5}, Lq/i;->a(Landroid/hardware/biometrics/BiometricPrompt$Builder;I)V

    .line 165
    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_c
    invoke-static {v5}, Ljp/ge;->a(I)Z

    .line 169
    .line 170
    .line 171
    move-result v3

    .line 172
    invoke-static {v0, v3}, Lq/h;->b(Landroid/hardware/biometrics/BiometricPrompt$Builder;Z)V

    .line 173
    .line 174
    .line 175
    :goto_5
    invoke-static {v0}, Lq/g;->c(Landroid/hardware/biometrics/BiometricPrompt$Builder;)Landroid/hardware/biometrics/BiometricPrompt;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    iget-object v5, p0, Lq/k;->e:Lq/s;

    .line 184
    .line 185
    iget-object v5, v5, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 186
    .line 187
    const/4 v6, 0x0

    .line 188
    if-nez v5, :cond_d

    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_d
    iget-object v7, v5, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 192
    .line 193
    check-cast v7, Ljavax/crypto/Cipher;

    .line 194
    .line 195
    if-eqz v7, :cond_e

    .line 196
    .line 197
    invoke-static {v7}, Lq/u;->b(Ljavax/crypto/Cipher;)Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    goto :goto_6

    .line 202
    :cond_e
    iget-object v7, v5, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v7, Ljava/security/Signature;

    .line 205
    .line 206
    if-eqz v7, :cond_f

    .line 207
    .line 208
    invoke-static {v7}, Lq/u;->a(Ljava/security/Signature;)Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    goto :goto_6

    .line 213
    :cond_f
    iget-object v7, v5, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v7, Ljavax/crypto/Mac;

    .line 216
    .line 217
    if-eqz v7, :cond_10

    .line 218
    .line 219
    invoke-static {v7}, Lq/u;->c(Ljavax/crypto/Mac;)Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    .line 220
    .line 221
    .line 222
    move-result-object v6

    .line 223
    goto :goto_6

    .line 224
    :cond_10
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 225
    .line 226
    const/16 v8, 0x1e

    .line 227
    .line 228
    if-lt v7, v8, :cond_11

    .line 229
    .line 230
    iget-object v5, v5, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v5, Landroid/security/identity/IdentityCredential;

    .line 233
    .line 234
    if-eqz v5, :cond_11

    .line 235
    .line 236
    invoke-static {v5}, Lq/v;->a(Landroid/security/identity/IdentityCredential;)Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    .line 237
    .line 238
    .line 239
    move-result-object v6

    .line 240
    :cond_11
    :goto_6
    iget-object v5, p0, Lq/k;->e:Lq/s;

    .line 241
    .line 242
    iget-object v7, v5, Lq/s;->i:Lb81/c;

    .line 243
    .line 244
    if-nez v7, :cond_12

    .line 245
    .line 246
    new-instance v7, Lb81/c;

    .line 247
    .line 248
    const/16 v8, 0x15

    .line 249
    .line 250
    const/4 v9, 0x0

    .line 251
    invoke-direct {v7, v8, v9}, Lb81/c;-><init>(IZ)V

    .line 252
    .line 253
    .line 254
    iput-object v7, v5, Lq/s;->i:Lb81/c;

    .line 255
    .line 256
    :cond_12
    iget-object v5, v5, Lq/s;->i:Lb81/c;

    .line 257
    .line 258
    iget-object v7, v5, Lb81/c;->e:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast v7, Landroid/os/CancellationSignal;

    .line 261
    .line 262
    if-nez v7, :cond_13

    .line 263
    .line 264
    invoke-static {}, Lq/t;->b()Landroid/os/CancellationSignal;

    .line 265
    .line 266
    .line 267
    move-result-object v7

    .line 268
    iput-object v7, v5, Lb81/c;->e:Ljava/lang/Object;

    .line 269
    .line 270
    :cond_13
    iget-object v5, v5, Lb81/c;->e:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast v5, Landroid/os/CancellationSignal;

    .line 273
    .line 274
    new-instance v7, Llo/q;

    .line 275
    .line 276
    invoke-direct {v7}, Llo/q;-><init>()V

    .line 277
    .line 278
    .line 279
    iget-object v8, p0, Lq/k;->e:Lq/s;

    .line 280
    .line 281
    iget-object v9, v8, Lq/s;->h:Lb81/b;

    .line 282
    .line 283
    if-nez v9, :cond_14

    .line 284
    .line 285
    new-instance v9, Lb81/b;

    .line 286
    .line 287
    new-instance v10, Lq/p;

    .line 288
    .line 289
    invoke-direct {v10, v8}, Lq/p;-><init>(Lq/s;)V

    .line 290
    .line 291
    .line 292
    invoke-direct {v9, v10}, Lb81/b;-><init>(Lq/p;)V

    .line 293
    .line 294
    .line 295
    iput-object v9, v8, Lq/s;->h:Lb81/b;

    .line 296
    .line 297
    :cond_14
    iget-object v8, v8, Lq/s;->h:Lb81/b;

    .line 298
    .line 299
    iget-object v9, v8, Lb81/b;->e:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast v9, Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;

    .line 302
    .line 303
    if-nez v9, :cond_15

    .line 304
    .line 305
    iget-object v9, v8, Lb81/b;->f:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v9, Lq/p;

    .line 308
    .line 309
    invoke-static {v9}, Lq/b;->a(Lq/d;)Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;

    .line 310
    .line 311
    .line 312
    move-result-object v9

    .line 313
    iput-object v9, v8, Lb81/b;->e:Ljava/lang/Object;

    .line 314
    .line 315
    :cond_15
    iget-object v8, v8, Lb81/b;->e:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v8, Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;

    .line 318
    .line 319
    if-nez v6, :cond_16

    .line 320
    .line 321
    :try_start_0
    invoke-static {v0, v5, v7, v8}, Lq/g;->b(Landroid/hardware/biometrics/BiometricPrompt;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V

    .line 322
    .line 323
    .line 324
    return-void

    .line 325
    :catch_0
    move-exception v0

    .line 326
    goto :goto_7

    .line 327
    :cond_16
    invoke-static {v0, v6, v5, v7, v8}, Lq/g;->a(Landroid/hardware/biometrics/BiometricPrompt;Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 328
    .line 329
    .line 330
    return-void

    .line 331
    :goto_7
    const-string v5, "Got NPE while authenticating with biometric prompt."

    .line 332
    .line 333
    invoke-static {v1, v5, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 334
    .line 335
    .line 336
    if-eqz v3, :cond_17

    .line 337
    .line 338
    const v0, 0x7f1201f0

    .line 339
    .line 340
    .line 341
    invoke-virtual {v3, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v4

    .line 345
    :cond_17
    invoke-virtual {p0, v2, v4}, Lq/k;->l(ILjava/lang/CharSequence;)V

    .line 346
    .line 347
    .line 348
    :cond_18
    return-void
.end method

.method public final onActivityResult(IILandroid/content/Intent;)V
    .locals 1

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroidx/fragment/app/j0;->onActivityResult(IILandroid/content/Intent;)V

    .line 2
    .line 3
    .line 4
    const/4 p3, 0x1

    .line 5
    if-ne p1, p3, :cond_1

    .line 6
    .line 7
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p1, Lq/s;->m:Z

    .line 11
    .line 12
    const/4 p1, -0x1

    .line 13
    if-ne p2, p1, :cond_0

    .line 14
    .line 15
    new-instance p1, Lq/n;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    invoke-direct {p1, p2, p3}, Lq/n;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lq/k;->m(Lq/n;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    const p1, 0x7f120369

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    const/16 p2, 0xa

    .line 33
    .line 34
    invoke-virtual {p0, p2, p1}, Lq/k;->l(ILjava/lang/CharSequence;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/j0;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const-string v0, "owner"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    const-string v2, "store"

    .line 33
    .line 34
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v2, "factory"

    .line 38
    .line 39
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string v2, "defaultCreationExtras"

    .line 43
    .line 44
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    new-instance v2, Lcom/google/firebase/messaging/w;

    .line 48
    .line 49
    invoke-direct {v2, v0, v1, p1}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 50
    .line 51
    .line 52
    const-class p1, Lq/s;

    .line 53
    .line 54
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    const-string v0, "modelClass"

    .line 59
    .line 60
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-interface {p1}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    if-eqz v0, :cond_7

    .line 68
    .line 69
    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 70
    .line 71
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {v2, p1, v0}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    check-cast p1, Lq/s;

    .line 80
    .line 81
    iput-object p1, p0, Lq/k;->e:Lq/s;

    .line 82
    .line 83
    iget-object v0, p1, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 84
    .line 85
    if-nez v0, :cond_1

    .line 86
    .line 87
    new-instance v0, Landroidx/lifecycle/i0;

    .line 88
    .line 89
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object v0, p1, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 93
    .line 94
    :cond_1
    iget-object p1, p1, Lq/s;->p:Landroidx/lifecycle/i0;

    .line 95
    .line 96
    new-instance v0, Lq/f;

    .line 97
    .line 98
    const/4 v1, 0x0

    .line 99
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 106
    .line 107
    iget-object v0, p1, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 108
    .line 109
    if-nez v0, :cond_2

    .line 110
    .line 111
    new-instance v0, Landroidx/lifecycle/i0;

    .line 112
    .line 113
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 114
    .line 115
    .line 116
    iput-object v0, p1, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 117
    .line 118
    :cond_2
    iget-object p1, p1, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 119
    .line 120
    new-instance v0, Lq/f;

    .line 121
    .line 122
    const/4 v1, 0x1

    .line 123
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 127
    .line 128
    .line 129
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 130
    .line 131
    iget-object v0, p1, Lq/s;->r:Landroidx/lifecycle/i0;

    .line 132
    .line 133
    if-nez v0, :cond_3

    .line 134
    .line 135
    new-instance v0, Landroidx/lifecycle/i0;

    .line 136
    .line 137
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 138
    .line 139
    .line 140
    iput-object v0, p1, Lq/s;->r:Landroidx/lifecycle/i0;

    .line 141
    .line 142
    :cond_3
    iget-object p1, p1, Lq/s;->r:Landroidx/lifecycle/i0;

    .line 143
    .line 144
    new-instance v0, Lq/f;

    .line 145
    .line 146
    const/4 v1, 0x2

    .line 147
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 151
    .line 152
    .line 153
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 154
    .line 155
    iget-object v0, p1, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 156
    .line 157
    if-nez v0, :cond_4

    .line 158
    .line 159
    new-instance v0, Landroidx/lifecycle/i0;

    .line 160
    .line 161
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 162
    .line 163
    .line 164
    iput-object v0, p1, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 165
    .line 166
    :cond_4
    iget-object p1, p1, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 167
    .line 168
    new-instance v0, Lq/f;

    .line 169
    .line 170
    const/4 v1, 0x3

    .line 171
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 175
    .line 176
    .line 177
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 178
    .line 179
    iget-object v0, p1, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 180
    .line 181
    if-nez v0, :cond_5

    .line 182
    .line 183
    new-instance v0, Landroidx/lifecycle/i0;

    .line 184
    .line 185
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 186
    .line 187
    .line 188
    iput-object v0, p1, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 189
    .line 190
    :cond_5
    iget-object p1, p1, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 191
    .line 192
    new-instance v0, Lq/f;

    .line 193
    .line 194
    const/4 v1, 0x4

    .line 195
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 199
    .line 200
    .line 201
    iget-object p1, p0, Lq/k;->e:Lq/s;

    .line 202
    .line 203
    iget-object v0, p1, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 204
    .line 205
    if-nez v0, :cond_6

    .line 206
    .line 207
    new-instance v0, Landroidx/lifecycle/i0;

    .line 208
    .line 209
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 210
    .line 211
    .line 212
    iput-object v0, p1, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 213
    .line 214
    :cond_6
    iget-object p1, p1, Lq/s;->u:Landroidx/lifecycle/i0;

    .line 215
    .line 216
    new-instance v0, Lq/f;

    .line 217
    .line 218
    const/4 v1, 0x5

    .line 219
    invoke-direct {v0, p0, v1}, Lq/f;-><init>(Lq/k;I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {p1, p0, v0}, Landroidx/lifecycle/g0;->e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 223
    .line 224
    .line 225
    return-void

    .line 226
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 227
    .line 228
    const-string p1, "Local and anonymous classes can not be ViewModels"

    .line 229
    .line 230
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    throw p0
.end method

.method public final onStart()V
    .locals 4

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/j0;->onStart()V

    .line 2
    .line 3
    .line 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 5
    .line 6
    const/16 v1, 0x1d

    .line 7
    .line 8
    if-ne v0, v1, :cond_2

    .line 9
    .line 10
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 11
    .line 12
    iget-object v1, v0, Lq/s;->f:Lil/g;

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    iget-object v0, v0, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/16 v0, 0xf

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/16 v0, 0xff

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 v0, 0x0

    .line 27
    :goto_0
    invoke-static {v0}, Ljp/ge;->a(I)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    iget-object v0, p0, Lq/k;->e:Lq/s;

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    iput-boolean v1, v0, Lq/s;->o:Z

    .line 37
    .line 38
    new-instance v1, Lq/j;

    .line 39
    .line 40
    const/4 v2, 0x2

    .line 41
    invoke-direct {v1, v0, v2}, Lq/j;-><init>(Lq/s;I)V

    .line 42
    .line 43
    .line 44
    const-wide/16 v2, 0xfa

    .line 45
    .line 46
    iget-object p0, p0, Lq/k;->d:Landroid/os/Handler;

    .line 47
    .line 48
    invoke-virtual {p0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 49
    .line 50
    .line 51
    :cond_2
    return-void
.end method
