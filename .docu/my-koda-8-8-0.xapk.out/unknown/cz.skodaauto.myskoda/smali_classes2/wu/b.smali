.class public final Lwu/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lvy0/x;

.field public final b:Ll2/j1;

.field public final c:Ll2/j1;

.field public final d:Lez0/c;

.field public final e:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 2
    .line 3
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 4
    .line 5
    const-string v1, "ioDispatcher"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lwu/b;->a:Lvy0/x;

    .line 14
    .line 15
    sget-object v0, Lwu/d;->d:Lwu/d;

    .line 16
    .line 17
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lwu/b;->b:Ll2/j1;

    .line 22
    .line 23
    iput-object v0, p0, Lwu/b;->c:Ll2/j1;

    .line 24
    .line 25
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lwu/b;->d:Lez0/c;

    .line 30
    .line 31
    const-string v0, "gmp_git_androidmapscompose_v6.12.1"

    .line 32
    .line 33
    iput-object v0, p0, Lwu/b;->e:Ljava/lang/String;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lwu/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lwu/a;

    .line 7
    .line 8
    iget v1, v0, Lwu/a;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lwu/a;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwu/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lwu/a;-><init>(Lwu/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lwu/a;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwu/a;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    iget-object v6, p0, Lwu/b;->b:Ll2/j1;

    .line 36
    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v4, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    return-object v5

    .line 47
    :catch_0
    move-exception p0

    .line 48
    goto :goto_4

    .line 49
    :catch_1
    move-exception p0

    .line 50
    goto :goto_5

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-object p1, v0, Lwu/a;->e:Lez0/c;

    .line 60
    .line 61
    iget-object v2, v0, Lwu/a;->d:Landroid/content/Context;

    .line 62
    .line 63
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :try_start_2
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    sget-object v2, Lwu/d;->e:Lwu/d;

    .line 75
    .line 76
    if-eq p2, v2, :cond_7

    .line 77
    .line 78
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    sget-object v2, Lwu/d;->f:Lwu/d;

    .line 83
    .line 84
    if-ne p2, v2, :cond_4

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_4
    iget-object p2, p0, Lwu/b;->d:Lez0/c;

    .line 88
    .line 89
    iput-object p1, v0, Lwu/a;->d:Landroid/content/Context;

    .line 90
    .line 91
    iput-object p2, v0, Lwu/a;->e:Lez0/c;

    .line 92
    .line 93
    iput v4, v0, Lwu/a;->h:I

    .line 94
    .line 95
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2
    :try_end_2
    .catch Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 99
    if-ne v2, v1, :cond_5

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_5
    move-object v2, p1

    .line 103
    move-object p1, p2

    .line 104
    :goto_1
    const/4 p2, 0x0

    .line 105
    :try_start_3
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    sget-object v7, Lwu/d;->d:Lwu/d;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 110
    .line 111
    if-eq v4, v7, :cond_6

    .line 112
    .line 113
    :try_start_4
    invoke-interface {p1, p2}, Lez0/a;->d(Ljava/lang/Object;)V
    :try_end_4
    .catch Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 114
    .line 115
    .line 116
    return-object v5

    .line 117
    :cond_6
    :try_start_5
    sget-object v4, Lwu/d;->e:Lwu/d;

    .line 118
    .line 119
    invoke-virtual {v6, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 120
    .line 121
    .line 122
    :try_start_6
    invoke-interface {p1, p2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-object p1, p0, Lwu/b;->a:Lvy0/x;

    .line 126
    .line 127
    new-instance v4, Lwa0/c;

    .line 128
    .line 129
    const/4 v7, 0x4

    .line 130
    invoke-direct {v4, v7, v2, p0, p2}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 131
    .line 132
    .line 133
    iput-object p2, v0, Lwu/a;->d:Landroid/content/Context;

    .line 134
    .line 135
    iput-object p2, v0, Lwu/a;->e:Lez0/c;

    .line 136
    .line 137
    iput v3, v0, Lwu/a;->h:I

    .line 138
    .line 139
    invoke-static {p1, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-ne p0, v1, :cond_7

    .line 144
    .line 145
    :goto_2
    return-object v1

    .line 146
    :catchall_0
    move-exception p0

    .line 147
    invoke-interface {p1, p2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    throw p0
    :try_end_6
    .catch Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0

    .line 151
    :cond_7
    :goto_3
    return-object v5

    .line 152
    :goto_4
    sget-object p1, Lwu/d;->d:Lwu/d;

    .line 153
    .line 154
    invoke-virtual {v6, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    throw p0

    .line 158
    :goto_5
    sget-object p1, Lwu/d;->g:Lwu/d;

    .line 159
    .line 160
    invoke-virtual {v6, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    throw p0
.end method
