.class public final Lhg0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final l:Lcom/google/android/gms/location/LocationRequest;


# instance fields
.field public final a:Ldg0/a;

.field public final b:Ltn0/a;

.field public final c:Ltn0/d;

.field public final d:Lgp/a;

.field public final e:Lhg0/b;

.field public final f:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public g:Lvy0/x1;

.field public h:Ljava/lang/ref/WeakReference;

.field public i:Landroid/location/LocationManager;

.field public final j:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public k:Lhg0/e;


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    const/16 v1, 0x64

    .line 2
    .line 3
    invoke-static {v1}, Lpp/k;->a(I)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/gms/location/LocationRequest;

    .line 7
    .line 8
    const-wide/16 v2, 0x0

    .line 9
    .line 10
    const-wide/16 v4, 0xbb8

    .line 11
    .line 12
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 13
    .line 14
    .line 15
    move-result-wide v6

    .line 16
    new-instance v2, Landroid/os/WorkSource;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-direct {v2, v3}, Landroid/os/WorkSource;-><init>(Landroid/os/WorkSource;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v20, v2

    .line 23
    .line 24
    move-object/from16 v21, v3

    .line 25
    .line 26
    move-wide v2, v4

    .line 27
    const-wide v8, 0x7fffffffffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    const-wide v10, 0x7fffffffffffffffL

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    const v12, 0x7fffffff

    .line 38
    .line 39
    .line 40
    const/4 v13, 0x0

    .line 41
    const/4 v14, 0x1

    .line 42
    const-wide/16 v15, 0xbb8

    .line 43
    .line 44
    const/16 v17, 0x0

    .line 45
    .line 46
    move/from16 v18, v17

    .line 47
    .line 48
    move/from16 v19, v17

    .line 49
    .line 50
    invoke-direct/range {v0 .. v21}, Lcom/google/android/gms/location/LocationRequest;-><init>(IJJJJJIFZJIIZLandroid/os/WorkSource;Lgp/g;)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ldg0/a;Ltn0/a;Ltn0/d;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lhg0/g;->a:Ldg0/a;

    .line 5
    .line 6
    iput-object p3, p0, Lhg0/g;->b:Ltn0/a;

    .line 7
    .line 8
    iput-object p4, p0, Lhg0/g;->c:Ltn0/d;

    .line 9
    .line 10
    sget p2, Lpp/d;->a:I

    .line 11
    .line 12
    new-instance v0, Lgp/a;

    .line 13
    .line 14
    sget-object v5, Lko/h;->c:Lko/h;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    sget-object v3, Lgp/a;->n:Lc2/k;

    .line 18
    .line 19
    sget-object v4, Lko/b;->a:Lko/a;

    .line 20
    .line 21
    move-object v1, p1

    .line 22
    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lhg0/g;->d:Lgp/a;

    .line 26
    .line 27
    new-instance p1, Lhg0/b;

    .line 28
    .line 29
    invoke-direct {p1, p0}, Lhg0/b;-><init>(Lhg0/g;)V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lhg0/g;->e:Lhg0/b;

    .line 33
    .line 34
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 35
    .line 36
    const/4 p2, 0x0

    .line 37
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 38
    .line 39
    .line 40
    iput-object p1, p0, Lhg0/g;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 41
    .line 42
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 43
    .line 44
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lhg0/g;->j:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 48
    .line 49
    return-void
.end method

.method public static final a(Lhg0/g;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lhg0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhg0/f;

    .line 7
    .line 8
    iget v1, v0, Lhg0/f;->f:I

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
    iput v1, v0, Lhg0/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhg0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhg0/f;-><init>(Lhg0/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhg0/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhg0/f;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lhg0/f;->f:I

    .line 52
    .line 53
    invoke-virtual {p0, v0}, Lhg0/g;->b(Lrx0/c;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v1, :cond_3

    .line 58
    .line 59
    return-object v1

    .line 60
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    const/4 v0, 0x0

    .line 67
    if-eqz p1, :cond_5

    .line 68
    .line 69
    iget-object p1, p0, Lhg0/g;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    invoke-virtual {p1, v1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_6

    .line 77
    .line 78
    iget-object p1, p0, Lhg0/g;->d:Lgp/a;

    .line 79
    .line 80
    iget-object v1, p0, Lhg0/g;->e:Lhg0/b;

    .line 81
    .line 82
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    if-nez v2, :cond_4

    .line 90
    .line 91
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    const-string v3, "invalid null looper"

    .line 96
    .line 97
    invoke-static {v2, v3}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :cond_4
    const-class v3, Lhg0/b;

    .line 101
    .line 102
    invoke-virtual {v3}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    invoke-static {v2, v1, v3}, Llp/xf;->b(Landroid/os/Looper;Ljava/lang/Object;Ljava/lang/String;)Lis/b;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    new-instance v2, Lcom/google/android/gms/internal/measurement/i4;

    .line 111
    .line 112
    invoke-direct {v2, p1, v1}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Lgp/a;Lis/b;)V

    .line 113
    .line 114
    .line 115
    new-instance v3, Lb81/d;

    .line 116
    .line 117
    const/4 v4, 0x5

    .line 118
    sget-object v5, Lhg0/g;->l:Lcom/google/android/gms/location/LocationRequest;

    .line 119
    .line 120
    invoke-direct {v3, v4, v2, v5}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    invoke-static {}, Lb81/d;->h()Lf8/d;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    iput-object v3, v4, Lf8/d;->f:Ljava/lang/Object;

    .line 128
    .line 129
    iput-object v2, v4, Lf8/d;->g:Ljava/lang/Object;

    .line 130
    .line 131
    iput-object v1, v4, Lf8/d;->h:Ljava/lang/Object;

    .line 132
    .line 133
    const/16 v1, 0x984

    .line 134
    .line 135
    iput v1, v4, Lf8/d;->d:I

    .line 136
    .line 137
    invoke-virtual {v4}, Lf8/d;->r()Lb81/d;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    invoke-virtual {p1, v1}, Lko/i;->c(Lb81/d;)Laq/t;

    .line 142
    .line 143
    .line 144
    new-instance p1, Lh50/p;

    .line 145
    .line 146
    const/16 v1, 0x16

    .line 147
    .line 148
    invoke-direct {p1, v1}, Lh50/p;-><init>(I)V

    .line 149
    .line 150
    .line 151
    invoke-static {v0, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_5
    new-instance p1, Lh50/p;

    .line 156
    .line 157
    const/16 v1, 0x17

    .line 158
    .line 159
    invoke-direct {p1, v1}, Lh50/p;-><init>(I)V

    .line 160
    .line 161
    .line 162
    invoke-static {v0, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 163
    .line 164
    .line 165
    :cond_6
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object p0
.end method


# virtual methods
.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lhg0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhg0/a;

    .line 7
    .line 8
    iget v1, v0, Lhg0/a;->f:I

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
    iput v1, v0, Lhg0/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhg0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhg0/a;-><init>(Lhg0/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhg0/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhg0/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Lun0/a;->e:Lun0/a;

    .line 52
    .line 53
    iput v3, v0, Lhg0/a;->f:I

    .line 54
    .line 55
    iget-object p0, p0, Lhg0/g;->b:Ltn0/a;

    .line 56
    .line 57
    invoke-virtual {p0, p1, v0}, Ltn0/a;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p1, Lun0/b;

    .line 65
    .line 66
    iget-boolean p0, p1, Lun0/b;->b:Z

    .line 67
    .line 68
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method

.method public final c()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    iget-object v2, p0, Lhg0/g;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lhg0/g;->d:Lgp/a;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-class v1, Lhg0/b;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p0, Lhg0/g;->e:Lhg0/b;

    .line 23
    .line 24
    invoke-static {v2, v1}, Llp/xf;->c(Ljava/lang/Object;Ljava/lang/String;)Llo/k;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    const/16 v2, 0x972

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Lko/i;->d(Llo/k;I)Laq/t;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    sget-object v1, Lj0/a;->f:Lj0/a;

    .line 35
    .line 36
    sget-object v2, Lmb/e;->e:Lmb/e;

    .line 37
    .line 38
    invoke-virtual {v0, v1, v2}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 39
    .line 40
    .line 41
    new-instance v0, Lh50/p;

    .line 42
    .line 43
    const/16 v1, 0x18

    .line 44
    .line 45
    invoke-direct {v0, v1}, Lh50/p;-><init>(I)V

    .line 46
    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    invoke-static {v1, p0, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 50
    .line 51
    .line 52
    :cond_0
    return-void
.end method
