.class public final Lv0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lv0/f;


# instance fields
.field public final a:Lcom/google/android/material/datepicker/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lv0/f;

    .line 2
    .line 3
    new-instance v1, Lcom/google/android/material/datepicker/d;

    .line 4
    .line 5
    invoke-direct {v1}, Lcom/google/android/material/datepicker/d;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, v1}, Lv0/f;-><init>(Lcom/google/android/material/datepicker/d;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lv0/f;->b:Lv0/f;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/datepicker/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv0/f;->a:Lcom/google/android/material/datepicker/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final varargs a(Landroidx/lifecycle/x;Lb0/r;[Lb0/z1;)V
    .locals 2

    .line 1
    const-string v0, "lifecycleOwner"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "cameraSelector"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lv0/f;->a:Lcom/google/android/material/datepicker/d;

    .line 12
    .line 13
    array-length v0, p3

    .line 14
    invoke-static {p3, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    check-cast p3, [Lb0/z1;

    .line 19
    .line 20
    const-string v0, "useCases"

    .line 21
    .line 22
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v0, "CX:bindToLifecycle"

    .line 26
    .line 27
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :try_start_0
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lb0/u;

    .line 37
    .line 38
    if-nez v0, :cond_0

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-object v0, v0, Lb0/u;->g:Lu/n;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    iget-object v0, v0, Lu/n;->b:Lz/a;

    .line 47
    .line 48
    invoke-virtual {v0}, Lz/a;->b()I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    :goto_0
    const/4 v1, 0x2

    .line 53
    if-eq v0, v1, :cond_1

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-static {p0, v0}, Lcom/google/android/material/datepicker/d;->c(Lcom/google/android/material/datepicker/d;I)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lb0/d1;

    .line 60
    .line 61
    invoke-static {p3}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 62
    .line 63
    .line 64
    move-result-object p3

    .line 65
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 66
    .line 67
    invoke-direct {v0, p3, v1}, Lb0/d1;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 68
    .line 69
    .line 70
    invoke-static {p0, p1, p2, v0}, Lcom/google/android/material/datepicker/d;->e(Lcom/google/android/material/datepicker/d;Landroidx/lifecycle/x;Lb0/r;Lb0/d1;)Lv0/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    .line 72
    .line 73
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_1
    :try_start_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 78
    .line 79
    const-string p1, "bindToLifecycle for single camera is not supported in concurrent camera mode, call unbindAll() first"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :catchall_0
    move-exception p0

    .line 86
    goto :goto_1

    .line 87
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    const-string p1, "CameraX not initialized yet."

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 95
    :goto_1
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 96
    .line 97
    .line 98
    throw p0
.end method
