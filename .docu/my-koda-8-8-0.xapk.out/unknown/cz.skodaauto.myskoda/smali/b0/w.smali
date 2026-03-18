.class public final Lb0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll0/k;


# static fields
.field public static final e:Lh0/g;

.field public static final f:Lh0/g;

.field public static final g:Lh0/g;

.field public static final h:Lh0/g;

.field public static final i:Lh0/g;

.field public static final j:Lh0/g;

.field public static final k:Lh0/g;

.field public static final l:Lh0/g;

.field public static final m:Lh0/g;

.field public static final n:Lh0/g;

.field public static final o:Lh0/g;

.field public static final p:Lh0/g;


# instance fields
.field public final d:Lh0/n1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.appConfig.cameraFactoryProvider"

    .line 4
    .line 5
    const-class v2, Ls/a;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lb0/w;->e:Lh0/g;

    .line 12
    .line 13
    new-instance v0, Lh0/g;

    .line 14
    .line 15
    const-string v1, "camerax.core.appConfig.deviceSurfaceManagerProvider"

    .line 16
    .line 17
    const-class v2, Ls/b;

    .line 18
    .line 19
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lb0/w;->f:Lh0/g;

    .line 23
    .line 24
    new-instance v0, Lh0/g;

    .line 25
    .line 26
    const-string v1, "camerax.core.appConfig.useCaseConfigFactoryProvider"

    .line 27
    .line 28
    const-class v2, Ls/c;

    .line 29
    .line 30
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lb0/w;->g:Lh0/g;

    .line 34
    .line 35
    new-instance v0, Lh0/g;

    .line 36
    .line 37
    const-string v1, "camerax.core.appConfig.cameraExecutor"

    .line 38
    .line 39
    const-class v2, Ljava/util/concurrent/Executor;

    .line 40
    .line 41
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lb0/w;->h:Lh0/g;

    .line 45
    .line 46
    new-instance v0, Lh0/g;

    .line 47
    .line 48
    const-string v1, "camerax.core.appConfig.schedulerHandler"

    .line 49
    .line 50
    const-class v2, Landroid/os/Handler;

    .line 51
    .line 52
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lb0/w;->i:Lh0/g;

    .line 56
    .line 57
    new-instance v0, Lh0/g;

    .line 58
    .line 59
    const-string v1, "camerax.core.appConfig.minimumLoggingLevel"

    .line 60
    .line 61
    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 62
    .line 63
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 64
    .line 65
    .line 66
    sput-object v0, Lb0/w;->j:Lh0/g;

    .line 67
    .line 68
    new-instance v0, Lh0/g;

    .line 69
    .line 70
    const-string v1, "camerax.core.appConfig.availableCamerasLimiter"

    .line 71
    .line 72
    const-class v4, Lb0/r;

    .line 73
    .line 74
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 75
    .line 76
    .line 77
    sput-object v0, Lb0/w;->k:Lh0/g;

    .line 78
    .line 79
    new-instance v0, Lh0/g;

    .line 80
    .line 81
    const-string v1, "camerax.core.appConfig.cameraOpenRetryMaxTimeoutInMillisWhileResuming"

    .line 82
    .line 83
    sget-object v4, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 84
    .line 85
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 86
    .line 87
    .line 88
    sput-object v0, Lb0/w;->l:Lh0/g;

    .line 89
    .line 90
    new-instance v0, Lh0/g;

    .line 91
    .line 92
    const-string v1, "camerax.core.appConfig.cameraProviderInitRetryPolicy"

    .line 93
    .line 94
    const-class v4, Lb0/m1;

    .line 95
    .line 96
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 97
    .line 98
    .line 99
    sput-object v0, Lb0/w;->m:Lh0/g;

    .line 100
    .line 101
    new-instance v0, Lh0/g;

    .line 102
    .line 103
    const-string v1, "camerax.core.appConfig.quirksSettings"

    .line 104
    .line 105
    const-class v4, Lh0/q1;

    .line 106
    .line 107
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 108
    .line 109
    .line 110
    sput-object v0, Lb0/w;->n:Lh0/g;

    .line 111
    .line 112
    new-instance v0, Lh0/g;

    .line 113
    .line 114
    const-string v1, "camerax.core.appConfig.configImplType"

    .line 115
    .line 116
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 117
    .line 118
    .line 119
    sput-object v0, Lb0/w;->o:Lh0/g;

    .line 120
    .line 121
    new-instance v0, Lh0/g;

    .line 122
    .line 123
    const-string v1, "camerax.core.appConfig.repeatingStreamForced"

    .line 124
    .line 125
    sget-object v2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 126
    .line 127
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 128
    .line 129
    .line 130
    sput-object v0, Lb0/w;->p:Lh0/g;

    .line 131
    .line 132
    return-void
.end method

.method public constructor <init>(Lh0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb0/w;->d:Lh0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Lb0/r;
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 2
    .line 3
    sget-object v0, Lb0/w;->k:Lh0/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lb0/r;

    .line 11
    .line 12
    return-object p0
.end method

.method public final c()Ls/a;
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 2
    .line 3
    sget-object v0, Lb0/w;->e:Lh0/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ls/a;

    .line 11
    .line 12
    return-object p0
.end method

.method public final h()J
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 8
    .line 9
    sget-object v1, Lb0/w;->l:Lh0/g;

    .line 10
    .line 11
    invoke-virtual {p0, v1, v0}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Long;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    return-wide v0
.end method

.method public final m()Ls/b;
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 2
    .line 3
    sget-object v0, Lb0/w;->f:Lh0/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ls/b;

    .line 11
    .line 12
    return-object p0
.end method

.method public final n()Ls/c;
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 2
    .line 3
    sget-object v0, Lb0/w;->g:Lh0/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ls/c;

    .line 11
    .line 12
    return-object p0
.end method

.method public final p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/w;->d:Lh0/n1;

    .line 2
    .line 3
    return-object p0
.end method
