.class public final Lh0/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/o2;
.implements Lh0/a1;
.implements Ll0/h;


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


# instance fields
.field public final d:Lh0/n1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.imageCapture.captureMode"

    .line 4
    .line 5
    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lh0/y0;->e:Lh0/g;

    .line 12
    .line 13
    new-instance v0, Lh0/g;

    .line 14
    .line 15
    const-string v1, "camerax.core.imageCapture.flashMode"

    .line 16
    .line 17
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lh0/y0;->f:Lh0/g;

    .line 21
    .line 22
    new-instance v0, Lh0/g;

    .line 23
    .line 24
    const-string v1, "camerax.core.imageCapture.bufferFormat"

    .line 25
    .line 26
    const-class v4, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lh0/y0;->g:Lh0/g;

    .line 32
    .line 33
    new-instance v0, Lh0/g;

    .line 34
    .line 35
    const-string v1, "camerax.core.imageCapture.outputFormat"

    .line 36
    .line 37
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lh0/y0;->h:Lh0/g;

    .line 41
    .line 42
    new-instance v0, Lh0/g;

    .line 43
    .line 44
    const-string v1, "camerax.core.imageCapture.imageReaderProxyProvider"

    .line 45
    .line 46
    const-class v4, Lb0/b1;

    .line 47
    .line 48
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Lh0/y0;->i:Lh0/g;

    .line 52
    .line 53
    new-instance v0, Lh0/g;

    .line 54
    .line 55
    const-string v1, "camerax.core.imageCapture.useSoftwareJpegEncoder"

    .line 56
    .line 57
    sget-object v4, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 58
    .line 59
    invoke-direct {v0, v1, v4, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lh0/y0;->j:Lh0/g;

    .line 63
    .line 64
    new-instance v0, Lh0/g;

    .line 65
    .line 66
    const-string v1, "camerax.core.imageCapture.flashType"

    .line 67
    .line 68
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lh0/y0;->k:Lh0/g;

    .line 72
    .line 73
    new-instance v0, Lh0/g;

    .line 74
    .line 75
    const-string v1, "camerax.core.imageCapture.screenFlash"

    .line 76
    .line 77
    const-class v2, Lb0/s0;

    .line 78
    .line 79
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 80
    .line 81
    .line 82
    sput-object v0, Lh0/y0;->l:Lh0/g;

    .line 83
    .line 84
    new-instance v0, Lh0/g;

    .line 85
    .line 86
    const-string v1, "camerax.core.useCase.isPostviewEnabled"

    .line 87
    .line 88
    const-class v2, Ljava/lang/Boolean;

    .line 89
    .line 90
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 91
    .line 92
    .line 93
    sput-object v0, Lh0/y0;->m:Lh0/g;

    .line 94
    .line 95
    return-void
.end method

.method public constructor <init>(Lh0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/y0;->d:Lh0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final l()I
    .locals 1

    .line 1
    sget-object v0, Lh0/z0;->C0:Lh0/g;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/y0;->d:Lh0/n1;

    .line 2
    .line 3
    return-object p0
.end method
