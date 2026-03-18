.class public final Lh0/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/o2;
.implements Lh0/a1;
.implements Ll0/l;


# static fields
.field public static final e:Lh0/g;

.field public static final f:Lh0/g;

.field public static final g:Lh0/g;

.field public static final h:Lh0/g;

.field public static final i:Lh0/g;

.field public static final j:Lh0/g;


# instance fields
.field public final d:Lh0/n1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.imageAnalysis.backpressureStrategy"

    .line 4
    .line 5
    const-class v2, Lb0/e0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lh0/x0;->e:Lh0/g;

    .line 12
    .line 13
    new-instance v0, Lh0/g;

    .line 14
    .line 15
    const-string v1, "camerax.core.imageAnalysis.imageQueueDepth"

    .line 16
    .line 17
    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 18
    .line 19
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lh0/x0;->f:Lh0/g;

    .line 23
    .line 24
    new-instance v0, Lh0/g;

    .line 25
    .line 26
    const-string v1, "camerax.core.imageAnalysis.imageReaderProxyProvider"

    .line 27
    .line 28
    const-class v2, Lb0/b1;

    .line 29
    .line 30
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lh0/x0;->g:Lh0/g;

    .line 34
    .line 35
    new-instance v0, Lh0/g;

    .line 36
    .line 37
    const-string v1, "camerax.core.imageAnalysis.outputImageFormat"

    .line 38
    .line 39
    const-class v2, Lb0/h0;

    .line 40
    .line 41
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lh0/x0;->h:Lh0/g;

    .line 45
    .line 46
    new-instance v0, Lh0/g;

    .line 47
    .line 48
    const-string v1, "camerax.core.imageAnalysis.onePixelShiftEnabled"

    .line 49
    .line 50
    const-class v2, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lh0/x0;->i:Lh0/g;

    .line 56
    .line 57
    new-instance v0, Lh0/g;

    .line 58
    .line 59
    const-string v1, "camerax.core.imageAnalysis.outputImageRotationEnabled"

    .line 60
    .line 61
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 62
    .line 63
    .line 64
    sput-object v0, Lh0/x0;->j:Lh0/g;

    .line 65
    .line 66
    return-void
.end method

.method public constructor <init>(Lh0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/x0;->d:Lh0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final l()I
    .locals 0

    .line 1
    const/16 p0, 0x23

    .line 2
    .line 3
    return p0
.end method

.method public final p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/x0;->d:Lh0/n1;

    .line 2
    .line 3
    return-object p0
.end method
