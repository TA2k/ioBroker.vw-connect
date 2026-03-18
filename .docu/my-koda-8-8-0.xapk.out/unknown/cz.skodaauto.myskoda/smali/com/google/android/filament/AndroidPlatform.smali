.class final Lcom/google/android/filament/AndroidPlatform;
.super Lcom/google/android/filament/Platform;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final LOG_TAG:Ljava/lang/String; = "Filament"

.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Landroid/opengl/EGL14;->eglGetDisplay(I)Landroid/opengl/EGLDisplay;

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/Platform;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getSharedContextNativeHandle(Ljava/lang/Object;)J
    .locals 0

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/AndroidPlatform21;->getSharedContextNativeHandle(Ljava/lang/Object;)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public log(Ljava/lang/String;)V
    .locals 0

    .line 1
    const-string p0, "Filament"

    .line 2
    .line 3
    invoke-static {p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public validateSharedContext(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Landroid/opengl/EGLContext;

    .line 2
    .line 3
    return p0
.end method

.method public validateStreamSource(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Landroid/graphics/SurfaceTexture;

    .line 2
    .line 3
    return p0
.end method

.method public validateSurface(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Landroid/view/Surface;

    .line 2
    .line 3
    return p0
.end method

.method public warn(Ljava/lang/String;)V
    .locals 0

    .line 1
    const-string p0, "Filament"

    .line 2
    .line 3
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    return-void
.end method
