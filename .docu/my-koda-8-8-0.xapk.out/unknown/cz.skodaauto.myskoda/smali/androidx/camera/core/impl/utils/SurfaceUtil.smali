.class public abstract Landroidx/camera/core/impl/utils/SurfaceUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "surface_util_jni"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static a(Landroid/view/Surface;)Ldv/a;
    .locals 2

    .line 1
    invoke-static {p0}, Landroidx/camera/core/impl/utils/SurfaceUtil;->nativeGetSurfaceInfo(Landroid/view/Surface;)[I

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ldv/a;

    .line 6
    .line 7
    const/4 v1, 0x7

    .line 8
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    aget v1, p0, v1

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    aget v1, p0, v1

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    aget p0, p0, v1

    .line 19
    .line 20
    return-object v0
.end method

.method private static native nativeGetSurfaceInfo(Landroid/view/Surface;)[I
.end method
