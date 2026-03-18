.class public Lcom/google/android/filament/SwapChain;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mNativeObject:J

.field private final mSurface:Ljava/lang/Object;


# direct methods
.method public constructor <init>(JLjava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/SwapChain;->mNativeObject:J

    .line 5
    .line 6
    iput-object p3, p0, Lcom/google/android/filament/SwapChain;->mSurface:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public static isProtectedContentSupported(Lcom/google/android/filament/Engine;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/SwapChain;->nIsProtectedContentSupported(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static isSRGBSwapChainSupported(Lcom/google/android/filament/Engine;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/SwapChain;->nIsSRGBSwapChainSupported(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method private static native nIsProtectedContentSupported(J)Z
.end method

.method private static native nIsSRGBSwapChainSupported(J)Z
.end method

.method private static native nSetFrameCompletedCallback(JLjava/lang/Object;Ljava/lang/Runnable;)V
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/SwapChain;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/SwapChain;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Calling method on destroyed SwapChain"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getNativeWindow()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/SwapChain;->mSurface:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public setFrameCompletedCallback(Ljava/lang/Object;Ljava/lang/Runnable;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/SwapChain;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/SwapChain;->nSetFrameCompletedCallback(JLjava/lang/Object;Ljava/lang/Runnable;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
