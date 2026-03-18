.class public Lcom/google/android/filament/NativeSurface;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final mHeight:I

.field private final mNativeObject:J

.field private final mWidth:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/google/android/filament/NativeSurface;->mWidth:I

    .line 5
    .line 6
    iput p2, p0, Lcom/google/android/filament/NativeSurface;->mHeight:I

    .line 7
    .line 8
    invoke-static {p1, p2}, Lcom/google/android/filament/NativeSurface;->nCreateSurface(II)J

    .line 9
    .line 10
    .line 11
    move-result-wide p1

    .line 12
    iput-wide p1, p0, Lcom/google/android/filament/NativeSurface;->mNativeObject:J

    .line 13
    .line 14
    return-void
.end method

.method private static native nCreateSurface(II)J
.end method

.method private static native nDestroySurface(J)V
.end method


# virtual methods
.method public dispose()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/NativeSurface;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/NativeSurface;->nDestroySurface(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getHeight()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/NativeSurface;->mHeight:I

    .line 2
    .line 3
    return p0
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/NativeSurface;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getWidth()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/NativeSurface;->mWidth:I

    .line 2
    .line 3
    return p0
.end method
