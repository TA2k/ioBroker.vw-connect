.class public Lcom/google/android/filament/Box;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final mCenter:[F

.field private final mHalfExtent:[F


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x3

    .line 2
    new-array v1, v0, [F

    iput-object v1, p0, Lcom/google/android/filament/Box;->mCenter:[F

    .line 3
    new-array v0, v0, [F

    iput-object v0, p0, Lcom/google/android/filament/Box;->mHalfExtent:[F

    return-void
.end method

.method public constructor <init>(FFFFFF)V
    .locals 2

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x3

    .line 5
    new-array v1, v0, [F

    iput-object v1, p0, Lcom/google/android/filament/Box;->mCenter:[F

    .line 6
    new-array v0, v0, [F

    iput-object v0, p0, Lcom/google/android/filament/Box;->mHalfExtent:[F

    const/4 p0, 0x0

    .line 7
    aput p1, v1, p0

    const/4 p1, 0x1

    .line 8
    aput p2, v1, p1

    const/4 p2, 0x2

    .line 9
    aput p3, v1, p2

    .line 10
    aput p4, v0, p0

    .line 11
    aput p5, v0, p1

    .line 12
    aput p6, v0, p2

    return-void
.end method

.method public constructor <init>([F[F)V
    .locals 4

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x3

    .line 14
    new-array v1, v0, [F

    iput-object v1, p0, Lcom/google/android/filament/Box;->mCenter:[F

    .line 15
    new-array v0, v0, [F

    iput-object v0, p0, Lcom/google/android/filament/Box;->mHalfExtent:[F

    const/4 p0, 0x0

    .line 16
    aget v2, p1, p0

    aput v2, v1, p0

    const/4 v2, 0x1

    .line 17
    aget v3, p1, v2

    aput v3, v1, v2

    const/4 v3, 0x2

    .line 18
    aget p1, p1, v3

    aput p1, v1, v3

    .line 19
    aget p1, p2, p0

    aput p1, v0, p0

    .line 20
    aget p0, p2, v2

    aput p0, v0, v2

    .line 21
    aget p0, p2, v3

    aput p0, v0, v3

    return-void
.end method


# virtual methods
.method public getCenter()[F
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Box;->mCenter:[F

    .line 2
    .line 3
    return-object p0
.end method

.method public getHalfExtent()[F
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Box;->mHalfExtent:[F

    .line 2
    .line 3
    return-object p0
.end method

.method public setCenter(FFF)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Box;->mCenter:[F

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aput p1, p0, v0

    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    aput p2, p0, p1

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    aput p3, p0, p1

    .line 11
    .line 12
    return-void
.end method

.method public setHalfExtent(FFF)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Box;->mHalfExtent:[F

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aput p1, p0, v0

    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    aput p2, p0, p1

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    aput p3, p0, p1

    .line 11
    .line 12
    return-void
.end method
