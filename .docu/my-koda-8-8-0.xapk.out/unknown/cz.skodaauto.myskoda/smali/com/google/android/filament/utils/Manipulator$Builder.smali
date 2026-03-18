.class public Lcom/google/android/filament/utils/Manipulator$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/Manipulator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Manipulator$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/utils/Manipulator$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/utils/Manipulator;->u()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/utils/Manipulator$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/utils/Manipulator$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mFinalizer:Lcom/google/android/filament/utils/Manipulator$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/utils/Manipulator$Mode;)Lcom/google/android/filament/utils/Manipulator;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {p0, v0, v1}, Lcom/google/android/filament/utils/Manipulator;->a(IJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long v0, p0, v0

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lcom/google/android/filament/utils/Manipulator;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {v0, p0, p1, v1}, Lcom/google/android/filament/utils/Manipulator;-><init>(JI)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "Couldn\'t create Manipulator"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public farPlane(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->b(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightMaxMoveSpeed(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->c(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightMoveDamping(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->d(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightPanSpeed(FF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->e(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightSpeedSteps(I)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/utils/Manipulator;->f(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightStartOrientation(FF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->g(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public flightStartPosition(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->h(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public fovDegrees(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->i(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public fovDirection(Lcom/google/android/filament/utils/Manipulator$Fov;)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/utils/Manipulator;->j(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public groundPlane(FFFF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    move v2, p1

    .line 4
    move v3, p2

    .line 5
    move v4, p3

    .line 6
    move v5, p4

    .line 7
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/utils/Manipulator;->k(JFFFF)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public mapExtent(FF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->l(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public mapMinDistance(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->m(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public orbitHomePosition(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->n(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public orbitSpeed(FF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->o(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public panning(Ljava/lang/Boolean;)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->p(JLjava/lang/Boolean;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public targetPosition(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->q(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public upVector(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->r(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public viewport(II)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->s(JII)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public zoomSpeed(F)Lcom/google/android/filament/utils/Manipulator$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->t(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
