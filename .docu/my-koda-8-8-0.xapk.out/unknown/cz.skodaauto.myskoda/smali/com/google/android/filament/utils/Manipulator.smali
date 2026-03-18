.class public Lcom/google/android/filament/utils/Manipulator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Manipulator$Mode;,
        Lcom/google/android/filament/utils/Manipulator$Key;,
        Lcom/google/android/filament/utils/Manipulator$Builder;,
        Lcom/google/android/filament/utils/Manipulator$Fov;
    }
.end annotation


# static fields
.field private static final sModeValues:[Lcom/google/android/filament/utils/Manipulator$Mode;


# instance fields
.field private final mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Manipulator$Mode;->values()[Lcom/google/android/filament/utils/Manipulator$Mode;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/utils/Manipulator;->sModeValues:[Lcom/google/android/filament/utils/Manipulator$Mode;

    .line 6
    .line 7
    return-void
.end method

.method private constructor <init>(J)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;-><init>(J)V

    return-void
.end method

.method public static bridge synthetic a(IJ)J
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/utils/Manipulator;->nBuilderBuild(JI)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFarPlane(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightMaxMoveSpeed(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightMoveDamping(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightPanSpeed(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightSpeedSteps(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightStartOrientation(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFlightStartPosition(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFovDegrees(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic j(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/utils/Manipulator;->nBuilderFovDirection(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k(JFFFF)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lcom/google/android/filament/utils/Manipulator;->nBuilderGroundPlane(JFFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic l(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nBuilderMapExtent(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic m(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderMapMinDistance(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic n(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Manipulator;->nBuilderOrbitHomePosition(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JI)J
.end method

.method private static native nBuilderFarPlane(JF)V
.end method

.method private static native nBuilderFlightMaxMoveSpeed(JF)V
.end method

.method private static native nBuilderFlightMoveDamping(JF)V
.end method

.method private static native nBuilderFlightPanSpeed(JFF)V
.end method

.method private static native nBuilderFlightSpeedSteps(JI)V
.end method

.method private static native nBuilderFlightStartOrientation(JFF)V
.end method

.method private static native nBuilderFlightStartPosition(JFFF)V
.end method

.method private static native nBuilderFovDegrees(JF)V
.end method

.method private static native nBuilderFovDirection(JI)V
.end method

.method private static native nBuilderGroundPlane(JFFFF)V
.end method

.method private static native nBuilderMapExtent(JFF)V
.end method

.method private static native nBuilderMapMinDistance(JF)V
.end method

.method private static native nBuilderOrbitHomePosition(JFFF)V
.end method

.method private static native nBuilderOrbitSpeed(JFF)V
.end method

.method private static native nBuilderPanning(JLjava/lang/Boolean;)V
.end method

.method private static native nBuilderTargetPosition(JFFF)V
.end method

.method private static native nBuilderUpVector(JFFF)V
.end method

.method private static native nBuilderViewport(JII)V
.end method

.method private static native nBuilderZoomSpeed(JF)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nDestroyManipulator(J)V
.end method

.method private static native nGetCurrentBookmark(J)J
.end method

.method private static native nGetHomeBookmark(J)J
.end method

.method private static native nGetLookAtDouble(J[D[D[D)V
.end method

.method private static native nGetLookAtFloat(J[F[F[F)V
.end method

.method private static native nGetMode(J)I
.end method

.method private static native nGrabBegin(JIIZ)V
.end method

.method private static native nGrabEnd(J)V
.end method

.method private static native nGrabUpdate(JII)V
.end method

.method private static native nJumpToBookmark(JJ)V
.end method

.method private static native nKeyDown(JI)V
.end method

.method private static native nKeyUp(JI)V
.end method

.method private static native nRaycast(JII[F)V
.end method

.method private static native nScroll(JIIF)V
.end method

.method private static native nSetViewport(JII)V
.end method

.method private static native nUpdate(JF)V
.end method

.method public static bridge synthetic o(JFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nBuilderOrbitSpeed(JFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic p(JLjava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderPanning(JLjava/lang/Boolean;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic q(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Manipulator;->nBuilderTargetPosition(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic r(JFFF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Manipulator;->nBuilderUpVector(JFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic s(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nBuilderViewport(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic t(JF)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nBuilderZoomSpeed(JF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic u()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Manipulator;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic v(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/Manipulator;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public finalize()V
    .locals 2

    .line 1
    :try_start_0
    invoke-super {p0}, Ljava/lang/Object;->finalize()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2
    .line 3
    .line 4
    :catchall_0
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 5
    .line 6
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/Manipulator;->nDestroyManipulator(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public getCurrentBookmark()Lcom/google/android/filament/utils/Bookmark;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bookmark;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/utils/Manipulator;->nGetCurrentBookmark(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Bookmark;-><init>(J)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public getHomeBookmark()Lcom/google/android/filament/utils/Bookmark;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bookmark;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/utils/Manipulator;->nGetHomeBookmark(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Bookmark;-><init>(J)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public getLookAt([D[D[D)V
    .locals 2

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nGetLookAtDouble(J[D[D[D)V

    return-void
.end method

.method public getLookAt([F[F[F)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nGetLookAtFloat(J[F[F[F)V

    return-void
.end method

.method public getMode()Lcom/google/android/filament/utils/Manipulator$Mode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/Manipulator;->sModeValues:[Lcom/google/android/filament/utils/Manipulator$Mode;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/utils/Manipulator;->nGetMode(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public grabBegin(IIZ)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nGrabBegin(JIIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public grabEnd()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/Manipulator;->nGrabEnd(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public grabUpdate(II)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nGrabUpdate(JII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public jumpToBookmark(Lcom/google/android/filament/utils/Bookmark;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Bookmark;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/utils/Manipulator;->nJumpToBookmark(JJ)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public keyDown(Lcom/google/android/filament/utils/Manipulator$Key;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/utils/Manipulator;->nKeyDown(JI)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public keyUp(Lcom/google/android/filament/utils/Manipulator$Key;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/utils/Manipulator;->nKeyUp(JI)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public raycast(II)[F
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [F

    .line 3
    .line 4
    iget-wide v1, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 5
    .line 6
    invoke-static {v1, v2, p1, p2, v0}, Lcom/google/android/filament/utils/Manipulator;->nRaycast(JII[F)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public scroll(IIF)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/utils/Manipulator;->nScroll(JIIF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setViewport(II)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->nSetViewport(JII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public update(F)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Manipulator;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/utils/Manipulator;->nUpdate(JF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
