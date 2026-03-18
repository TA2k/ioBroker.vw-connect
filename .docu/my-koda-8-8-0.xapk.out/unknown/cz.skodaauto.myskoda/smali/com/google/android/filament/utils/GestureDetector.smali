.class public final Lcom/google/android/filament/utils/GestureDetector;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/GestureDetector$Gesture;,
        Lcom/google/android/filament/utils/GestureDetector$TouchPair;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000V\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0010\u0007\n\u0002\u0008\u0005\u0018\u00002\u00020\u0001:\u0002)*B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\u0008H\u0002\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u000bH\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u000bH\u0002\u00a2\u0006\u0004\u0008\u000e\u0010\rJ\u000f\u0010\u000f\u001a\u00020\u000bH\u0002\u00a2\u0006\u0004\u0008\u000f\u0010\rJ\u0015\u0010\u0012\u001a\u00020\u00082\u0006\u0010\u0011\u001a\u00020\u0010\u00a2\u0006\u0004\u0008\u0012\u0010\u0013R\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u0014R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010\u0015R\u0016\u0010\u0017\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0017\u0010\u0018R\u0016\u0010\u001a\u001a\u00020\u00198\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u001a\u0010\u001bR\u001a\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u00190\u001c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001d\u0010\u001eR\u001a\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u00190\u001c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001f\u0010\u001eR\u001a\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u00190\u001c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008 \u0010\u001eR\u0014\u0010\"\u001a\u00020!8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008\"\u0010#R\u0014\u0010$\u001a\u00020!8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008$\u0010#R\u0014\u0010%\u001a\u00020!8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008%\u0010#R\u0014\u0010\'\u001a\u00020&8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\'\u0010(\u00a8\u0006+"
    }
    d2 = {
        "Lcom/google/android/filament/utils/GestureDetector;",
        "",
        "Landroid/view/View;",
        "view",
        "Lcom/google/android/filament/utils/Manipulator;",
        "manipulator",
        "<init>",
        "(Landroid/view/View;Lcom/google/android/filament/utils/Manipulator;)V",
        "Llx0/b0;",
        "endGesture",
        "()V",
        "",
        "isOrbitGesture",
        "()Z",
        "isPanGesture",
        "isZoomGesture",
        "Landroid/view/MotionEvent;",
        "event",
        "onTouchEvent",
        "(Landroid/view/MotionEvent;)V",
        "Landroid/view/View;",
        "Lcom/google/android/filament/utils/Manipulator;",
        "Lcom/google/android/filament/utils/GestureDetector$Gesture;",
        "currentGesture",
        "Lcom/google/android/filament/utils/GestureDetector$Gesture;",
        "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
        "previousTouch",
        "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
        "Ljava/util/ArrayList;",
        "tentativePanEvents",
        "Ljava/util/ArrayList;",
        "tentativeOrbitEvents",
        "tentativeZoomEvents",
        "",
        "kGestureConfidenceCount",
        "I",
        "kPanConfidenceDistance",
        "kZoomConfidenceDistance",
        "",
        "kZoomSpeed",
        "F",
        "Gesture",
        "TouchPair",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

.field private final kGestureConfidenceCount:I

.field private final kPanConfidenceDistance:I

.field private final kZoomConfidenceDistance:I

.field private final kZoomSpeed:F

.field private final manipulator:Lcom/google/android/filament/utils/Manipulator;

.field private previousTouch:Lcom/google/android/filament/utils/GestureDetector$TouchPair;

.field private final tentativeOrbitEvents:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
            ">;"
        }
    .end annotation
.end field

.field private final tentativePanEvents:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
            ">;"
        }
    .end annotation
.end field

.field private final tentativeZoomEvents:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lcom/google/android/filament/utils/GestureDetector$TouchPair;",
            ">;"
        }
    .end annotation
.end field

.field private final view:Landroid/view/View;


# direct methods
.method public constructor <init>(Landroid/view/View;Lcom/google/android/filament/utils/Manipulator;)V
    .locals 1

    .line 1
    const-string v0, "view"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "manipulator"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->view:Landroid/view/View;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 17
    .line 18
    sget-object p1, Lcom/google/android/filament/utils/GestureDetector$Gesture;->NONE:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 19
    .line 20
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 21
    .line 22
    new-instance p1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 23
    .line 24
    invoke-direct {p1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->previousTouch:Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 28
    .line 29
    new-instance p1, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 35
    .line 36
    new-instance p1, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeOrbitEvents:Ljava/util/ArrayList;

    .line 42
    .line 43
    new-instance p1, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 49
    .line 50
    const/4 p1, 0x2

    .line 51
    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector;->kGestureConfidenceCount:I

    .line 52
    .line 53
    const/4 p1, 0x4

    .line 54
    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector;->kPanConfidenceDistance:I

    .line 55
    .line 56
    const/16 p1, 0xa

    .line 57
    .line 58
    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector;->kZoomConfidenceDistance:I

    .line 59
    .line 60
    const p1, 0x3dcccccd    # 0.1f

    .line 61
    .line 62
    .line 63
    iput p1, p0, Lcom/google/android/filament/utils/GestureDetector;->kZoomSpeed:F

    .line 64
    .line 65
    return-void
.end method

.method private final endGesture()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeOrbitEvents:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 14
    .line 15
    .line 16
    sget-object v0, Lcom/google/android/filament/utils/GestureDetector$Gesture;->NONE:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 17
    .line 18
    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 19
    .line 20
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 21
    .line 22
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Manipulator;->grabEnd()V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method private final isOrbitGesture()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeOrbitEvents:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector;->kGestureConfidenceCount:I

    .line 8
    .line 9
    if-le v0, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method private final isPanGesture()Z
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lcom/google/android/filament/utils/GestureDetector;->kGestureConfidenceCount:I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-gt v0, v1, :cond_0

    .line 11
    .line 12
    return v2

    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getMidpoint()Lcom/google/android/filament/utils/Float2;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 32
    .line 33
    invoke-virtual {v1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getMidpoint()Lcom/google/android/filament/utils/Float2;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v3, Lcom/google/android/filament/utils/Float2;

    .line 38
    .line 39
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    sub-float/2addr v4, v5

    .line 48
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    sub-float/2addr v0, v1

    .line 57
    invoke-direct {v3, v4, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    mul-float/2addr v1, v0

    .line 69
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    mul-float/2addr v3, v0

    .line 78
    add-float/2addr v3, v1

    .line 79
    float-to-double v0, v3

    .line 80
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 81
    .line 82
    .line 83
    move-result-wide v0

    .line 84
    double-to-float v0, v0

    .line 85
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector;->kPanConfidenceDistance:I

    .line 86
    .line 87
    int-to-float p0, p0

    .line 88
    cmpl-float p0, v0, p0

    .line 89
    .line 90
    if-lez p0, :cond_1

    .line 91
    .line 92
    const/4 p0, 0x1

    .line 93
    return p0

    .line 94
    :cond_1
    return v2
.end method

.method private final isZoomGesture()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lcom/google/android/filament/utils/GestureDetector;->kGestureConfidenceCount:I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-gt v0, v1, :cond_0

    .line 11
    .line 12
    return v2

    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getSeparation()F

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 32
    .line 33
    invoke-virtual {v1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getSeparation()F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    sub-float/2addr v1, v0

    .line 38
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget p0, p0, Lcom/google/android/filament/utils/GestureDetector;->kZoomConfidenceDistance:I

    .line 43
    .line 44
    int-to-float p0, p0

    .line 45
    cmpl-float p0, v0, p0

    .line 46
    .line 47
    if-lez p0, :cond_1

    .line 48
    .line 49
    const/4 p0, 0x1

    .line 50
    return p0

    .line 51
    :cond_1
    return v2
.end method


# virtual methods
.method public final onTouchEvent(Landroid/view/MotionEvent;)V
    .locals 6

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 7
    .line 8
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->view:Landroid/view/View;

    .line 9
    .line 10
    invoke-virtual {v1}, Landroid/view/View;->getHeight()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-direct {v0, p1, v1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;-><init>(Landroid/view/MotionEvent;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x1

    .line 22
    if-eq v1, v2, :cond_c

    .line 23
    .line 24
    const/4 v3, 0x2

    .line 25
    if-eq v1, v3, :cond_0

    .line 26
    .line 27
    const/4 p1, 0x3

    .line 28
    if-eq v1, p1, :cond_c

    .line 29
    .line 30
    goto/16 :goto_0

    .line 31
    .line 32
    :cond_0
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eq v1, v2, :cond_1

    .line 37
    .line 38
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 39
    .line 40
    sget-object v4, Lcom/google/android/filament/utils/GestureDetector$Gesture;->ORBIT:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 41
    .line 42
    if-eq v1, v4, :cond_3

    .line 43
    .line 44
    :cond_1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eq v1, v3, :cond_2

    .line 49
    .line 50
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 51
    .line 52
    sget-object v4, Lcom/google/android/filament/utils/GestureDetector$Gesture;->PAN:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 53
    .line 54
    if-eq v1, v4, :cond_3

    .line 55
    .line 56
    :cond_2
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eq v1, v3, :cond_4

    .line 61
    .line 62
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 63
    .line 64
    sget-object v4, Lcom/google/android/filament/utils/GestureDetector$Gesture;->ZOOM:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 65
    .line 66
    if-ne v1, v4, :cond_4

    .line 67
    .line 68
    :cond_3
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector;->endGesture()V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_4
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 73
    .line 74
    sget-object v4, Lcom/google/android/filament/utils/GestureDetector$Gesture;->ZOOM:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 75
    .line 76
    if-ne v1, v4, :cond_5

    .line 77
    .line 78
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->previousTouch:Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 79
    .line 80
    invoke-virtual {p1}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getSeparation()F

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getSeparation()F

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    iget-object v2, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 89
    .line 90
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getX()I

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getY()I

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    sub-float/2addr p1, v1

    .line 99
    iget v1, p0, Lcom/google/android/filament/utils/GestureDetector;->kZoomSpeed:F

    .line 100
    .line 101
    mul-float/2addr p1, v1

    .line 102
    invoke-virtual {v2, v3, v4, p1}, Lcom/google/android/filament/utils/Manipulator;->scroll(IIF)V

    .line 103
    .line 104
    .line 105
    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->previousTouch:Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 106
    .line 107
    return-void

    .line 108
    :cond_5
    sget-object v5, Lcom/google/android/filament/utils/GestureDetector$Gesture;->NONE:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 109
    .line 110
    if-eq v1, v5, :cond_6

    .line 111
    .line 112
    iget-object p0, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 113
    .line 114
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getX()I

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getY()I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    invoke-virtual {p0, p1, v0}, Lcom/google/android/filament/utils/Manipulator;->grabUpdate(II)V

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    :cond_6
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-ne v1, v2, :cond_7

    .line 131
    .line 132
    iget-object v1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeOrbitEvents:Ljava/util/ArrayList;

    .line 133
    .line 134
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    :cond_7
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    if-ne p1, v3, :cond_8

    .line 142
    .line 143
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativePanEvents:Ljava/util/ArrayList;

    .line 144
    .line 145
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->tentativeZoomEvents:Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    :cond_8
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector;->isOrbitGesture()Z

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    if-eqz p1, :cond_9

    .line 158
    .line 159
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 160
    .line 161
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getX()I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getY()I

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    const/4 v2, 0x0

    .line 170
    invoke-virtual {p1, v1, v0, v2}, Lcom/google/android/filament/utils/Manipulator;->grabBegin(IIZ)V

    .line 171
    .line 172
    .line 173
    sget-object p1, Lcom/google/android/filament/utils/GestureDetector$Gesture;->ORBIT:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 174
    .line 175
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 176
    .line 177
    return-void

    .line 178
    :cond_9
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector;->isZoomGesture()Z

    .line 179
    .line 180
    .line 181
    move-result p1

    .line 182
    if-eqz p1, :cond_a

    .line 183
    .line 184
    iput-object v4, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 185
    .line 186
    iput-object v0, p0, Lcom/google/android/filament/utils/GestureDetector;->previousTouch:Lcom/google/android/filament/utils/GestureDetector$TouchPair;

    .line 187
    .line 188
    return-void

    .line 189
    :cond_a
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector;->isPanGesture()Z

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    if-eqz p1, :cond_b

    .line 194
    .line 195
    iget-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->manipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 196
    .line 197
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getX()I

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    invoke-virtual {v0}, Lcom/google/android/filament/utils/GestureDetector$TouchPair;->getY()I

    .line 202
    .line 203
    .line 204
    move-result v0

    .line 205
    invoke-virtual {p1, v1, v0, v2}, Lcom/google/android/filament/utils/Manipulator;->grabBegin(IIZ)V

    .line 206
    .line 207
    .line 208
    sget-object p1, Lcom/google/android/filament/utils/GestureDetector$Gesture;->PAN:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 209
    .line 210
    iput-object p1, p0, Lcom/google/android/filament/utils/GestureDetector;->currentGesture:Lcom/google/android/filament/utils/GestureDetector$Gesture;

    .line 211
    .line 212
    :cond_b
    :goto_0
    return-void

    .line 213
    :cond_c
    invoke-direct {p0}, Lcom/google/android/filament/utils/GestureDetector;->endGesture()V

    .line 214
    .line 215
    .line 216
    return-void
.end method
