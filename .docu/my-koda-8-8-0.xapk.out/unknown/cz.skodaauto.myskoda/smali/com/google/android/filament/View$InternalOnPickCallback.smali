.class Lcom/google/android/filament/View$InternalOnPickCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "View.cpp"
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "InternalOnPickCallback"
.end annotation


# instance fields
.field mDepth:F
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "View.cpp"
    .end annotation
.end field

.field mFragCoordsX:F
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "View.cpp"
    .end annotation
.end field

.field mFragCoordsY:F
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "View.cpp"
    .end annotation
.end field

.field mFragCoordsZ:F
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "View.cpp"
    .end annotation
.end field

.field private final mPickingQueryResult:Lcom/google/android/filament/View$PickingQueryResult;

.field mRenderable:I
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation

    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "View.cpp"
    .end annotation
.end field

.field private final mUserCallback:Lcom/google/android/filament/View$OnPickCallback;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/View$OnPickCallback;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/android/filament/View$PickingQueryResult;

    .line 5
    .line 6
    invoke-direct {v0}, Lcom/google/android/filament/View$PickingQueryResult;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mPickingQueryResult:Lcom/google/android/filament/View$PickingQueryResult;

    .line 10
    .line 11
    iput-object p1, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mUserCallback:Lcom/google/android/filament/View$OnPickCallback;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mPickingQueryResult:Lcom/google/android/filament/View$PickingQueryResult;

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mRenderable:I

    .line 4
    .line 5
    iput v1, v0, Lcom/google/android/filament/View$PickingQueryResult;->renderable:I

    .line 6
    .line 7
    iget v1, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mDepth:F

    .line 8
    .line 9
    iput v1, v0, Lcom/google/android/filament/View$PickingQueryResult;->depth:F

    .line 10
    .line 11
    iget-object v1, v0, Lcom/google/android/filament/View$PickingQueryResult;->fragCoords:[F

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    iget v3, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mFragCoordsX:F

    .line 15
    .line 16
    aput v3, v1, v2

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    iget v3, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mFragCoordsY:F

    .line 20
    .line 21
    aput v3, v1, v2

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    iget v3, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mFragCoordsZ:F

    .line 25
    .line 26
    aput v3, v1, v2

    .line 27
    .line 28
    iget-object p0, p0, Lcom/google/android/filament/View$InternalOnPickCallback;->mUserCallback:Lcom/google/android/filament/View$OnPickCallback;

    .line 29
    .line 30
    invoke-interface {p0, v0}, Lcom/google/android/filament/View$OnPickCallback;->onPick(Lcom/google/android/filament/View$PickingQueryResult;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method
