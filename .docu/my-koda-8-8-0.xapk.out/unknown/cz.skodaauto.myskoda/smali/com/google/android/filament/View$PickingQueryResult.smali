.class public Lcom/google/android/filament/View$PickingQueryResult;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "PickingQueryResult"
.end annotation


# instance fields
.field public depth:F

.field public fragCoords:[F

.field public renderable:I
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x3

    .line 5
    new-array v0, v0, [F

    .line 6
    .line 7
    iput-object v0, p0, Lcom/google/android/filament/View$PickingQueryResult;->fragCoords:[F

    .line 8
    .line 9
    return-void
.end method
