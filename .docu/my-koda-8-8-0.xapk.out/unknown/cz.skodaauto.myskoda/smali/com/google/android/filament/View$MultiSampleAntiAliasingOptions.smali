.class public Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "MultiSampleAntiAliasingOptions"
.end annotation


# instance fields
.field public customResolve:Z

.field public enabled:Z

.field public sampleCount:I


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->enabled:Z

    .line 6
    .line 7
    const/4 v1, 0x4

    .line 8
    iput v1, p0, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->sampleCount:I

    .line 9
    .line 10
    iput-boolean v0, p0, Lcom/google/android/filament/View$MultiSampleAntiAliasingOptions;->customResolve:Z

    .line 11
    .line 12
    return-void
.end method
