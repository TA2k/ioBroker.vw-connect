.class public Lcom/google/android/filament/View$RenderQuality;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "RenderQuality"
.end annotation


# instance fields
.field public hdrColorBuffer:Lcom/google/android/filament/View$QualityLevel;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/android/filament/View$QualityLevel;->HIGH:Lcom/google/android/filament/View$QualityLevel;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/filament/View$RenderQuality;->hdrColorBuffer:Lcom/google/android/filament/View$QualityLevel;

    .line 7
    .line 8
    return-void
.end method
