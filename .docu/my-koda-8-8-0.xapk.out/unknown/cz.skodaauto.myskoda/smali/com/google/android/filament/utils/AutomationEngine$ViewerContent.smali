.class public Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/AutomationEngine;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ViewerContent"
.end annotation


# instance fields
.field public assetLights:[I
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation
.end field

.field public indirectLight:Lcom/google/android/filament/IndirectLight;

.field public lightManager:Lcom/google/android/filament/LightManager;

.field public materials:[Lcom/google/android/filament/MaterialInstance;

.field public renderer:Lcom/google/android/filament/Renderer;

.field public scene:Lcom/google/android/filament/Scene;

.field public sunlight:I
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation
.end field

.field public view:Lcom/google/android/filament/View;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
