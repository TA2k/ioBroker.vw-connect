.class public Lcom/google/android/filament/ToneMapper$Agx;
.super Lcom/google/android/filament/ToneMapper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/ToneMapper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Agx"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/ToneMapper$Agx$AgxLook;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/ToneMapper$Agx$AgxLook;->NONE:Lcom/google/android/filament/ToneMapper$Agx$AgxLook;

    invoke-direct {p0, v0}, Lcom/google/android/filament/ToneMapper$Agx;-><init>(Lcom/google/android/filament/ToneMapper$Agx$AgxLook;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/ToneMapper$Agx$AgxLook;)V
    .locals 2

    .line 2
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-static {p1}, Lcom/google/android/filament/ToneMapper;->c(I)J

    move-result-wide v0

    const/4 p1, 0x0

    invoke-direct {p0, v0, v1, p1}, Lcom/google/android/filament/ToneMapper;-><init>(JI)V

    return-void
.end method
