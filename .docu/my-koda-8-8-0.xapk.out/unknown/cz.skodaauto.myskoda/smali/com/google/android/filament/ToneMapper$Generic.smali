.class public Lcom/google/android/filament/ToneMapper$Generic;
.super Lcom/google/android/filament/ToneMapper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/ToneMapper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Generic"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 4

    const v0, 0x3e5c28f6    # 0.215f

    const/high16 v1, 0x41200000    # 10.0f

    const v2, 0x3fc66666    # 1.55f

    const v3, 0x3e3851ec    # 0.18f

    .line 1
    invoke-direct {p0, v2, v3, v0, v1}, Lcom/google/android/filament/ToneMapper$Generic;-><init>(FFFF)V

    return-void
.end method

.method public constructor <init>(FFFF)V
    .locals 0

    .line 2
    invoke-static {p1, p2, p3, p4}, Lcom/google/android/filament/ToneMapper;->e(FFFF)J

    move-result-wide p1

    const/4 p3, 0x0

    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/ToneMapper;-><init>(JI)V

    return-void
.end method


# virtual methods
.method public getContrast()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/ToneMapper;->h(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getHdrMax()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/ToneMapper;->i(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getMidGrayIn()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/ToneMapper;->j(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getMidGrayOut()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/ToneMapper;->k(J)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setContrast(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ToneMapper;->l(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setHdrMax(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ToneMapper;->m(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setMidGrayIn(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ToneMapper;->n(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setMidGrayOut(F)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/ToneMapper;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/ToneMapper;->o(JF)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
