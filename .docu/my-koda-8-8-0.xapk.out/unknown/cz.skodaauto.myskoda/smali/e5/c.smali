.class public final Le5/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le5/d;


# instance fields
.field public a:Z

.field public b:Ljava/lang/String;

.field public c:Ljava/lang/String;

.field public d:F

.field public e:F


# virtual methods
.method public final value()F
    .locals 2

    .line 1
    iget v0, p0, Le5/c;->d:F

    .line 2
    .line 3
    iget v1, p0, Le5/c;->e:F

    .line 4
    .line 5
    cmpl-float v1, v0, v1

    .line 6
    .line 7
    if-ltz v1, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    iput-boolean v1, p0, Le5/c;->a:Z

    .line 11
    .line 12
    :cond_0
    iget-boolean v1, p0, Le5/c;->a:Z

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    const/high16 v1, 0x3f800000    # 1.0f

    .line 17
    .line 18
    add-float/2addr v0, v1

    .line 19
    iput v0, p0, Le5/c;->d:F

    .line 20
    .line 21
    :cond_1
    iget p0, p0, Le5/c;->d:F

    .line 22
    .line 23
    return p0
.end method
