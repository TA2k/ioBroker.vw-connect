.class public Lin/v1;
.super Llp/pa;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:F

.field public b:F

.field public final synthetic c:Lin/z1;


# direct methods
.method public constructor <init>(Lin/z1;FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lin/v1;->c:Lin/z1;

    .line 5
    .line 6
    iput p2, p0, Lin/v1;->a:F

    .line 7
    .line 8
    iput p3, p0, Lin/v1;->b:F

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public d(Ljava/lang/String;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lin/v1;->c:Lin/z1;

    .line 2
    .line 3
    invoke-virtual {v0}, Lin/z1;->m0()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lin/x1;

    .line 12
    .line 13
    iget-boolean v2, v1, Lin/x1;->b:Z

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iget-object v2, v0, Lin/z1;->a:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Landroid/graphics/Canvas;

    .line 20
    .line 21
    iget v3, p0, Lin/v1;->a:F

    .line 22
    .line 23
    iget v4, p0, Lin/v1;->b:F

    .line 24
    .line 25
    iget-object v1, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 26
    .line 27
    invoke-virtual {v2, p1, v3, v4, v1}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    iget-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Lin/x1;

    .line 33
    .line 34
    iget-boolean v2, v1, Lin/x1;->c:Z

    .line 35
    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    iget-object v2, v0, Lin/z1;->a:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v2, Landroid/graphics/Canvas;

    .line 41
    .line 42
    iget v3, p0, Lin/v1;->a:F

    .line 43
    .line 44
    iget v4, p0, Lin/v1;->b:F

    .line 45
    .line 46
    iget-object v1, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 47
    .line 48
    invoke-virtual {v2, p1, v3, v4, v1}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    iget v1, p0, Lin/v1;->a:F

    .line 52
    .line 53
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lin/x1;

    .line 56
    .line 57
    iget-object v0, v0, Lin/x1;->d:Landroid/graphics/Paint;

    .line 58
    .line 59
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    add-float/2addr p1, v1

    .line 64
    iput p1, p0, Lin/v1;->a:F

    .line 65
    .line 66
    return-void
.end method
