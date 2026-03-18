.class public final synthetic Lkw/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/p;


# instance fields
.field public final synthetic a:Lkw/n;


# direct methods
.method public synthetic constructor <init>(Lkw/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkw/o;->a:Lkw/n;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Landroid/graphics/RectF;)F
    .locals 1

    .line 1
    const-string v0, "horizontalDimensions"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bounds"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lkw/o;->a:Lkw/n;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2, p3}, Lkw/n;->a(Lkw/g;Lkw/i;Landroid/graphics/RectF;)F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-virtual {p2, p1}, Lkw/i;->c(Lkw/g;)F

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    const/4 v0, 0x0

    .line 22
    cmpg-float v0, p1, v0

    .line 23
    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    const/high16 p1, 0x3f800000    # 1.0f

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p3}, Landroid/graphics/RectF;->width()F

    .line 30
    .line 31
    .line 32
    move-result p3

    .line 33
    iget v0, p2, Lkw/i;->d:F

    .line 34
    .line 35
    iget p2, p2, Lkw/i;->e:F

    .line 36
    .line 37
    add-float/2addr v0, p2

    .line 38
    sub-float/2addr p3, v0

    .line 39
    div-float p1, p3, p1

    .line 40
    .line 41
    :goto_0
    invoke-static {p0, p1}, Ljava/lang/Math;->max(FF)F

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0
.end method
