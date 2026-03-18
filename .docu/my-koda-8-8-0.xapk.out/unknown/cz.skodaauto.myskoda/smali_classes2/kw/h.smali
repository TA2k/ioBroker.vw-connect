.class public final Lkw/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/g;
.implements Lpw/f;


# instance fields
.field public a:Lay0/k;

.field public final b:Lc2/k;

.field public final c:Landroid/graphics/RectF;

.field public d:F

.field public e:Z

.field public f:Lmw/a;

.field public g:Lmw/m;

.field public h:Z

.field public i:Lkw/f;


# direct methods
.method public constructor <init>(Landroid/graphics/RectF;Lmw/a;Lmw/m;ZLkw/f;Lay0/k;)V
    .locals 2

    .line 1
    const-string v0, "model"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p6, p0, Lkw/h;->a:Lay0/k;

    .line 10
    .line 11
    new-instance p6, Lc2/k;

    .line 12
    .line 13
    const/16 v0, 0x16

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {p6, v0, v1}, Lc2/k;-><init>(IZ)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v0, p6, Lc2/k;->e:Ljava/lang/Object;

    .line 25
    .line 26
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v0, p6, Lc2/k;->f:Ljava/lang/Object;

    .line 32
    .line 33
    iput-object p6, p0, Lkw/h;->b:Lc2/k;

    .line 34
    .line 35
    iput-object p1, p0, Lkw/h;->c:Landroid/graphics/RectF;

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    iput p1, p0, Lkw/h;->d:F

    .line 39
    .line 40
    const/4 p1, 0x1

    .line 41
    iput-boolean p1, p0, Lkw/h;->e:Z

    .line 42
    .line 43
    iput-object p2, p0, Lkw/h;->f:Lmw/a;

    .line 44
    .line 45
    iput-object p3, p0, Lkw/h;->g:Lmw/m;

    .line 46
    .line 47
    iput-boolean p4, p0, Lkw/h;->h:Z

    .line 48
    .line 49
    iput-object p5, p0, Lkw/h;->i:Lkw/f;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 0

    .line 1
    iget p0, p0, Lkw/h;->d:F

    .line 2
    .line 3
    return p0
.end method

.method public final b(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->a:Lay0/k;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final c(F)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkw/h;->a()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-float/2addr p0, p1

    .line 6
    return p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkw/h;->h:Z

    .line 2
    .line 3
    return p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkw/h;->e:Z

    .line 2
    .line 3
    return p0
.end method

.method public final f()Landroid/graphics/RectF;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->c:Landroid/graphics/RectF;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()Lmw/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->f:Lmw/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkw/h;->e()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/high16 p0, 0x3f800000    # 1.0f

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    const/high16 p0, -0x40800000    # -1.0f

    .line 11
    .line 12
    return p0
.end method

.method public final i()Lc2/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->b:Lc2/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Lmw/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->g:Lmw/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(F)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lkw/h;->c(F)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-int p0, p0

    .line 6
    return p0
.end method

.method public final l()Lkw/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw/h;->i:Lkw/f;

    .line 2
    .line 3
    return-object p0
.end method
