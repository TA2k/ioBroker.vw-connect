.class public final Lb3/a;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:I

.field public final synthetic i:Z


# direct methods
.method public constructor <init>(FFIZ)V
    .locals 0

    .line 1
    iput p1, p0, Lb3/a;->f:F

    .line 2
    .line 3
    iput p2, p0, Lb3/a;->g:F

    .line 4
    .line 5
    iput p3, p0, Lb3/a;->h:I

    .line 6
    .line 7
    iput-boolean p4, p0, Lb3/a;->i:Z

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Le3/k0;

    .line 2
    .line 3
    iget-object v0, p1, Le3/k0;->u:Lt4/c;

    .line 4
    .line 5
    invoke-interface {v0}, Lt4/c;->a()F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget v1, p0, Lb3/a;->f:F

    .line 10
    .line 11
    mul-float/2addr v0, v1

    .line 12
    iget-object v1, p1, Le3/k0;->u:Lt4/c;

    .line 13
    .line 14
    invoke-interface {v1}, Lt4/c;->a()F

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    iget v2, p0, Lb3/a;->g:F

    .line 19
    .line 20
    mul-float/2addr v1, v2

    .line 21
    const/4 v2, 0x0

    .line 22
    cmpl-float v3, v0, v2

    .line 23
    .line 24
    if-lez v3, :cond_0

    .line 25
    .line 26
    cmpl-float v2, v1, v2

    .line 27
    .line 28
    if-lez v2, :cond_0

    .line 29
    .line 30
    new-instance v2, Le3/o;

    .line 31
    .line 32
    iget v3, p0, Lb3/a;->h:I

    .line 33
    .line 34
    invoke-direct {v2, v0, v1, v3}, Le3/o;-><init>(FFI)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v2, 0x0

    .line 39
    :goto_0
    invoke-virtual {p1, v2}, Le3/k0;->f(Le3/o;)V

    .line 40
    .line 41
    .line 42
    sget-object v0, Le3/j0;->a:Le3/i0;

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Le3/k0;->w(Le3/n0;)V

    .line 45
    .line 46
    .line 47
    iget-boolean p0, p0, Lb3/a;->i:Z

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Le3/k0;->d(Z)V

    .line 50
    .line 51
    .line 52
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object p0
.end method
