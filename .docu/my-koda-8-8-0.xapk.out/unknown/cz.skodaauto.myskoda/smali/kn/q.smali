.class public final Lkn/q;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lkotlin/jvm/internal/n;

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:J

.field public final synthetic j:Lx2/d;

.field public final synthetic k:Lt3/s0;

.field public final synthetic l:Lkn/m0;

.field public final synthetic m:Lt3/e1;


# direct methods
.method public constructor <init>(Lay0/k;IIJLx2/d;Lt3/s0;Lkn/m0;Lt3/e1;)V
    .locals 0

    .line 1
    check-cast p1, Lkotlin/jvm/internal/n;

    .line 2
    .line 3
    iput-object p1, p0, Lkn/q;->f:Lkotlin/jvm/internal/n;

    .line 4
    .line 5
    iput p2, p0, Lkn/q;->g:I

    .line 6
    .line 7
    iput p3, p0, Lkn/q;->h:I

    .line 8
    .line 9
    iput-wide p4, p0, Lkn/q;->i:J

    .line 10
    .line 11
    iput-object p6, p0, Lkn/q;->j:Lx2/d;

    .line 12
    .line 13
    iput-object p7, p0, Lkn/q;->k:Lt3/s0;

    .line 14
    .line 15
    iput-object p8, p0, Lkn/q;->l:Lkn/m0;

    .line 16
    .line 17
    iput-object p9, p0, Lkn/q;->m:Lt3/e1;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    const-string v0, "$this$layout"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lkn/q;->g:I

    .line 9
    .line 10
    iget v1, p0, Lkn/q;->h:I

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkp/f9;->a(II)J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    new-instance v4, Lt4/l;

    .line 17
    .line 18
    invoke-direct {v4, v2, v3}, Lt4/l;-><init>(J)V

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lkn/q;->f:Lkotlin/jvm/internal/n;

    .line 22
    .line 23
    invoke-interface {v2, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Ljava/lang/Number;

    .line 28
    .line 29
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    iget-wide v3, p0, Lkn/q;->i:J

    .line 34
    .line 35
    invoke-static {v3, v4}, Lt4/a;->g(J)I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    sub-int/2addr v5, v1

    .line 40
    add-int/2addr v5, v2

    .line 41
    invoke-static {v3, v4}, Lt4/a;->h(J)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-object v2, p0, Lkn/q;->k:Lt3/s0;

    .line 46
    .line 47
    invoke-interface {v2}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-object v3, p0, Lkn/q;->j:Lx2/d;

    .line 52
    .line 53
    invoke-interface {v3, v0, v1, v2}, Lx2/d;->a(IILt4/m;)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    iget-object v1, p0, Lkn/q;->l:Lkn/m0;

    .line 58
    .line 59
    iput v0, v1, Lkn/m0;->b:I

    .line 60
    .line 61
    iput v5, v1, Lkn/m0;->c:I

    .line 62
    .line 63
    iget-object p0, p0, Lkn/q;->m:Lt3/e1;

    .line 64
    .line 65
    invoke-static {p1, p0, v0, v5}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 66
    .line 67
    .line 68
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    return-object p0
.end method
