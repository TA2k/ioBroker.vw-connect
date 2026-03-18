.class public final synthetic Lh2/k9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt3/e1;

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Lt3/e1;

.field public final synthetic h:I

.field public final synthetic i:Lkotlin/jvm/internal/d0;


# direct methods
.method public synthetic constructor <init>(Lt3/e1;IILt3/e1;ILkotlin/jvm/internal/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/k9;->d:Lt3/e1;

    .line 5
    .line 6
    iput p2, p0, Lh2/k9;->e:I

    .line 7
    .line 8
    iput p3, p0, Lh2/k9;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Lh2/k9;->g:Lt3/e1;

    .line 11
    .line 12
    iput p5, p0, Lh2/k9;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Lh2/k9;->i:Lkotlin/jvm/internal/d0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/k9;->d:Lt3/e1;

    .line 4
    .line 5
    iget v1, p0, Lh2/k9;->e:I

    .line 6
    .line 7
    iget v2, p0, Lh2/k9;->f:I

    .line 8
    .line 9
    invoke-static {p1, v0, v1, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lh2/k9;->i:Lkotlin/jvm/internal/d0;

    .line 13
    .line 14
    iget v0, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 15
    .line 16
    iget-object v1, p0, Lh2/k9;->g:Lt3/e1;

    .line 17
    .line 18
    iget p0, p0, Lh2/k9;->h:I

    .line 19
    .line 20
    invoke-static {p1, v1, p0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method
