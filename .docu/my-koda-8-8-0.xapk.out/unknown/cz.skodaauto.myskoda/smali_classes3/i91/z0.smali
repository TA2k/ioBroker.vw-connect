.class public final synthetic Li91/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt3/e1;

.field public final synthetic e:I

.field public final synthetic f:Lt3/e1;

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Lt3/e1;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Lt3/e1;ILt3/e1;IILt3/e1;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/z0;->d:Lt3/e1;

    .line 5
    .line 6
    iput p2, p0, Li91/z0;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Li91/z0;->f:Lt3/e1;

    .line 9
    .line 10
    iput p4, p0, Li91/z0;->g:I

    .line 11
    .line 12
    iput p5, p0, Li91/z0;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Li91/z0;->i:Lt3/e1;

    .line 15
    .line 16
    iput p7, p0, Li91/z0;->j:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

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
    const/4 v0, 0x0

    .line 9
    iget-object v1, p0, Li91/z0;->d:Lt3/e1;

    .line 10
    .line 11
    iget v2, p0, Li91/z0;->e:I

    .line 12
    .line 13
    invoke-static {p1, v1, v0, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Li91/z0;->f:Lt3/e1;

    .line 17
    .line 18
    iget v1, p0, Li91/z0;->g:I

    .line 19
    .line 20
    iget v2, p0, Li91/z0;->h:I

    .line 21
    .line 22
    invoke-static {p1, v0, v1, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Li91/z0;->i:Lt3/e1;

    .line 26
    .line 27
    iget p0, p0, Li91/z0;->j:I

    .line 28
    .line 29
    invoke-static {p1, v0, v1, p0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
