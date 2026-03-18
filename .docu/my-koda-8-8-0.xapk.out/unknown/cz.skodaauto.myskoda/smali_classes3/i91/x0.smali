.class public final synthetic Li91/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt3/e1;

.field public final synthetic e:Lt3/e1;

.field public final synthetic f:I

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lt3/e1;Lt3/e1;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/x0;->d:Lt3/e1;

    .line 5
    .line 6
    iput-object p2, p0, Li91/x0;->e:Lt3/e1;

    .line 7
    .line 8
    iput p3, p0, Li91/x0;->f:I

    .line 9
    .line 10
    iput p4, p0, Li91/x0;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

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
    iget-object v0, p0, Li91/x0;->d:Lt3/e1;

    .line 9
    .line 10
    iget v1, v0, Lt3/e1;->d:I

    .line 11
    .line 12
    if-lez v1, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-static {p1, v0, v1, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget v0, v0, Lt3/e1;->d:I

    .line 19
    .line 20
    iget v1, p0, Li91/x0;->f:I

    .line 21
    .line 22
    add-int/2addr v0, v1

    .line 23
    iget-object v1, p0, Li91/x0;->e:Lt3/e1;

    .line 24
    .line 25
    iget p0, p0, Li91/x0;->g:I

    .line 26
    .line 27
    invoke-static {p1, v1, v0, p0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
