.class public final synthetic Li91/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lt3/e1;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Lt3/e1;

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(FLt3/e1;IIILt3/e1;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li91/c;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Li91/c;->e:Lt3/e1;

    .line 7
    .line 8
    iput p3, p0, Li91/c;->f:I

    .line 9
    .line 10
    iput p4, p0, Li91/c;->g:I

    .line 11
    .line 12
    iput p5, p0, Li91/c;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Li91/c;->i:Lt3/e1;

    .line 15
    .line 16
    iput p7, p0, Li91/c;->j:I

    .line 17
    .line 18
    iput p8, p0, Li91/c;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

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
    iget v1, p0, Li91/c;->d:F

    .line 10
    .line 11
    cmpg-float v0, v1, v0

    .line 12
    .line 13
    iget v1, p0, Li91/c;->h:I

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget v0, p0, Li91/c;->g:I

    .line 19
    .line 20
    add-int/2addr v0, v1

    .line 21
    iget-object v2, p0, Li91/c;->e:Lt3/e1;

    .line 22
    .line 23
    iget v3, p0, Li91/c;->f:I

    .line 24
    .line 25
    invoke-static {p1, v2, v3, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget v0, p0, Li91/c;->k:I

    .line 29
    .line 30
    add-int/2addr v0, v1

    .line 31
    iget-object v1, p0, Li91/c;->i:Lt3/e1;

    .line 32
    .line 33
    iget p0, p0, Li91/c;->j:I

    .line 34
    .line 35
    invoke-static {p1, v1, p0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
