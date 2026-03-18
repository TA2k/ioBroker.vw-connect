.class public final synthetic Lh2/ea;
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

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Lt3/e1;ILt3/e1;IILt3/e1;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/ea;->d:Lt3/e1;

    .line 5
    .line 6
    iput p2, p0, Lh2/ea;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lh2/ea;->f:Lt3/e1;

    .line 9
    .line 10
    iput p4, p0, Lh2/ea;->g:I

    .line 11
    .line 12
    iput p5, p0, Lh2/ea;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Lh2/ea;->i:Lt3/e1;

    .line 15
    .line 16
    iput p7, p0, Lh2/ea;->j:I

    .line 17
    .line 18
    iput p8, p0, Lh2/ea;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    iget-object v1, p0, Lh2/ea;->d:Lt3/e1;

    .line 5
    .line 6
    iget v2, p0, Lh2/ea;->e:I

    .line 7
    .line 8
    invoke-static {p1, v1, v0, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lh2/ea;->f:Lt3/e1;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget v1, p0, Lh2/ea;->g:I

    .line 16
    .line 17
    iget v2, p0, Lh2/ea;->h:I

    .line 18
    .line 19
    invoke-static {p1, v0, v1, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 20
    .line 21
    .line 22
    :cond_0
    iget-object v0, p0, Lh2/ea;->i:Lt3/e1;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    iget v1, p0, Lh2/ea;->j:I

    .line 27
    .line 28
    iget p0, p0, Lh2/ea;->k:I

    .line 29
    .line 30
    invoke-static {p1, v0, v1, p0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 31
    .line 32
    .line 33
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0
.end method
