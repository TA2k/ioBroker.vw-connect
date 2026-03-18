.class public final Lzb/g0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public e:I

.field public f:Lay0/k;

.field public g:Lkotlin/jvm/internal/d0;

.field public synthetic h:Ljava/lang/Object;

.field public i:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lzb/g0;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lzb/g0;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lzb/g0;->i:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-static {p1, v0, p0}, Lzb/b;->s(ILay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p1, Llx0/o;

    .line 22
    .line 23
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-object p1
.end method
