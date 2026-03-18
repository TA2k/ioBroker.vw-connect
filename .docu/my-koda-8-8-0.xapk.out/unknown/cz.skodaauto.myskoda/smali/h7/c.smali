.class public final Lh7/c;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public e:Lrx/b;

.field public f:Lxy0/z;

.field public g:Lxy0/c;

.field public synthetic h:Ljava/lang/Object;

.field public i:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lh7/c;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lh7/c;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lh7/c;->i:I

    .line 9
    .line 10
    invoke-static {p0}, Llp/n0;->b(Lrx0/c;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
