.class public final Lo8/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/i0;


# instance fields
.field public final a:[B


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x1000

    .line 5
    .line 6
    new-array v0, v0, [B

    .line 7
    .line 8
    iput-object v0, p0, Lo8/n;->a:[B

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lw7/p;II)V
    .locals 0

    .line 1
    invoke-virtual {p1, p2}, Lw7/p;->J(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final b(JIIILo8/h0;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lt7/o;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lt7/g;IZ)I
    .locals 1

    .line 1
    iget-object p0, p0, Lo8/n;->a:[B

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {v0, p2}, Ljava/lang/Math;->min(II)I

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-interface {p1, p0, v0, p2}, Lt7/g;->read([BII)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/4 p1, -0x1

    .line 14
    if-ne p0, p1, :cond_1

    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    return p1

    .line 19
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    return p0
.end method
