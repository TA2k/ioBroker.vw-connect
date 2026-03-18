.class public final Landroidx/glance/appwidget/protobuf/f;
.super Landroidx/glance/appwidget/protobuf/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:I

.field public final i:I


# direct methods
.method public constructor <init>([BII)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Landroidx/glance/appwidget/protobuf/g;-><init>([B)V

    .line 2
    .line 3
    .line 4
    add-int v0, p2, p3

    .line 5
    .line 6
    array-length p1, p1

    .line 7
    invoke-static {p2, v0, p1}, Landroidx/glance/appwidget/protobuf/g;->e(III)I

    .line 8
    .line 9
    .line 10
    iput p2, p0, Landroidx/glance/appwidget/protobuf/f;->h:I

    .line 11
    .line 12
    iput p3, p0, Landroidx/glance/appwidget/protobuf/f;->i:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final c(I)B
    .locals 3

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    iget v1, p0, Landroidx/glance/appwidget/protobuf/f;->i:I

    .line 4
    .line 5
    sub-int v0, v1, v0

    .line 6
    .line 7
    or-int/2addr v0, p1

    .line 8
    if-gez v0, :cond_1

    .line 9
    .line 10
    if-gez p1, :cond_0

    .line 11
    .line 12
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    const-string v0, "Index < 0: "

    .line 15
    .line 16
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 25
    .line 26
    const-string v0, "Index > length: "

    .line 27
    .line 28
    const-string v2, ", "

    .line 29
    .line 30
    invoke-static {v0, v2, p1, v1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/f;->h:I

    .line 39
    .line 40
    add-int/2addr v0, p1

    .line 41
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/g;->e:[B

    .line 42
    .line 43
    aget-byte p0, p0, v0

    .line 44
    .line 45
    return p0
.end method

.method public final i()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/glance/appwidget/protobuf/f;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public final k(I)B
    .locals 1

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/f;->h:I

    .line 2
    .line 3
    add-int/2addr v0, p1

    .line 4
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/g;->e:[B

    .line 5
    .line 6
    aget-byte p0, p0, v0

    .line 7
    .line 8
    return p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/glance/appwidget/protobuf/f;->i:I

    .line 2
    .line 3
    return p0
.end method
