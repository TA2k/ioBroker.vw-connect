.class public final Lmx0/d;
.super Lmx0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/RandomAccess;


# instance fields
.field public final d:Lmx0/e;

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(Lmx0/e;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmx0/d;->d:Lmx0/e;

    .line 5
    .line 6
    iput p2, p0, Lmx0/d;->e:I

    .line 7
    .line 8
    invoke-virtual {p1}, Lmx0/a;->c()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-static {p2, p3, p1}, Landroidx/glance/appwidget/protobuf/f1;->b(III)V

    .line 13
    .line 14
    .line 15
    sub-int/2addr p3, p2

    .line 16
    iput p3, p0, Lmx0/d;->f:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lmx0/d;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lmx0/d;->f:I

    .line 2
    .line 3
    if-ltz p1, :cond_0

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lmx0/d;->e:I

    .line 8
    .line 9
    add-int/2addr v0, p1

    .line 10
    iget-object p0, p0, Lmx0/d;->d:Lmx0/e;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 18
    .line 19
    const-string v1, "index: "

    .line 20
    .line 21
    const-string v2, ", size: "

    .line 22
    .line 23
    invoke-static {v1, v2, p1, v0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    .line 1
    iget v0, p0, Lmx0/d;->f:I

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Landroidx/glance/appwidget/protobuf/f1;->b(III)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lmx0/d;

    .line 7
    .line 8
    iget v1, p0, Lmx0/d;->e:I

    .line 9
    .line 10
    add-int/2addr p1, v1

    .line 11
    add-int/2addr v1, p2

    .line 12
    iget-object p0, p0, Lmx0/d;->d:Lmx0/e;

    .line 13
    .line 14
    invoke-direct {v0, p0, p1, v1}, Lmx0/d;-><init>(Lmx0/e;II)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method
