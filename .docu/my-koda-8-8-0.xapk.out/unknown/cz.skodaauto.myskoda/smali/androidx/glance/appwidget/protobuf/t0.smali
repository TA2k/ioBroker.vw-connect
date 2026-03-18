.class public final Landroidx/glance/appwidget/protobuf/t0;
.super Landroidx/glance/appwidget/protobuf/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/RandomAccess;


# static fields
.field public static final g:Landroidx/glance/appwidget/protobuf/t0;


# instance fields
.field public e:[Ljava/lang/Object;

.field public f:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroidx/glance/appwidget/protobuf/t0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0, v2, v1, v1}, Landroidx/glance/appwidget/protobuf/t0;-><init>([Ljava/lang/Object;IZ)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Landroidx/glance/appwidget/protobuf/t0;->g:Landroidx/glance/appwidget/protobuf/t0;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>([Ljava/lang/Object;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractList;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p3, p0, Landroidx/glance/appwidget/protobuf/b;->d:Z

    .line 5
    .line 6
    iput-object p1, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p2, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 5

    .line 8
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/b;->c()V

    if-ltz p1, :cond_1

    .line 9
    iget v0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    if-gt p1, v0, :cond_1

    .line 10
    iget-object v1, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    array-length v2, v1

    const/4 v3, 0x1

    if-ge v0, v2, :cond_0

    add-int/lit8 v2, p1, 0x1

    sub-int/2addr v0, p1

    .line 11
    invoke-static {v1, p1, v1, v2, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    goto :goto_0

    :cond_0
    const/4 v2, 0x3

    const/4 v4, 0x2

    .line 12
    invoke-static {v0, v2, v4, v3}, La7/g0;->x(IIII)I

    move-result v0

    .line 13
    new-array v0, v0, [Ljava/lang/Object;

    const/4 v2, 0x0

    .line 14
    invoke-static {v1, v2, v0, v2, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 15
    iget-object v1, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    add-int/lit8 v2, p1, 0x1

    iget v4, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    sub-int/2addr v4, p1

    invoke-static {v1, p1, v0, v2, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    iput-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 17
    :goto_0
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    aput-object p2, v0, p1

    .line 18
    iget p1, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    add-int/2addr p1, v3

    iput p1, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 19
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    add-int/2addr p1, v3

    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    return-void

    .line 20
    :cond_1
    new-instance p2, Ljava/lang/IndexOutOfBoundsException;

    .line 21
    const-string v0, "Index:"

    const-string v1, ", Size:"

    .line 22
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    .line 23
    iget p0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 24
    invoke-direct {p2, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/b;->c()V

    .line 2
    iget v0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    iget-object v1, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    array-length v2, v1

    const/4 v3, 0x1

    if-ne v0, v2, :cond_0

    mul-int/lit8 v0, v0, 0x3

    .line 3
    div-int/lit8 v0, v0, 0x2

    add-int/2addr v0, v3

    .line 4
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    .line 5
    iput-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 6
    :cond_0
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    iget v1, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    add-int/lit8 v2, v1, 0x1

    iput v2, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    aput-object p1, v0, v1

    .line 7
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    add-int/2addr p1, v3

    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    return v3
.end method

.method public final e(I)V
    .locals 3

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 9
    .line 10
    const-string v1, "Index:"

    .line 11
    .line 12
    const-string v2, ", Size:"

    .line 13
    .line 14
    invoke-static {v1, p1, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget p0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public final g(I)Landroidx/glance/appwidget/protobuf/t0;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 2
    .line 3
    if-lt p1, v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 6
    .line 7
    invoke-static {v0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance v0, Landroidx/glance/appwidget/protobuf/t0;

    .line 12
    .line 13
    iget p0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, p1, p0, v1}, Landroidx/glance/appwidget/protobuf/t0;-><init>([Ljava/lang/Object;IZ)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/t0;->e(I)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 5
    .line 6
    aget-object p0, p0, p1

    .line 7
    .line 8
    return-object p0
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/b;->c()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/t0;->e(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 8
    .line 9
    aget-object v1, v0, p1

    .line 10
    .line 11
    iget v2, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 12
    .line 13
    add-int/lit8 v3, v2, -0x1

    .line 14
    .line 15
    if-ge p1, v3, :cond_0

    .line 16
    .line 17
    add-int/lit8 v3, p1, 0x1

    .line 18
    .line 19
    sub-int/2addr v2, p1

    .line 20
    add-int/lit8 v2, v2, -0x1

    .line 21
    .line 22
    invoke-static {v0, v3, v0, p1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget p1, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 26
    .line 27
    add-int/lit8 p1, p1, -0x1

    .line 28
    .line 29
    iput p1, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 30
    .line 31
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 32
    .line 33
    add-int/lit8 p1, p1, 0x1

    .line 34
    .line 35
    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 36
    .line 37
    return-object v1
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/b;->c()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/t0;->e(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Landroidx/glance/appwidget/protobuf/t0;->e:[Ljava/lang/Object;

    .line 8
    .line 9
    aget-object v1, v0, p1

    .line 10
    .line 11
    aput-object p2, v0, p1

    .line 12
    .line 13
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 18
    .line 19
    return-object v1
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/glance/appwidget/protobuf/t0;->f:I

    .line 2
    .line 3
    return p0
.end method
