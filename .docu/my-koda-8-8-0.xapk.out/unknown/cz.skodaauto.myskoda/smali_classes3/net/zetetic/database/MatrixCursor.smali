.class public Lnet/zetetic/database/MatrixCursor;
.super Lnet/zetetic/database/AbstractCursor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/MatrixCursor$RowBuilder;
    }
.end annotation


# instance fields
.field private final columnCount:I

.field private final columnNames:[Ljava/lang/String;

.field private data:[Ljava/lang/Object;

.field private rowCount:I


# direct methods
.method public constructor <init>([Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x10

    .line 6
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/MatrixCursor;-><init>([Ljava/lang/String;I)V

    return-void
.end method

.method public constructor <init>([Ljava/lang/String;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/AbstractCursor;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 3
    iput-object p1, p0, Lnet/zetetic/database/MatrixCursor;->columnNames:[Ljava/lang/String;

    .line 4
    array-length p1, p1

    iput p1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    const/4 v0, 0x1

    if-ge p2, v0, :cond_0

    move p2, v0

    :cond_0
    mul-int/2addr p1, p2

    .line 5
    new-array p1, p1, [Ljava/lang/Object;

    iput-object p1, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    return-void
.end method

.method public static bridge synthetic a(Lnet/zetetic/database/MatrixCursor;)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method private addRow(Ljava/util/ArrayList;I)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "*>;I)V"
        }
    .end annotation

    .line 16
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 17
    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    if-ne v0, v1, :cond_1

    .line 18
    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 19
    iget-object p0, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    add-int v2, p2, v1

    .line 20
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    aput-object v3, p0, v2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void

    .line 21
    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v1, "columnNames.length = "

    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget p0, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p0, ", columnValues.size() = "

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method private ensureCapacity(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    if-le p1, v1, :cond_1

    .line 5
    .line 6
    array-length v1, v0

    .line 7
    mul-int/lit8 v1, v1, 0x2

    .line 8
    .line 9
    if-ge v1, p1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move p1, v1

    .line 13
    :goto_0
    new-array p1, p1, [Ljava/lang/Object;

    .line 14
    .line 15
    iput-object p1, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    .line 16
    .line 17
    array-length p0, v0

    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-static {v0, v1, p1, v1, p0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 20
    .line 21
    .line 22
    :cond_1
    return-void
.end method

.method private get(I)Ljava/lang/Object;
    .locals 3

    .line 1
    if-ltz p1, :cond_2

    .line 2
    .line 3
    iget v0, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_2

    .line 6
    .line 7
    iget v1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 8
    .line 9
    if-ltz v1, :cond_1

    .line 10
    .line 11
    iget v2, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 12
    .line 13
    if-ge v1, v2, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    .line 16
    .line 17
    mul-int/2addr v1, v0

    .line 18
    add-int/2addr v1, p1

    .line 19
    aget-object p0, p0, v1

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance p0, Landroid/database/CursorIndexOutOfBoundsException;

    .line 23
    .line 24
    const-string p1, "After last row."

    .line 25
    .line 26
    invoke-direct {p0, p1}, Landroid/database/CursorIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    new-instance p0, Landroid/database/CursorIndexOutOfBoundsException;

    .line 31
    .line 32
    const-string p1, "Before first row."

    .line 33
    .line 34
    invoke-direct {p0, p1}, Landroid/database/CursorIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    new-instance v0, Landroid/database/CursorIndexOutOfBoundsException;

    .line 39
    .line 40
    const-string v1, "Requested column: "

    .line 41
    .line 42
    const-string v2, ", # of columns: "

    .line 43
    .line 44
    invoke-static {v1, p1, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget p0, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {v0, p0}, Landroid/database/CursorIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0
.end method


# virtual methods
.method public addRow(Ljava/lang/Iterable;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "*>;)V"
        }
    .end annotation

    .line 6
    iget v0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    mul-int/2addr v0, v1

    add-int/2addr v1, v0

    .line 7
    invoke-direct {p0, v1}, Lnet/zetetic/database/MatrixCursor;->ensureCapacity(I)V

    .line 8
    instance-of v2, p1, Ljava/util/ArrayList;

    if-eqz v2, :cond_0

    .line 9
    check-cast p1, Ljava/util/ArrayList;

    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/MatrixCursor;->addRow(Ljava/util/ArrayList;I)V

    return-void

    .line 10
    :cond_0
    iget-object v2, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    .line 11
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    if-eq v0, v1, :cond_1

    add-int/lit8 v4, v0, 0x1

    .line 12
    aput-object v3, v2, v0

    move v0, v4

    goto :goto_0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "columnValues.size() > columnNames.length"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    if-ne v0, v1, :cond_3

    .line 14
    iget p1, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    return-void

    .line 15
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "columnValues.size() < columnNames.length"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public addRow([Ljava/lang/Object;)V
    .locals 3

    .line 1
    array-length v0, p1

    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    if-ne v0, v1, :cond_0

    .line 2
    iget v0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    add-int/lit8 v2, v0, 0x1

    iput v2, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    mul-int/2addr v0, v1

    add-int/2addr v1, v0

    .line 3
    invoke-direct {p0, v1}, Lnet/zetetic/database/MatrixCursor;->ensureCapacity(I)V

    .line 4
    iget-object v1, p0, Lnet/zetetic/database/MatrixCursor;->data:[Ljava/lang/Object;

    iget p0, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    const/4 v2, 0x0

    invoke-static {p1, v2, v1, v0, p0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-void

    .line 5
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "columnNames.length = "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget p0, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p0, ", columnValues.length = "

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    array-length p0, p1

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public fillWindow(ILnet/zetetic/database/CursorWindow;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lnet/zetetic/database/DatabaseUtils;->cursorFillWindow(Landroid/database/Cursor;ILnet/zetetic/database/CursorWindow;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public getColumnNames()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/MatrixCursor;->columnNames:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCount()I
    .locals 0

    .line 1
    iget p0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 2
    .line 3
    return p0
.end method

.method public getDouble(I)D
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const-wide/16 p0, 0x0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    instance-of p1, p0, Ljava/lang/Number;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    check-cast p0, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0

    .line 21
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 26
    .line 27
    .line 28
    move-result-wide p0

    .line 29
    return-wide p0
.end method

.method public getFloat(I)F
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    instance-of p1, p0, Ljava/lang/Number;

    .line 10
    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    check-cast p0, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public getInt(I)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    instance-of p1, p0, Ljava/lang/Number;

    .line 10
    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    check-cast p0, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public getLong(I)J
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const-wide/16 p0, 0x0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    instance-of p1, p0, Ljava/lang/Number;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    check-cast p0, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0

    .line 21
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 26
    .line 27
    .line 28
    move-result-wide p0

    .line 29
    return-wide p0
.end method

.method public getShort(I)S
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    instance-of p1, p0, Ljava/lang/Number;

    .line 10
    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    check-cast p0, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Number;->shortValue()S

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Ljava/lang/Short;->parseShort(Ljava/lang/String;)S

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public getString(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public getType(I)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lnet/zetetic/database/DatabaseUtils;->getTypeOfObject(Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isNull(I)Z
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/MatrixCursor;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public newRow()Lnet/zetetic/database/MatrixCursor$RowBuilder;
    .locals 3

    .line 1
    iget v0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lnet/zetetic/database/MatrixCursor;->rowCount:I

    .line 6
    .line 7
    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    invoke-direct {p0, v0}, Lnet/zetetic/database/MatrixCursor;->ensureCapacity(I)V

    .line 11
    .line 12
    .line 13
    iget v1, p0, Lnet/zetetic/database/MatrixCursor;->columnCount:I

    .line 14
    .line 15
    sub-int v1, v0, v1

    .line 16
    .line 17
    new-instance v2, Lnet/zetetic/database/MatrixCursor$RowBuilder;

    .line 18
    .line 19
    invoke-direct {v2, p0, v1, v0}, Lnet/zetetic/database/MatrixCursor$RowBuilder;-><init>(Lnet/zetetic/database/MatrixCursor;II)V

    .line 20
    .line 21
    .line 22
    return-object v2
.end method

.method public onMove(II)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
