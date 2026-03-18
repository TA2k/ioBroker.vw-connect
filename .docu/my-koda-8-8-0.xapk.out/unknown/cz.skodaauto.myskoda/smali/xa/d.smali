.class public final Lxa/d;
.super Lxa/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lxa/d;->g:I

    const-string v0, "db"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sql"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0, p1, p2}, Lxa/f;-><init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;)V

    .line 6
    invoke-interface {p1, p2}, Landroidx/sqlite/db/SupportSQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroidx/sqlite/db/SupportSQLiteStatement;

    move-result-object p1

    iput-object p1, p0, Lxa/d;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;Lxa/c;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lxa/d;->g:I

    const-string v0, "db"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sql"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0, p1, p2}, Lxa/f;-><init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;)V

    .line 2
    iput-object p3, p0, Lxa/d;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;Lxa/e;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lxa/d;->g:I

    const-string v0, "db"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sql"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0, p1, p2}, Lxa/f;-><init>(Landroidx/sqlite/db/SupportSQLiteDatabase;Ljava/lang/String;)V

    .line 4
    iput-object p3, p0, Lxa/d;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final bindBlob(I[B)V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x19

    .line 10
    .line 11
    const-string p1, "column index out of range"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 24
    .line 25
    invoke-interface {p0, p1, p2}, Lva/a;->bindBlob(I[B)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lxa/e;

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2}, Lxa/e;->bindBlob(I[B)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bindDouble(ID)V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x19

    .line 10
    .line 11
    const-string p1, "column index out of range"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 24
    .line 25
    invoke-interface {p0, p1, p2, p3}, Lva/a;->bindDouble(ID)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lxa/e;

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2, p3}, Lxa/e;->bindDouble(ID)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bindLong(IJ)V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x19

    .line 10
    .line 11
    const-string p1, "column index out of range"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 24
    .line 25
    invoke-interface {p0, p1, p2, p3}, Lva/a;->bindLong(IJ)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lxa/e;

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2, p3}, Lxa/e;->bindLong(IJ)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bindNull(I)V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x19

    .line 10
    .line 11
    const-string p1, "column index out of range"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Lva/a;->bindNull(I)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lxa/e;

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lxa/e;->bindNull(I)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c0()Z
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lxa/f;->c0()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lxa/e;

    .line 14
    .line 15
    invoke-interface {p0}, Lua/c;->c0()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final close()V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lxa/f;->f:Z

    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object v0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    iput-boolean v0, p0, Lxa/f;->f:Z

    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lxa/e;

    .line 24
    .line 25
    invoke-virtual {p0}, Lxa/e;->close()V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g0(I)Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->g0(I)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getBlob(I)[B
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->getBlob(I)[B

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getColumnCount()I
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lxa/e;

    .line 19
    .line 20
    invoke-virtual {p0}, Lxa/e;->getColumnCount()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getColumnName(I)Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->getColumnName(I)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDouble(I)D
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->getDouble(I)D

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    return-wide p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getLong(I)J
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->getLong(I)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    return-wide p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final isNull(I)Z
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0x15

    .line 10
    .line 11
    const-string p1, "no row"

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 19
    .line 20
    .line 21
    const/16 p0, 0x15

    .line 22
    .line 23
    const-string p1, "no row"

    .line 24
    .line 25
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    throw p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lxa/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lxa/e;->isNull(I)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    return p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public reset()V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lxa/f;->reset()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lxa/e;

    .line 13
    .line 14
    invoke-virtual {p0}, Lxa/e;->reset()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final s0()Z
    .locals 3

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lxa/c;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iget-object p0, p0, Lxa/f;->d:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 15
    .line 16
    if-eqz v0, :cond_4

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    if-eq v0, v1, :cond_3

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    if-eq v0, v1, :cond_2

    .line 23
    .line 24
    const/4 v1, 0x3

    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    if-ne v0, v1, :cond_0

    .line 29
    .line 30
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransactionReadOnly()V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance p0, La8/r0;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransactionNonExclusive()V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransaction()V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->endTransaction()V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_4
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->setTransactionSuccessful()V

    .line 53
    .line 54
    .line 55
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->endTransaction()V

    .line 56
    .line 57
    .line 58
    :goto_0
    const/4 p0, 0x0

    .line 59
    return p0

    .line 60
    :pswitch_0
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 61
    .line 62
    .line 63
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 66
    .line 67
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteStatement;->execute()V

    .line 68
    .line 69
    .line 70
    const/4 p0, 0x0

    .line 71
    return p0

    .line 72
    :pswitch_1
    iget-object v0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v0, Lxa/e;

    .line 75
    .line 76
    invoke-virtual {v0}, Lxa/e;->s0()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    const/4 v2, 0x0

    .line 81
    invoke-virtual {v0, v2}, Lxa/e;->g0(I)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    const-string v2, "wal"

    .line 86
    .line 87
    invoke-virtual {v0, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    iget-object p0, p0, Lxa/f;->d:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 92
    .line 93
    if-eqz v0, :cond_5

    .line 94
    .line 95
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->enableWriteAheadLogging()Z

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_5
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->disableWriteAheadLogging()V

    .line 100
    .line 101
    .line 102
    :goto_1
    return v1

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final w(ILjava/lang/String;)V
    .locals 1

    .line 1
    iget v0, p0, Lxa/d;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p1, "value"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 12
    .line 13
    .line 14
    const/16 p0, 0x19

    .line 15
    .line 16
    const-string p1, "column index out of range"

    .line 17
    .line 18
    invoke-static {p0, p1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    throw p0

    .line 23
    :pswitch_0
    const-string v0, "value"

    .line 24
    .line 25
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lxa/f;->a()V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 34
    .line 35
    invoke-interface {p0, p1, p2}, Lva/a;->bindString(ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_1
    const-string v0, "value"

    .line 40
    .line 41
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lxa/d;->h:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lxa/e;

    .line 47
    .line 48
    invoke-virtual {p0, p1, p2}, Lxa/e;->w(ILjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
