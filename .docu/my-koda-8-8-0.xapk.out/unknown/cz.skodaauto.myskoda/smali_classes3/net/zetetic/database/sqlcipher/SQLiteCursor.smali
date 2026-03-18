.class public Lnet/zetetic/database/sqlcipher/SQLiteCursor;
.super Lnet/zetetic/database/AbstractWindowedCursor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static CURSOR_WINDOW_NEEDS_RECREATED:Z = false

.field private static final DEFAULT_CURSOR_WINDOW_SIZE:I = -0x1

.field static final NO_COUNT:I = -0x1

.field public static PREFERRED_CURSOR_WINDOW_SIZE:I = -0x1

.field static final TAG:Ljava/lang/String; = "SQLiteCursor"


# instance fields
.field private mColumnNameMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private final mColumns:[Ljava/lang/String;

.field private mCount:I

.field private mCursorWindowCapacity:I

.field private final mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

.field private final mEditTable:Ljava/lang/String;

.field private final mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteQuery;)V
    .locals 1

    .line 2
    invoke-direct {p0}, Lnet/zetetic/database/AbstractWindowedCursor;-><init>()V

    const/4 v0, -0x1

    .line 3
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    if-eqz p3, :cond_0

    .line 4
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

    .line 5
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mEditTable:Ljava/lang/String;

    const/4 p1, 0x0

    .line 6
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumnNameMap:Ljava/util/Map;

    .line 7
    iput-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 8
    invoke-virtual {p3}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getColumnNames()[Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumns:[Ljava/lang/String;

    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "query object cannot be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteQuery;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-direct {p0, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteQuery;)V

    return-void
.end method

.method private awc_clearOrCreateWindow(Ljava/lang/String;)V
    .locals 2

    .line 1
    sget v0, Lnet/zetetic/database/CursorWindow;->PREFERRED_CURSOR_WINDOW_SIZE:I

    .line 2
    .line 3
    sget-boolean v1, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->CURSOR_WINDOW_NEEDS_RECREATED:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->awc_closeWindow()V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    sput-boolean v1, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->CURSOR_WINDOW_NEEDS_RECREATED:Z

    .line 12
    .line 13
    :cond_0
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->getWindow()Lnet/zetetic/database/CursorWindow;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    new-instance v1, Lnet/zetetic/database/CursorWindow;

    .line 20
    .line 21
    invoke-direct {v1, p1, v0}, Lnet/zetetic/database/CursorWindow;-><init>(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->setWindow(Lnet/zetetic/database/CursorWindow;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    invoke-virtual {v1}, Lnet/zetetic/database/CursorWindow;->clear()V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method private awc_closeWindow()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->setWindow(Lnet/zetetic/database/CursorWindow;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method private fillWindow(I)V
    .locals 6

    .line 1
    const-string v0, "SQLiteCursor"

    .line 2
    .line 3
    const-string v1, "received count(*) from native_fill_window: "

    .line 4
    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->getDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPath()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-direct {p0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->awc_clearOrCreateWindow(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :try_start_0
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 17
    .line 18
    const/4 v3, -0x1

    .line 19
    const/4 v4, 0x0

    .line 20
    if-ne v2, v3, :cond_1

    .line 21
    .line 22
    invoke-static {p1, v4}, Lnet/zetetic/database/DatabaseUtils;->cursorPickFillWindowStartPosition(II)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 27
    .line 28
    iget-object v4, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 29
    .line 30
    const/4 v5, 0x1

    .line 31
    invoke-virtual {v3, v4, v2, p1, v5}, Lnet/zetetic/database/sqlcipher/SQLiteQuery;->fillWindow(Lnet/zetetic/database/CursorWindow;IIZ)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 36
    .line 37
    iget-object p1, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 38
    .line 39
    invoke-virtual {p1}, Lnet/zetetic/database/CursorWindow;->getNumRows()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCursorWindowCapacity:I

    .line 44
    .line 45
    const/4 p1, 0x3

    .line 46
    invoke-static {v0, p1}, Lnet/zetetic/database/Logger;->isLoggable(Ljava/lang/String;I)Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_0

    .line 51
    .line 52
    new-instance p1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 58
    .line 59
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-static {v0, p1}, Lnet/zetetic/database/Logger;->d(Ljava/lang/String;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :catch_0
    move-exception p1

    .line 71
    goto :goto_0

    .line 72
    :cond_0
    return-void

    .line 73
    :cond_1
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCursorWindowCapacity:I

    .line 74
    .line 75
    invoke-static {p1, v0}, Lnet/zetetic/database/DatabaseUtils;->cursorPickFillWindowStartPosition(II)I

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 80
    .line 81
    iget-object v2, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 82
    .line 83
    invoke-virtual {v1, v2, v0, p1, v4}, Lnet/zetetic/database/sqlcipher/SQLiteQuery;->fillWindow(Lnet/zetetic/database/CursorWindow;IIZ)I
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :goto_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->awc_closeWindow()V

    .line 88
    .line 89
    .line 90
    throw p1
.end method

.method public static resetCursorWindowSize()V
    .locals 1

    .line 1
    const/16 v0, 0x4000

    .line 2
    .line 3
    sput v0, Lnet/zetetic/database/CursorWindow;->PREFERRED_CURSOR_WINDOW_SIZE:I

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    sput-boolean v0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->CURSOR_WINDOW_NEEDS_RECREATED:Z

    .line 7
    .line 8
    return-void
.end method

.method public static setCursorWindowSize(I)V
    .locals 0

    .line 1
    sput p0, Lnet/zetetic/database/CursorWindow;->PREFERRED_CURSOR_WINDOW_SIZE:I

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    sput-boolean p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->CURSOR_WINDOW_NEEDS_RECREATED:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->close()V

    .line 2
    .line 3
    .line 4
    monitor-enter p0

    .line 5
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 6
    .line 7
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

    .line 11
    .line 12
    invoke-interface {v0}, Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;->cursorClosed()V

    .line 13
    .line 14
    .line 15
    monitor-exit p0

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception v0

    .line 18
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw v0
.end method

.method public deactivate()V
    .locals 0

    .line 1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->deactivate()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

    .line 5
    .line 6
    invoke-interface {p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;->cursorDeactivated()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public finalize()V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    goto :goto_1

    .line 11
    :cond_0
    :goto_0
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->finalize()V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :goto_1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->finalize()V

    .line 16
    .line 17
    .line 18
    throw v0
.end method

.method public getColumnIndex(Ljava/lang/String;)I
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumnNameMap:Ljava/util/Map;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumns:[Ljava/lang/String;

    .line 6
    .line 7
    array-length v1, v0

    .line 8
    new-instance v2, Ljava/util/HashMap;

    .line 9
    .line 10
    const/high16 v3, 0x3f800000    # 1.0f

    .line 11
    .line 12
    invoke-direct {v2, v1, v3}, Ljava/util/HashMap;-><init>(IF)V

    .line 13
    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    :goto_0
    if-ge v3, v1, :cond_0

    .line 17
    .line 18
    aget-object v4, v0, v3

    .line 19
    .line 20
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    invoke-virtual {v2, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    add-int/lit8 v3, v3, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumnNameMap:Ljava/util/Map;

    .line 31
    .line 32
    :cond_1
    const/16 v0, 0x2e

    .line 33
    .line 34
    invoke-virtual {p1, v0}, Ljava/lang/String;->lastIndexOf(I)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    const/4 v1, -0x1

    .line 39
    if-eq v0, v1, :cond_2

    .line 40
    .line 41
    new-instance v2, Ljava/lang/Exception;

    .line 42
    .line 43
    invoke-direct {v2}, Ljava/lang/Exception;-><init>()V

    .line 44
    .line 45
    .line 46
    const-string v3, "requesting column name with table name -- "

    .line 47
    .line 48
    invoke-virtual {v3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    const-string v4, "SQLiteCursor"

    .line 53
    .line 54
    invoke-static {v4, v3, v2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 55
    .line 56
    .line 57
    add-int/lit8 v0, v0, 0x1

    .line 58
    .line 59
    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    :cond_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumnNameMap:Ljava/util/Map;

    .line 64
    .line 65
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Ljava/lang/Integer;

    .line 70
    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    return p0

    .line 78
    :cond_3
    return v1
.end method

.method public getColumnNames()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mColumns:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCount()I
    .locals 2

    .line 1
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->fillWindow(I)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 11
    .line 12
    return p0
.end method

.method public getDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public onMove(II)Z
    .locals 1

    .line 1
    iget-object p1, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, Lnet/zetetic/database/CursorWindow;->getStartPosition()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-lt p2, p1, :cond_0

    .line 10
    .line 11
    iget-object p1, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 12
    .line 13
    invoke-virtual {p1}, Lnet/zetetic/database/CursorWindow;->getStartPosition()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 18
    .line 19
    invoke-virtual {v0}, Lnet/zetetic/database/CursorWindow;->getNumRows()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    add-int/2addr v0, p1

    .line 24
    if-lt p2, v0, :cond_1

    .line 25
    .line 26
    :cond_0
    invoke-direct {p0, p2}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->fillWindow(I)V

    .line 27
    .line 28
    .line 29
    :cond_1
    const/4 p0, 0x1

    .line 30
    return p0
.end method

.method public requery()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->isClosed()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    monitor-enter p0

    .line 10
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mQuery:Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    .line 11
    .line 12
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isOpen()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return v1

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 27
    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    invoke-virtual {v0}, Lnet/zetetic/database/CursorWindow;->clear()V

    .line 31
    .line 32
    .line 33
    :cond_2
    const/4 v0, -0x1

    .line 34
    iput v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 35
    .line 36
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 37
    .line 38
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

    .line 39
    .line 40
    invoke-interface {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;->cursorRequeried(Landroid/database/Cursor;)V

    .line 41
    .line 42
    .line 43
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    :try_start_1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->requery()Z

    .line 45
    .line 46
    .line 47
    move-result p0
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 48
    return p0

    .line 49
    :catch_0
    move-exception p0

    .line 50
    const-string v0, "SQLiteCursor"

    .line 51
    .line 52
    new-instance v2, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v3, "requery() failed "

    .line 55
    .line 56
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-static {v0, v2, p0}, Lnet/zetetic/database/Logger;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    return v1

    .line 74
    :goto_0
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 75
    throw v0
.end method

.method public setSelectionArguments([Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mDriver:Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;->setBindArguments([Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setWindow(Lnet/zetetic/database/CursorWindow;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lnet/zetetic/database/AbstractWindowedCursor;->setWindow(Lnet/zetetic/database/CursorWindow;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, -0x1

    .line 5
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteCursor;->mCount:I

    .line 6
    .line 7
    return-void
.end method
