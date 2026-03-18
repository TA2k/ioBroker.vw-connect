.class public abstract Lnet/zetetic/database/AbstractCursor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/database/Cursor;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/AbstractCursor$SelfContentObserver;
    }
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "Cursor"


# instance fields
.field protected mClosed:Z

.field private final mContentObservable:Landroid/database/ContentObservable;

.field protected mContentResolver:Landroid/content/ContentResolver;

.field private final mDataSetObservable:Landroid/database/DataSetObservable;

.field private mExtras:Landroid/os/Bundle;

.field private mNotifyUri:Landroid/net/Uri;

.field protected mPos:I

.field private mSelfObserver:Landroid/database/ContentObserver;

.field private final mSelfObserverLock:Ljava/lang/Object;

.field private mSelfObserverRegistered:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverLock:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Landroid/database/DataSetObservable;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/database/DataSetObservable;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mDataSetObservable:Landroid/database/DataSetObservable;

    .line 17
    .line 18
    new-instance v0, Landroid/database/ContentObservable;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/database/ContentObservable;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mContentObservable:Landroid/database/ContentObservable;

    .line 24
    .line 25
    sget-object v0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 26
    .line 27
    iput-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mExtras:Landroid/os/Bundle;

    .line 28
    .line 29
    const/4 v0, -0x1

    .line 30
    iput v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public checkPosition()V
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    iget v1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 3
    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget v1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 11
    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance v0, Landroid/database/CursorIndexOutOfBoundsException;

    .line 16
    .line 17
    iget v1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 18
    .line 19
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-direct {v0, v1, p0}, Landroid/database/CursorIndexOutOfBoundsException;-><init>(II)V

    .line 24
    .line 25
    .line 26
    throw v0
.end method

.method public close()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lnet/zetetic/database/AbstractCursor;->mClosed:Z

    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mContentObservable:Landroid/database/ContentObservable;

    .line 5
    .line 6
    invoke-virtual {v0}, Landroid/database/Observable;->unregisterAll()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->onDeactivateOrClose()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public copyStringToBuffer(ILandroid/database/CharArrayBuffer;)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lnet/zetetic/database/AbstractCursor;->getString(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_2

    .line 7
    .line 8
    iget-object v0, p2, Landroid/database/CharArrayBuffer;->data:[C

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    array-length v1, v0

    .line 13
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-ge v1, v2, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-virtual {p0, p1, v1, v0, p1}, Ljava/lang/String;->getChars(II[CI)V

    .line 25
    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p2, Landroid/database/CharArrayBuffer;->data:[C

    .line 33
    .line 34
    :goto_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    iput p0, p2, Landroid/database/CharArrayBuffer;->sizeCopied:I

    .line 39
    .line 40
    return-void

    .line 41
    :cond_2
    iput p1, p2, Landroid/database/CharArrayBuffer;->sizeCopied:I

    .line 42
    .line 43
    return-void
.end method

.method public deactivate()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->onDeactivateOrClose()V

    .line 2
    .line 3
    .line 4
    return-void
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

.method public finalize()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v1, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverRegistered:Z

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    :try_start_0
    iget-boolean v0, p0, Lnet/zetetic/database/AbstractCursor;->mClosed:Z

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->close()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    :catch_0
    :cond_1
    return-void
.end method

.method public getBlob(I)[B
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "getBlob is not supported"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public getColumnCount()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getColumnNames()[Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    array-length p0, p0

    .line 6
    return p0
.end method

.method public getColumnIndex(Ljava/lang/String;)I
    .locals 5

    .line 1
    const/16 v0, 0x2e

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->lastIndexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    new-instance v2, Ljava/lang/Exception;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/lang/Exception;-><init>()V

    .line 13
    .line 14
    .line 15
    const-string v3, "requesting column name with table name -- "

    .line 16
    .line 17
    invoke-virtual {v3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    const-string v4, "Cursor"

    .line 22
    .line 23
    invoke-static {v4, v3, v2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    add-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    :cond_0
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getColumnNames()[Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    array-length v0, p0

    .line 37
    const/4 v2, 0x0

    .line 38
    :goto_0
    if-ge v2, v0, :cond_2

    .line 39
    .line 40
    aget-object v3, p0, v2

    .line 41
    .line 42
    invoke-virtual {v3, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_1

    .line 47
    .line 48
    return v2

    .line 49
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    return v1
.end method

.method public getColumnIndexOrThrow(Ljava/lang/String;)I
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lnet/zetetic/database/AbstractCursor;->getColumnIndex(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-ltz p0, :cond_0

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    const-string v0, "column \'"

    .line 11
    .line 12
    const-string v1, "\' does not exist"

    .line 13
    .line 14
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public getColumnName(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getColumnNames()[Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    aget-object p0, p0, p1

    .line 6
    .line 7
    return-object p0
.end method

.method public abstract getColumnNames()[Ljava/lang/String;
.end method

.method public abstract getCount()I
.end method

.method public abstract getDouble(I)D
.end method

.method public getExtras()Landroid/os/Bundle;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mExtras:Landroid/os/Bundle;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract getFloat(I)F
.end method

.method public abstract getInt(I)I
.end method

.method public abstract getLong(I)J
.end method

.method public getNotificationUri()Landroid/net/Uri;
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mNotifyUri:Landroid/net/Uri;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final getPosition()I
    .locals 0

    .line 1
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 2
    .line 3
    return p0
.end method

.method public abstract getShort(I)S
.end method

.method public abstract getString(I)Ljava/lang/String;
.end method

.method public abstract getType(I)I
.end method

.method public getWantsAllOnMoveCalls()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final isAfterLast()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 8
    .line 9
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-ne v0, p0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0

    .line 18
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 19
    return p0
.end method

.method public final isBeforeFirst()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 8
    .line 9
    const/4 v0, -0x1

    .line 10
    if-ne p0, v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public isClosed()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lnet/zetetic/database/AbstractCursor;->mClosed:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isFirst()Z
    .locals 1

    .line 1
    iget v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final isLast()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 6
    .line 7
    add-int/lit8 v1, v0, -0x1

    .line 8
    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public abstract isNull(I)Z
.end method

.method public final move(I)Z
    .locals 1

    .line 1
    iget v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 2
    .line 3
    add-int/2addr v0, p1

    .line 4
    invoke-virtual {p0, v0}, Lnet/zetetic/database/AbstractCursor;->moveToPosition(I)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public final moveToFirst()Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lnet/zetetic/database/AbstractCursor;->moveToPosition(I)Z

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final moveToLast()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v0, v0, -0x1

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lnet/zetetic/database/AbstractCursor;->moveToPosition(I)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final moveToNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lnet/zetetic/database/AbstractCursor;->moveToPosition(I)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final moveToPosition(I)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractCursor;->getCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-lt p1, v0, :cond_0

    .line 7
    .line 8
    iput v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    const/4 v0, -0x1

    .line 12
    if-gez p1, :cond_1

    .line 13
    .line 14
    iput v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 15
    .line 16
    return v1

    .line 17
    :cond_1
    iget v1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 18
    .line 19
    if-ne p1, v1, :cond_2

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_2
    invoke-virtual {p0, v1, p1}, Lnet/zetetic/database/AbstractCursor;->onMove(II)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    iput v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 30
    .line 31
    return v1

    .line 32
    :cond_3
    iput p1, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 33
    .line 34
    return v1
.end method

.method public final moveToPrevious()Z
    .locals 1

    .line 1
    iget v0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lnet/zetetic/database/AbstractCursor;->moveToPosition(I)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public onChange(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/AbstractCursor;->mContentObservable:Landroid/database/ContentObservable;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-virtual {v1, p1, v2}, Landroid/database/ContentObservable;->dispatchChange(ZLandroid/net/Uri;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lnet/zetetic/database/AbstractCursor;->mNotifyUri:Landroid/net/Uri;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    iget-object p1, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 17
    .line 18
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 19
    .line 20
    invoke-virtual {p1, v1, p0}, Landroid/content/ContentResolver;->notifyChange(Landroid/net/Uri;Landroid/database/ContentObserver;)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    monitor-exit v0

    .line 27
    return-void

    .line 28
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    throw p0
.end method

.method public onDeactivateOrClose()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-boolean v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverRegistered:Z

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mDataSetObservable:Landroid/database/DataSetObservable;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/database/DataSetObservable;->notifyInvalidated()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public abstract onMove(II)Z
.end method

.method public registerContentObserver(Landroid/database/ContentObserver;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mContentObservable:Landroid/database/ContentObservable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/database/ContentObservable;->registerObserver(Landroid/database/ContentObserver;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public registerDataSetObserver(Landroid/database/DataSetObserver;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mDataSetObservable:Landroid/database/DataSetObservable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/database/Observable;->registerObserver(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public requery()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-boolean v2, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverRegistered:Z

    .line 7
    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    iget-object v2, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 11
    .line 12
    iget-object v3, p0, Lnet/zetetic/database/AbstractCursor;->mNotifyUri:Landroid/net/Uri;

    .line 13
    .line 14
    invoke-virtual {v2, v3, v1, v0}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    .line 15
    .line 16
    .line 17
    iput-boolean v1, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverRegistered:Z

    .line 18
    .line 19
    :cond_0
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mDataSetObservable:Landroid/database/DataSetObservable;

    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/database/DataSetObservable;->notifyChanged()V

    .line 22
    .line 23
    .line 24
    return v1
.end method

.method public respond(Landroid/os/Bundle;)Landroid/os/Bundle;
    .locals 0

    .line 1
    sget-object p0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 2
    .line 3
    return-object p0
.end method

.method public setExtras(Landroid/os/Bundle;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p1, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 4
    .line 5
    :cond_0
    iput-object p1, p0, Lnet/zetetic/database/AbstractCursor;->mExtras:Landroid/os/Bundle;

    .line 6
    .line 7
    return-void
.end method

.method public setNotificationUri(Landroid/content/ContentResolver;Landroid/net/Uri;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p2, p0, Lnet/zetetic/database/AbstractCursor;->mNotifyUri:Landroid/net/Uri;

    .line 5
    .line 6
    iput-object p1, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 7
    .line 8
    iget-object p2, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 9
    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1, p2}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    new-instance p1, Lnet/zetetic/database/AbstractCursor$SelfContentObserver;

    .line 19
    .line 20
    invoke-direct {p1, p0}, Lnet/zetetic/database/AbstractCursor$SelfContentObserver;-><init>(Lnet/zetetic/database/AbstractCursor;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserver:Landroid/database/ContentObserver;

    .line 24
    .line 25
    iget-object p2, p0, Lnet/zetetic/database/AbstractCursor;->mContentResolver:Landroid/content/ContentResolver;

    .line 26
    .line 27
    iget-object v1, p0, Lnet/zetetic/database/AbstractCursor;->mNotifyUri:Landroid/net/Uri;

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-virtual {p2, v1, v2, p1}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    .line 31
    .line 32
    .line 33
    iput-boolean v2, p0, Lnet/zetetic/database/AbstractCursor;->mSelfObserverRegistered:Z

    .line 34
    .line 35
    monitor-exit v0

    .line 36
    return-void

    .line 37
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0
.end method

.method public unregisterContentObserver(Landroid/database/ContentObserver;)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lnet/zetetic/database/AbstractCursor;->mClosed:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mContentObservable:Landroid/database/ContentObservable;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroid/database/Observable;->unregisterObserver(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public unregisterDataSetObserver(Landroid/database/DataSetObserver;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractCursor;->mDataSetObservable:Landroid/database/DataSetObservable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/database/Observable;->unregisterObserver(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
