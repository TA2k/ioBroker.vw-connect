.class public Lnet/zetetic/database/CursorWindow;
.super Lnet/zetetic/database/sqlcipher/SQLiteClosable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final DEFAULT_CURSOR_WINDOW_SIZE:I = 0x4000

.field public static PREFERRED_CURSOR_WINDOW_SIZE:I = 0x4000

.field private static final WINDOW_SIZE_KB:I = 0x10


# instance fields
.field private final mName:Ljava/lang/String;

.field private mStartPos:I

.field public mWindowPtr:J

.field private final mWindowSizeBytes:I


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x4000

    .line 1
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/CursorWindow;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 2

    .line 2
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;-><init>()V

    const/4 v0, 0x0

    .line 3
    iput v0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    iput p2, p0, Lnet/zetetic/database/CursorWindow;->mWindowSizeBytes:I

    if-eqz p1, :cond_0

    .line 5
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, "<unnamed>"

    :goto_0
    iput-object p1, p0, Lnet/zetetic/database/CursorWindow;->mName:Ljava/lang/String;

    .line 6
    invoke-static {p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeCreate(Ljava/lang/String;I)J

    move-result-wide v0

    iput-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    const-wide/16 p0, 0x0

    cmp-long p0, v0, p0

    if-eqz p0, :cond_1

    return-void

    .line 7
    :cond_1
    new-instance p0, Lnet/zetetic/database/CursorWindowAllocationException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Cursor window allocation of "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    div-int/lit16 p2, p2, 0x400

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p2, " kb failed. "

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Lnet/zetetic/database/CursorWindowAllocationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private dispose()V
    .locals 5

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v4, v0, v2

    .line 6
    .line 7
    if-eqz v4, :cond_0

    .line 8
    .line 9
    invoke-static {v0, v1}, Lnet/zetetic/database/CursorWindow;->nativeDispose(J)V

    .line 10
    .line 11
    .line 12
    iput-wide v2, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method private static native nativeAllocRow(J)Z
.end method

.method private static native nativeClear(J)V
.end method

.method private static native nativeCreate(Ljava/lang/String;I)J
.end method

.method private static native nativeDispose(J)V
.end method

.method private static native nativeFreeLastRow(J)V
.end method

.method private static native nativeGetBlob(JII)[B
.end method

.method private static native nativeGetDouble(JII)D
.end method

.method private static native nativeGetLong(JII)J
.end method

.method private static native nativeGetName(J)Ljava/lang/String;
.end method

.method private static native nativeGetNumRows(J)I
.end method

.method private static native nativeGetString(JII)Ljava/lang/String;
.end method

.method private static native nativeGetType(JII)I
.end method

.method private static native nativePutBlob(J[BII)Z
.end method

.method private static native nativePutDouble(JDII)Z
.end method

.method private static native nativePutLong(JJII)Z
.end method

.method private static native nativePutNull(JII)Z
.end method

.method private static native nativePutString(JLjava/lang/String;II)Z
.end method

.method private static native nativeSetNumColumns(JI)Z
.end method


# virtual methods
.method public allocRow()Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lnet/zetetic/database/CursorWindow;->nativeAllocRow(J)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public clear()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 3
    .line 4
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 5
    .line 6
    invoke-static {v0, v1}, Lnet/zetetic/database/CursorWindow;->nativeClear(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public copyStringToBuffer(IILandroid/database/CharArrayBuffer;)V
    .locals 0

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    iput-object p0, p3, Landroid/database/CharArrayBuffer;->data:[C

    .line 12
    .line 13
    array-length p0, p0

    .line 14
    iput p0, p3, Landroid/database/CharArrayBuffer;->sizeCopied:I

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "CharArrayBuffer should not be null"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0
.end method

.method public finalize()V
    .locals 1

    .line 1
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/CursorWindow;->dispose()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2
    .line 3
    .line 4
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 5
    .line 6
    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception v0

    .line 9
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 10
    .line 11
    .line 12
    throw v0
.end method

.method public freeLastRow()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lnet/zetetic/database/CursorWindow;->nativeFreeLastRow(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getBlob(II)[B
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeGetBlob(JII)[B

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public getDouble(II)D
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeGetDouble(JII)D

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0
.end method

.method public getFloat(II)F
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getDouble(II)D

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    double-to-float p0, p0

    .line 6
    return p0
.end method

.method public getInt(II)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getLong(II)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    long-to-int p0, p0

    .line 6
    return p0
.end method

.method public getLong(II)J
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeGetLong(JII)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/CursorWindow;->mName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getNumRows()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lnet/zetetic/database/CursorWindow;->nativeGetNumRows(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getShort(II)S
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getLong(II)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    long-to-int p0, p0

    .line 6
    int-to-short p0, p0

    .line 7
    return p0
.end method

.method public getStartPosition()I
    .locals 0

    .line 1
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 2
    .line 3
    return p0
.end method

.method public getString(II)Ljava/lang/String;
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeGetString(JII)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public getType(II)I
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativeGetType(JII)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public getWindowSizeBytes()I
    .locals 0

    .line 1
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mWindowSizeBytes:I

    .line 2
    .line 3
    return p0
.end method

.method public isBlob(II)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getType(II)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x4

    .line 6
    if-eq p0, p1, :cond_1

    .line 7
    .line 8
    if-nez p0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 14
    return p0
.end method

.method public isNull(II)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->getType(II)I

    .line 2
    .line 3
    .line 4
    move-result p0

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

.method public onAllReferencesReleased()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/CursorWindow;->dispose()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public putBlob([BII)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p2, p0

    .line 6
    invoke-static {v0, v1, p1, p2, p3}, Lnet/zetetic/database/CursorWindow;->nativePutBlob(J[BII)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public putDouble(DII)Z
    .locals 6

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int v4, p3, p0

    .line 6
    .line 7
    move-wide v2, p1

    .line 8
    move v5, p4

    .line 9
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/CursorWindow;->nativePutDouble(JDII)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public putLong(JII)Z
    .locals 6

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int v4, p3, p0

    .line 6
    .line 7
    move-wide v2, p1

    .line 8
    move v5, p4

    .line 9
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/CursorWindow;->nativePutLong(JJII)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public putNull(II)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p1, p0

    .line 6
    invoke-static {v0, v1, p1, p2}, Lnet/zetetic/database/CursorWindow;->nativePutNull(JII)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public putString(Ljava/lang/String;II)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 4
    .line 5
    sub-int/2addr p2, p0

    .line 6
    invoke-static {v0, v1, p1, p2, p3}, Lnet/zetetic/database/CursorWindow;->nativePutString(JLjava/lang/String;II)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public setNumColumns(I)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lnet/zetetic/database/CursorWindow;->nativeSetNumColumns(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public setStartPosition(I)V
    .locals 0

    .line 1
    iput p1, p0, Lnet/zetetic/database/CursorWindow;->mStartPos:I

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lnet/zetetic/database/CursorWindow;->getName()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, " {"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J

    .line 19
    .line 20
    invoke-static {v1, v2}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p0, "}"

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
