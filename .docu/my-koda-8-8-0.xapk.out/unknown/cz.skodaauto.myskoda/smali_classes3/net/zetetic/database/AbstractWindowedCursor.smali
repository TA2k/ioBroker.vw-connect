.class public abstract Lnet/zetetic/database/AbstractWindowedCursor;
.super Lnet/zetetic/database/AbstractCursor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field protected mWindow:Lnet/zetetic/database/CursorWindow;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/AbstractCursor;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public checkPosition()V
    .locals 1

    .line 1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Landroid/database/StaleDataException;

    .line 10
    .line 11
    const-string v0, "Attempting to access a closed CursorWindow.Most probable cause: cursor is deactivated prior to calling this method."

    .line 12
    .line 13
    invoke-direct {p0, v0}, Landroid/database/StaleDataException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public clearOrCreateWindow(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lnet/zetetic/database/CursorWindow;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lnet/zetetic/database/CursorWindow;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {v0}, Lnet/zetetic/database/CursorWindow;->clear()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public closeWindow()V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public copyStringToBuffer(ILandroid/database/CharArrayBuffer;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1, p2}, Lnet/zetetic/database/CursorWindow;->copyStringToBuffer(IILandroid/database/CharArrayBuffer;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public getBlob(I)[B
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getBlob(II)[B

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public getDouble(I)D
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getDouble(II)D

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0
.end method

.method public getFloat(I)F
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getFloat(II)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public getInt(I)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getInt(II)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public getLong(I)J
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getLong(II)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0
.end method

.method public getShort(I)S
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getShort(II)S

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public getString(I)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->checkPosition()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 5
    .line 6
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public getType(I)I
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getType(II)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getWindow()Lnet/zetetic/database/CursorWindow;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    return-object p0
.end method

.method public hasWindow()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public isNull(I)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/AbstractCursor;->mPos:I

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Lnet/zetetic/database/CursorWindow;->getType(II)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

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

.method public onDeactivateOrClose()V
    .locals 0

    .line 1
    invoke-super {p0}, Lnet/zetetic/database/AbstractCursor;->onDeactivateOrClose()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->closeWindow()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public setWindow(Lnet/zetetic/database/CursorWindow;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/AbstractWindowedCursor;->closeWindow()V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lnet/zetetic/database/AbstractWindowedCursor;->mWindow:Lnet/zetetic/database/CursorWindow;

    .line 9
    .line 10
    :cond_0
    return-void
.end method
