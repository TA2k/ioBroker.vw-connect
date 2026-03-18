.class public final Lh4/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/text/CharacterIterator;


# instance fields
.field public final d:Ljava/lang/CharSequence;

.field public final e:I

.field public f:I


# direct methods
.method public constructor <init>(ILjava/lang/CharSequence;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lh4/c;->d:Ljava/lang/CharSequence;

    .line 5
    .line 6
    iput p1, p0, Lh4/c;->e:I

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput p1, p0, Lh4/c;->f:I

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final clone()Ljava/lang/Object;
    .locals 0

    .line 1
    :try_start_0
    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/CloneNotSupportedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    new-instance p0, Ljava/lang/InternalError;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/InternalError;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public final current()C
    .locals 2

    .line 1
    iget v0, p0, Lh4/c;->f:I

    .line 2
    .line 3
    iget v1, p0, Lh4/c;->e:I

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const p0, 0xffff

    .line 8
    .line 9
    .line 10
    return p0

    .line 11
    :cond_0
    iget-object p0, p0, Lh4/c;->d:Ljava/lang/CharSequence;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final first()C
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lh4/c;->f:I

    .line 3
    .line 4
    invoke-virtual {p0}, Lh4/c;->current()C

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public final getBeginIndex()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final getEndIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lh4/c;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public final getIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lh4/c;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final last()C
    .locals 1

    .line 1
    iget v0, p0, Lh4/c;->e:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iput v0, p0, Lh4/c;->f:I

    .line 6
    .line 7
    const p0, 0xffff

    .line 8
    .line 9
    .line 10
    return p0

    .line 11
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 12
    .line 13
    iput v0, p0, Lh4/c;->f:I

    .line 14
    .line 15
    iget-object p0, p0, Lh4/c;->d:Ljava/lang/CharSequence;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final next()C
    .locals 2

    .line 1
    iget v0, p0, Lh4/c;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lh4/c;->f:I

    .line 6
    .line 7
    iget v1, p0, Lh4/c;->e:I

    .line 8
    .line 9
    if-lt v0, v1, :cond_0

    .line 10
    .line 11
    iput v1, p0, Lh4/c;->f:I

    .line 12
    .line 13
    const p0, 0xffff

    .line 14
    .line 15
    .line 16
    return p0

    .line 17
    :cond_0
    iget-object p0, p0, Lh4/c;->d:Ljava/lang/CharSequence;

    .line 18
    .line 19
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public final previous()C
    .locals 1

    .line 1
    iget v0, p0, Lh4/c;->f:I

    .line 2
    .line 3
    if-gtz v0, :cond_0

    .line 4
    .line 5
    const p0, 0xffff

    .line 6
    .line 7
    .line 8
    return p0

    .line 9
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    iput v0, p0, Lh4/c;->f:I

    .line 12
    .line 13
    iget-object p0, p0, Lh4/c;->d:Ljava/lang/CharSequence;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final setIndex(I)C
    .locals 1

    .line 1
    iget v0, p0, Lh4/c;->e:I

    .line 2
    .line 3
    if-gt p1, v0, :cond_0

    .line 4
    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    iput p1, p0, Lh4/c;->f:I

    .line 8
    .line 9
    invoke-virtual {p0}, Lh4/c;->current()C

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    const-string p1, "invalid position"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method
