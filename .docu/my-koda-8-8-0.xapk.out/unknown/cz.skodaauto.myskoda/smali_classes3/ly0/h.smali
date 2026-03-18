.class public final Lly0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final d:Ljava/lang/CharSequence;

.field public e:I

.field public f:I

.field public g:I

.field public h:I


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;)V
    .locals 1

    .line 1
    const-string v0, "string"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lly0/h;->d:Ljava/lang/CharSequence;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 9

    .line 1
    iget v0, p0, Lly0/h;->e:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    return v2

    .line 10
    :cond_0
    return v1

    .line 11
    :cond_1
    iget v0, p0, Lly0/h;->h:I

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    if-gez v0, :cond_2

    .line 15
    .line 16
    iput v3, p0, Lly0/h;->e:I

    .line 17
    .line 18
    return v1

    .line 19
    :cond_2
    iget-object v0, p0, Lly0/h;->d:Ljava/lang/CharSequence;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    iget v4, p0, Lly0/h;->f:I

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    :goto_0
    if-ge v4, v5, :cond_5

    .line 32
    .line 33
    invoke-interface {v0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    const/16 v7, 0xd

    .line 38
    .line 39
    const/16 v8, 0xa

    .line 40
    .line 41
    if-eq v6, v8, :cond_3

    .line 42
    .line 43
    if-eq v6, v7, :cond_3

    .line 44
    .line 45
    add-int/lit8 v4, v4, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    if-ne v6, v7, :cond_4

    .line 49
    .line 50
    add-int/lit8 v1, v4, 0x1

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    if-ge v1, v5, :cond_4

    .line 57
    .line 58
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-ne v0, v8, :cond_4

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_4
    move v3, v2

    .line 66
    :goto_1
    move v1, v4

    .line 67
    goto :goto_2

    .line 68
    :cond_5
    const/4 v3, -0x1

    .line 69
    :goto_2
    iput v2, p0, Lly0/h;->e:I

    .line 70
    .line 71
    iput v3, p0, Lly0/h;->h:I

    .line 72
    .line 73
    iput v1, p0, Lly0/h;->g:I

    .line 74
    .line 75
    return v2
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lly0/h;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput v0, p0, Lly0/h;->e:I

    .line 9
    .line 10
    iget v0, p0, Lly0/h;->g:I

    .line 11
    .line 12
    iget v1, p0, Lly0/h;->f:I

    .line 13
    .line 14
    iget v2, p0, Lly0/h;->h:I

    .line 15
    .line 16
    add-int/2addr v2, v0

    .line 17
    iput v2, p0, Lly0/h;->f:I

    .line 18
    .line 19
    iget-object p0, p0, Lly0/h;->d:Ljava/lang/CharSequence;

    .line 20
    .line 21
    invoke-interface {p0, v1, v0}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public final remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "Operation is not supported for read-only collection"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
