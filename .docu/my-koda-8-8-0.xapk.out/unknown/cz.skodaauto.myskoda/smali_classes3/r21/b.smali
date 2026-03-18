.class public final Lr21/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final d:Ljava/lang/CharSequence;

.field public final e:Lr21/a;

.field public f:I

.field public g:Ls21/a;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;Lr21/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lr21/b;->f:I

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lr21/b;->g:Ls21/a;

    .line 9
    .line 10
    iput-object p1, p0, Lr21/b;->d:Ljava/lang/CharSequence;

    .line 11
    .line 12
    iput-object p2, p0, Lr21/b;->e:Lr21/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lr21/b;->f:I

    .line 2
    .line 3
    iget-object p0, p0, Lr21/b;->d:Ljava/lang/CharSequence;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-ge v0, p0, :cond_0

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

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lr21/b;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    iget-object v0, p0, Lr21/b;->g:Ls21/a;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_2

    .line 11
    .line 12
    iget-object v0, p0, Lr21/b;->e:Lr21/a;

    .line 13
    .line 14
    invoke-virtual {v0}, Lr21/a;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v0}, Lr21/a;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    iget-object v2, v0, Lr21/a;->e:Ls21/a;

    .line 27
    .line 28
    iput-object v1, v0, Lr21/a;->e:Ls21/a;

    .line 29
    .line 30
    iput-object v2, p0, Lr21/b;->g:Ls21/a;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    iget-object v0, p0, Lr21/b;->d:Ljava/lang/CharSequence;

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    new-instance v1, Lb8/i;

    .line 46
    .line 47
    iget v2, p0, Lr21/b;->f:I

    .line 48
    .line 49
    const/16 v3, 0x8

    .line 50
    .line 51
    invoke-direct {v1, v2, v0, v3}, Lb8/i;-><init>(III)V

    .line 52
    .line 53
    .line 54
    iput v0, p0, Lr21/b;->f:I

    .line 55
    .line 56
    return-object v1

    .line 57
    :cond_2
    :goto_0
    iget v0, p0, Lr21/b;->f:I

    .line 58
    .line 59
    iget-object v2, p0, Lr21/b;->g:Ls21/a;

    .line 60
    .line 61
    iget v3, v2, Ls21/a;->b:I

    .line 62
    .line 63
    if-ge v0, v3, :cond_3

    .line 64
    .line 65
    new-instance v1, Lb8/i;

    .line 66
    .line 67
    const/16 v2, 0x8

    .line 68
    .line 69
    invoke-direct {v1, v0, v3, v2}, Lb8/i;-><init>(III)V

    .line 70
    .line 71
    .line 72
    iput v3, p0, Lr21/b;->f:I

    .line 73
    .line 74
    return-object v1

    .line 75
    :cond_3
    iget v0, v2, Ls21/a;->c:I

    .line 76
    .line 77
    iput v0, p0, Lr21/b;->f:I

    .line 78
    .line 79
    iput-object v1, p0, Lr21/b;->g:Ls21/a;

    .line 80
    .line 81
    return-object v2

    .line 82
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 83
    .line 84
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 85
    .line 86
    .line 87
    throw p0
.end method

.method public final remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "remove"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
