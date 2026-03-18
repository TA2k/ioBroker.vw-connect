.class public final Llz0/u;
.super Llz0/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Ljava/lang/Integer;

.field public final d:Ljava/lang/Integer;

.field public final e:Llz0/a;

.field public final f:Z


# direct methods
.method public constructor <init>(Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)V
    .locals 1

    .line 1
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object v0, p1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    invoke-direct {p0, v0, p4}, Llz0/d;-><init>(Ljava/lang/Integer;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Llz0/u;->c:Ljava/lang/Integer;

    .line 14
    .line 15
    iput-object p2, p0, Llz0/u;->d:Ljava/lang/Integer;

    .line 16
    .line 17
    iput-object p3, p0, Llz0/u;->e:Llz0/a;

    .line 18
    .line 19
    iput-boolean p5, p0, Llz0/u;->f:Z

    .line 20
    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    new-instance p0, Lgy0/j;

    .line 24
    .line 25
    const/16 p1, 0x9

    .line 26
    .line 27
    const/4 p2, 0x1

    .line 28
    invoke-direct {p0, p2, p1, p2}, Lgy0/h;-><init>(III)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    invoke-virtual {p0, p1}, Lgy0/j;->i(I)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string p1, "Invalid length for field "

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p1, ": "

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :cond_2
    :goto_1
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/CharSequence;II)Llz0/f;
    .locals 3

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llz0/u;->d:Ljava/lang/Integer;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    sub-int v1, p4, p3

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-le v1, v2, :cond_0

    .line 17
    .line 18
    new-instance p0, Lc1/l2;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    const/4 p2, 0x5

    .line 25
    invoke-direct {p0, p1, p2}, Lc1/l2;-><init>(II)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    iget-object v0, p0, Llz0/u;->c:Ljava/lang/Integer;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    sub-int v1, p4, p3

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-ge v1, v2, :cond_1

    .line 40
    .line 41
    new-instance p0, Lc1/l2;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    const/4 p2, 0x4

    .line 48
    invoke-direct {p0, p1, p2}, Lc1/l2;-><init>(II)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    const/4 v0, 0x0

    .line 53
    :goto_0
    const/4 v1, 0x0

    .line 54
    if-ge p3, p4, :cond_3

    .line 55
    .line 56
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    mul-int/lit8 v0, v0, 0xa

    .line 61
    .line 62
    add-int/lit8 v2, v2, -0x30

    .line 63
    .line 64
    add-int/2addr v0, v2

    .line 65
    if-gez v0, :cond_2

    .line 66
    .line 67
    move-object p2, v1

    .line 68
    goto :goto_1

    .line 69
    :cond_2
    add-int/lit8 p3, p3, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    :goto_1
    if-nez p2, :cond_4

    .line 77
    .line 78
    sget-object p0, Llz0/e;->d:Llz0/e;

    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_4
    iget-boolean p3, p0, Llz0/u;->f:Z

    .line 82
    .line 83
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-eqz p3, :cond_5

    .line 88
    .line 89
    neg-int p2, p2

    .line 90
    :cond_5
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    iget-object p0, p0, Llz0/u;->e:Llz0/a;

    .line 95
    .line 96
    invoke-interface {p0, p1, p2}, Llz0/a;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-nez p0, :cond_6

    .line 101
    .line 102
    return-object v1

    .line 103
    :cond_6
    new-instance p1, Ld8/c;

    .line 104
    .line 105
    invoke-direct {p1, p0}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    return-object p1
.end method
