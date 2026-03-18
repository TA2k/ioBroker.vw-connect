.class public final Lg11/h;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lj11/h;

.field public b:Ljava/lang/String;

.field public final c:Ljava/lang/StringBuilder;


# direct methods
.method public constructor <init>(CII)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lj11/h;

    .line 5
    .line 6
    invoke-direct {v0}, Lj11/s;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lg11/h;->a:Lj11/h;

    .line 10
    .line 11
    new-instance v1, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lg11/h;->c:Ljava/lang/StringBuilder;

    .line 17
    .line 18
    iput-char p1, v0, Lj11/h;->g:C

    .line 19
    .line 20
    iput p2, v0, Lj11/h;->h:I

    .line 21
    .line 22
    iput p3, v0, Lj11/h;->i:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a(Lk11/b;)V
    .locals 1

    .line 1
    iget-object p1, p1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 2
    .line 3
    iget-object v0, p0, Lg11/h;->b:Ljava/lang/String;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Lg11/h;->b:Ljava/lang/String;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object p0, p0, Lg11/h;->c:Ljava/lang/StringBuilder;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const/16 p1, 0xa

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lg11/h;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Li11/a;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lg11/h;->a:Lj11/h;

    .line 12
    .line 13
    iput-object v0, v1, Lj11/h;->j:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p0, p0, Lg11/h;->c:Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    iput-object p0, v1, Lj11/h;->k:Ljava/lang/String;

    .line 22
    .line 23
    return-void
.end method

.method public final f()Lj11/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lg11/h;->a:Lj11/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 7

    .line 1
    iget v0, p1, Lg11/g;->f:I

    .line 2
    .line 3
    iget v1, p1, Lg11/g;->c:I

    .line 4
    .line 5
    iget-object v2, p1, Lg11/g;->a:Lk11/b;

    .line 6
    .line 7
    iget-object v2, v2, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 8
    .line 9
    iget p1, p1, Lg11/g;->h:I

    .line 10
    .line 11
    const/4 v3, 0x4

    .line 12
    iget-object p0, p0, Lg11/h;->a:Lj11/h;

    .line 13
    .line 14
    if-ge p1, v3, :cond_3

    .line 15
    .line 16
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-ge v0, p1, :cond_3

    .line 21
    .line 22
    invoke-interface {v2, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    iget-char v3, p0, Lj11/h;->g:C

    .line 27
    .line 28
    if-ne p1, v3, :cond_3

    .line 29
    .line 30
    iget p1, p0, Lj11/h;->h:I

    .line 31
    .line 32
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    move v5, v0

    .line 37
    :goto_0
    if-ge v5, v4, :cond_1

    .line 38
    .line 39
    invoke-interface {v2, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eq v6, v3, :cond_0

    .line 44
    .line 45
    move v4, v5

    .line 46
    goto :goto_1

    .line 47
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    :goto_1
    sub-int/2addr v4, v0

    .line 51
    if-ge v4, p1, :cond_2

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    add-int/2addr v0, v4

    .line 55
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    invoke-static {v2, v0, p1}, Llp/p1;->e(Ljava/lang/CharSequence;II)I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-ne p1, v0, :cond_3

    .line 68
    .line 69
    new-instance p0, Lc9/h;

    .line 70
    .line 71
    const/4 p1, -0x1

    .line 72
    const/4 v0, 0x1

    .line 73
    invoke-direct {p0, p1, p1, v0}, Lc9/h;-><init>(IIZ)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_3
    :goto_2
    iget p0, p0, Lj11/h;->i:I

    .line 78
    .line 79
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    :goto_3
    if-lez p0, :cond_4

    .line 84
    .line 85
    if-ge v1, p1, :cond_4

    .line 86
    .line 87
    invoke-interface {v2, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    const/16 v3, 0x20

    .line 92
    .line 93
    if-ne v0, v3, :cond_4

    .line 94
    .line 95
    add-int/lit8 v1, v1, 0x1

    .line 96
    .line 97
    add-int/lit8 p0, p0, -0x1

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_4
    invoke-static {v1}, Lc9/h;->a(I)Lc9/h;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method
