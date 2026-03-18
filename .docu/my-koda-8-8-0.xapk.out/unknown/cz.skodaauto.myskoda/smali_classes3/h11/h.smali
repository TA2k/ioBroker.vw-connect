.class public final Lh11/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll4/d0;


# instance fields
.field public d:I

.field public e:I

.field public f:I

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(II)V
    .locals 1

    const/high16 v0, -0x80000000

    .line 14
    invoke-direct {p0, v0, p1, p2}, Lh11/h;-><init>(III)V

    return-void
.end method

.method public constructor <init>(III)V
    .locals 3

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    const-string v0, ""

    const/high16 v1, -0x80000000

    if-eq p1, v1, :cond_0

    const-string v2, "/"

    .line 17
    invoke-static {p1, v2}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v0

    .line 18
    :goto_0
    iput-object p1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 19
    iput p2, p0, Lh11/h;->d:I

    .line 20
    iput p3, p0, Lh11/h;->e:I

    .line 21
    iput v1, p0, Lh11/h;->f:I

    .line 22
    iput-object v0, p0, Lh11/h;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Li2/e0;)V
    .locals 5

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 29
    iget-object v0, p1, Li2/e0;->a:Ljava/lang/String;

    .line 30
    iget-char v1, p1, Li2/e0;->b:C

    const/4 v2, 0x0

    const/4 v3, 0x6

    .line 31
    invoke-static {v0, v1, v2, v3}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    move-result v4

    iput v4, p0, Lh11/h;->d:I

    .line 32
    invoke-static {v0, v1, v2, v3}, Lly0/p;->O(Ljava/lang/CharSequence;CII)I

    move-result v0

    iput v0, p0, Lh11/h;->e:I

    .line 33
    iget-object p1, p1, Li2/e0;->c:Ljava/lang/String;

    .line 34
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    iput p1, p0, Lh11/h;->f:I

    .line 35
    new-instance p1, La0/j;

    const/16 v0, 0x19

    invoke-direct {p1, p0, v0}, La0/j;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lh11/h;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lk11/b;

    const-string v1, ""

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Lk11/b;-><init>(Ljava/lang/CharSequence;Lj11/w;)V

    .line 3
    iput-object v0, p0, Lh11/h;->h:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 4
    iput v0, p0, Lh11/h;->f:I

    .line 5
    iput-object p1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 6
    iput v0, p0, Lh11/h;->d:I

    .line 7
    iput v0, p0, Lh11/h;->e:I

    .line 8
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_0

    .line 9
    invoke-virtual {p0, v0, v0}, Lh11/h;->a(II)V

    .line 10
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lk11/b;

    .line 11
    iput-object p1, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 12
    iget-object p1, p1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 13
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result p1

    iput p1, p0, Lh11/h;->f:I

    :cond_0
    return-void
.end method


# virtual methods
.method public a(II)V
    .locals 2

    .line 1
    iget-object p0, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/List;

    .line 4
    .line 5
    if-ltz p1, :cond_1

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-ge p1, v0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lk11/b;

    .line 18
    .line 19
    if-ltz p2, :cond_0

    .line 20
    .line 21
    iget-object p1, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-gt p2, p1, :cond_0

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    const-string v0, "Index "

    .line 33
    .line 34
    const-string v1, " out of range, line length: "

    .line 35
    .line 36
    invoke-static {v0, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    iget-object p0, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 41
    .line 42
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p1

    .line 57
    :cond_1
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 58
    .line 59
    const-string v0, "Line index "

    .line 60
    .line 61
    const-string v1, " out of range, number of lines: "

    .line 62
    .line 63
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p2
.end method

.method public b(Lg4/g;)Ll4/b0;
    .locals 6

    .line 1
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lh11/h;->f:I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-le v0, v1, :cond_0

    .line 11
    .line 12
    invoke-static {v2, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "<this>"

    .line 17
    .line 18
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v1, "range"

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget v1, v0, Lgy0/h;->d:I

    .line 27
    .line 28
    iget v0, v0, Lgy0/h;->e:I

    .line 29
    .line 30
    add-int/lit8 v0, v0, 0x1

    .line 31
    .line 32
    invoke-virtual {p1, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    const-string v0, "substring(...)"

    .line 37
    .line 38
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    const-string v0, ""

    .line 42
    .line 43
    move v1, v2

    .line 44
    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-ge v2, v3, :cond_3

    .line 49
    .line 50
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    add-int/lit8 v4, v1, 0x1

    .line 55
    .line 56
    new-instance v5, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    iget v3, p0, Lh11/h;->d:I

    .line 72
    .line 73
    if-eq v4, v3, :cond_1

    .line 74
    .line 75
    add-int/lit8 v1, v1, 0x2

    .line 76
    .line 77
    iget v3, p0, Lh11/h;->e:I

    .line 78
    .line 79
    if-ne v1, v3, :cond_2

    .line 80
    .line 81
    :cond_1
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget-object v1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v1, Li2/e0;

    .line 88
    .line 89
    iget-char v1, v1, Li2/e0;->b:C

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 99
    .line 100
    move v1, v4

    .line 101
    goto :goto_0

    .line 102
    :cond_3
    new-instance p1, Ll4/b0;

    .line 103
    .line 104
    new-instance v1, Lg4/g;

    .line 105
    .line 106
    invoke-direct {v1, v0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iget-object p0, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p0, La0/j;

    .line 112
    .line 113
    invoke-direct {p1, v1, p0}, Ll4/b0;-><init>(Lg4/g;Ll4/p;)V

    .line 114
    .line 115
    .line 116
    return-object p1
.end method

.method public c(C)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    const/4 p0, -0x1

    .line 9
    return p0

    .line 10
    :cond_0
    if-ne v1, p1, :cond_1

    .line 11
    .line 12
    return v0

    .line 13
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 16
    .line 17
    .line 18
    goto :goto_0
.end method

.method public d()V
    .locals 2

    .line 1
    iget v0, p0, Lh11/h;->f:I

    .line 2
    .line 3
    const/high16 v1, -0x80000000

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lh11/h;->d:I

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget v1, p0, Lh11/h;->e:I

    .line 11
    .line 12
    add-int/2addr v0, v1

    .line 13
    :goto_0
    iput v0, p0, Lh11/h;->f:I

    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    iget v1, p0, Lh11/h;->f:I

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iput-object v0, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 37
    .line 38
    return-void
.end method

.method public e(Lb8/i;Lb8/i;)Lbn/c;
    .locals 6

    .line 1
    iget-object p0, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/List;

    .line 4
    .line 5
    iget v0, p1, Lb8/i;->b:I

    .line 6
    .line 7
    iget p1, p1, Lb8/i;->c:I

    .line 8
    .line 9
    iget v1, p2, Lb8/i;->b:I

    .line 10
    .line 11
    iget p2, p2, Lb8/i;->c:I

    .line 12
    .line 13
    if-ne v0, v1, :cond_1

    .line 14
    .line 15
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lk11/b;

    .line 20
    .line 21
    iget-object v0, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 22
    .line 23
    invoke-interface {v0, p1, p2}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    iget-object p0, p0, Lk11/b;->b:Lj11/w;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    iget v0, p0, Lj11/w;->a:I

    .line 32
    .line 33
    iget p0, p0, Lj11/w;->b:I

    .line 34
    .line 35
    add-int/2addr p0, p1

    .line 36
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    new-instance v1, Lj11/w;

    .line 41
    .line 42
    invoke-direct {v1, v0, p0, p1}, Lj11/w;-><init>(III)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 v1, 0x0

    .line 47
    :goto_0
    new-instance p0, Lk11/b;

    .line 48
    .line 49
    invoke-direct {p0, p2, v1}, Lk11/b;-><init>(Ljava/lang/CharSequence;Lj11/w;)V

    .line 50
    .line 51
    .line 52
    new-instance p1, Lbn/c;

    .line 53
    .line 54
    const/4 p2, 0x4

    .line 55
    invoke-direct {p1, p2}, Lbn/c;-><init>(I)V

    .line 56
    .line 57
    .line 58
    iget-object p2, p1, Lbn/c;->d:Ljava/util/ArrayList;

    .line 59
    .line 60
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    return-object p1

    .line 64
    :cond_1
    new-instance v2, Lbn/c;

    .line 65
    .line 66
    const/4 v3, 0x4

    .line 67
    invoke-direct {v2, v3}, Lbn/c;-><init>(I)V

    .line 68
    .line 69
    .line 70
    iget-object v3, v2, Lbn/c;->d:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    check-cast v4, Lk11/b;

    .line 77
    .line 78
    iget-object v5, v4, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 79
    .line 80
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    invoke-virtual {v4, p1, v5}, Lk11/b;->a(II)Lk11/b;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 92
    .line 93
    if-ge v0, v1, :cond_2

    .line 94
    .line 95
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    check-cast p1, Lk11/b;

    .line 100
    .line 101
    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_2
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    check-cast p0, Lk11/b;

    .line 110
    .line 111
    const/4 p1, 0x0

    .line 112
    invoke-virtual {p0, p1, p2}, Lk11/b;->a(II)Lk11/b;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-virtual {v3, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    return-object v2
.end method

.method public f()Z
    .locals 3

    .line 1
    iget v0, p0, Lh11/h;->e:I

    .line 2
    .line 3
    iget v1, p0, Lh11/h;->f:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-ge v0, v1, :cond_0

    .line 7
    .line 8
    return v2

    .line 9
    :cond_0
    iget v0, p0, Lh11/h;->d:I

    .line 10
    .line 11
    iget-object p0, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljava/util/List;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    sub-int/2addr p0, v2

    .line 20
    if-ge v0, p0, :cond_1

    .line 21
    .line 22
    return v2

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public g(Lhu/q;)I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    iget-object v2, p1, Lhu/q;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v2, Ljava/util/BitSet;

    .line 9
    .line 10
    invoke-virtual {v2, v1}, Ljava/util/BitSet;->get(I)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    add-int/lit8 v0, v0, 0x1

    .line 17
    .line 18
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return v0
.end method

.method public h(C)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-ne v1, p1, :cond_0

    .line 7
    .line 8
    add-int/lit8 v0, v0, 0x1

    .line 9
    .line 10
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return v0
.end method

.method public i()V
    .locals 1

    .line 1
    iget p0, p0, Lh11/h;->f:I

    .line 2
    .line 3
    const/high16 v0, -0x80000000

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v0, "generateNewId() must be called before retrieving ids."

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method public j()V
    .locals 3

    .line 1
    iget-object v0, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    iget v1, p0, Lh11/h;->e:I

    .line 6
    .line 7
    add-int/lit8 v1, v1, 0x1

    .line 8
    .line 9
    iput v1, p0, Lh11/h;->e:I

    .line 10
    .line 11
    iget v2, p0, Lh11/h;->f:I

    .line 12
    .line 13
    if-le v1, v2, :cond_1

    .line 14
    .line 15
    iget v1, p0, Lh11/h;->d:I

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    iput v1, p0, Lh11/h;->d:I

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-ge v1, v2, :cond_0

    .line 26
    .line 27
    iget v1, p0, Lh11/h;->d:I

    .line 28
    .line 29
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Lk11/b;

    .line 34
    .line 35
    iput-object v0, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 36
    .line 37
    iget-object v0, v0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iput v0, p0, Lh11/h;->f:I

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    new-instance v0, Lk11/b;

    .line 47
    .line 48
    const-string v1, ""

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-direct {v0, v1, v2}, Lk11/b;-><init>(Ljava/lang/CharSequence;Lj11/w;)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 55
    .line 56
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iput v0, p0, Lh11/h;->f:I

    .line 61
    .line 62
    :goto_0
    const/4 v0, 0x0

    .line 63
    iput v0, p0, Lh11/h;->e:I

    .line 64
    .line 65
    :cond_1
    return-void
.end method

.method public k(C)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ne v0, p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public l(Ljava/lang/String;)Z
    .locals 4

    .line 1
    iget v0, p0, Lh11/h;->e:I

    .line 2
    .line 3
    iget v1, p0, Lh11/h;->f:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-ge v0, v1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    add-int/2addr v1, v0

    .line 13
    iget v0, p0, Lh11/h;->f:I

    .line 14
    .line 15
    if-gt v1, v0, :cond_2

    .line 16
    .line 17
    move v0, v2

    .line 18
    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-ge v0, v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lk11/b;

    .line 27
    .line 28
    iget-object v1, v1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 29
    .line 30
    iget v3, p0, Lh11/h;->e:I

    .line 31
    .line 32
    add-int/2addr v3, v0

    .line 33
    invoke-interface {v1, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eq v1, v3, :cond_0

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    iget v0, p0, Lh11/h;->e:I

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    add-int/2addr p1, v0

    .line 54
    iput p1, p0, Lh11/h;->e:I

    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_2
    :goto_1
    return v2
.end method

.method public m()C
    .locals 2

    .line 1
    iget v0, p0, Lh11/h;->e:I

    .line 2
    .line 3
    iget v1, p0, Lh11/h;->f:I

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lk11/b;

    .line 10
    .line 11
    iget-object p0, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :cond_0
    iget v0, p0, Lh11/h;->d:I

    .line 19
    .line 20
    iget-object p0, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ljava/util/List;

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/lit8 p0, p0, -0x1

    .line 29
    .line 30
    if-ge v0, p0, :cond_1

    .line 31
    .line 32
    const/16 p0, 0xa

    .line 33
    .line 34
    return p0

    .line 35
    :cond_1
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public n()Lb8/i;
    .locals 3

    .line 1
    new-instance v0, Lb8/i;

    .line 2
    .line 3
    iget v1, p0, Lh11/h;->d:I

    .line 4
    .line 5
    iget p0, p0, Lh11/h;->e:I

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    invoke-direct {v0, v1, p0, v2}, Lb8/i;-><init>(III)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public o(Lb8/i;)V
    .locals 1

    .line 1
    iget v0, p1, Lb8/i;->b:I

    .line 2
    .line 3
    iget p1, p1, Lb8/i;->c:I

    .line 4
    .line 5
    invoke-virtual {p0, v0, p1}, Lh11/h;->a(II)V

    .line 6
    .line 7
    .line 8
    iput v0, p0, Lh11/h;->d:I

    .line 9
    .line 10
    iput p1, p0, Lh11/h;->e:I

    .line 11
    .line 12
    iget-object p1, p0, Lh11/h;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Ljava/util/List;

    .line 15
    .line 16
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lk11/b;

    .line 21
    .line 22
    iput-object p1, p0, Lh11/h;->h:Ljava/lang/Object;

    .line 23
    .line 24
    iget-object p1, p1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    iput p1, p0, Lh11/h;->f:I

    .line 31
    .line 32
    return-void
.end method

.method public p()I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    const/16 v2, 0x20

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    return v0

    .line 14
    :cond_0
    :pswitch_0
    add-int/lit8 v0, v0, 0x1

    .line 15
    .line 16
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    nop

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method
