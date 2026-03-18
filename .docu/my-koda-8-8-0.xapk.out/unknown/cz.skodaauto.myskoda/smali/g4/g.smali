.class public final Lg4/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/CharSequence;


# instance fields
.field public final d:Ljava/util/List;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/util/ArrayList;

.field public final g:Ljava/util/ArrayList;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lg4/e0;->a:Lu2/l;

    .line 2
    .line 3
    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 34
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 35
    invoke-direct {p0, p1, v0}, Lg4/g;-><init>(Ljava/lang/String;Ljava/util/List;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/List;)V
    .locals 1

    .line 36
    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p2, 0x0

    :cond_0
    check-cast p2, Ljava/util/List;

    invoke-direct {p0, p2, p1}, Lg4/g;-><init>(Ljava/util/List;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/lang/String;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lg4/g;->d:Ljava/util/List;

    iput-object p2, p0, Lg4/g;->e:Ljava/lang/String;

    const/4 p2, 0x0

    const/4 v0, 0x0

    if-eqz p1, :cond_4

    .line 2
    move-object v1, p1

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v1

    move v2, p2

    move-object v3, v0

    move-object v4, v3

    :goto_0
    if-ge v2, v1, :cond_5

    .line 3
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    .line 4
    check-cast v5, Lg4/e;

    .line 5
    iget-object v6, v5, Lg4/e;->a:Ljava/lang/Object;

    .line 6
    instance-of v7, v6, Lg4/g0;

    if-eqz v7, :cond_1

    if-nez v3, :cond_0

    .line 7
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 8
    :cond_0
    invoke-interface {v3, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 9
    :cond_1
    instance-of v6, v6, Lg4/t;

    if-eqz v6, :cond_3

    if-nez v4, :cond_2

    .line 10
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 11
    :cond_2
    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_3
    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_4
    move-object v3, v0

    move-object v4, v3

    .line 12
    :cond_5
    iput-object v3, p0, Lg4/g;->f:Ljava/util/ArrayList;

    .line 13
    iput-object v4, p0, Lg4/g;->g:Ljava/util/ArrayList;

    if-eqz v4, :cond_6

    .line 14
    new-instance p0, Lg4/f;

    .line 15
    invoke-direct {p0, p2}, Lg4/f;-><init>(I)V

    .line 16
    invoke-static {v4, p0}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v0

    .line 17
    :cond_6
    move-object p0, v0

    check-cast p0, Ljava/util/Collection;

    if-eqz p0, :cond_b

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result p0

    if-eqz p0, :cond_7

    goto :goto_5

    .line 18
    :cond_7
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lg4/e;

    .line 19
    iget p0, p0, Lg4/e;->c:I

    .line 20
    sget-object p1, Landroidx/collection/o;->a:Landroidx/collection/a0;

    .line 21
    new-instance p1, Landroidx/collection/a0;

    const/4 p2, 0x1

    invoke-direct {p1, p2}, Landroidx/collection/a0;-><init>(I)V

    .line 22
    invoke-virtual {p1, p0}, Landroidx/collection/a0;->a(I)V

    .line 23
    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result p0

    move v1, p2

    :goto_2
    if-ge v1, p0, :cond_b

    .line 24
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lg4/e;

    .line 25
    :goto_3
    iget v3, p1, Landroidx/collection/a0;->b:I

    if-eqz v3, :cond_a

    .line 26
    invoke-virtual {p1}, Landroidx/collection/a0;->d()I

    move-result v3

    .line 27
    iget v4, v2, Lg4/e;->b:I

    iget v5, v2, Lg4/e;->c:I

    if-lt v4, v3, :cond_8

    .line 28
    iget v3, p1, Landroidx/collection/a0;->b:I

    sub-int/2addr v3, p2

    .line 29
    invoke-virtual {p1, v3}, Landroidx/collection/a0;->e(I)V

    goto :goto_3

    :cond_8
    if-gt v5, v3, :cond_9

    goto :goto_4

    .line 30
    :cond_9
    new-instance v4, Ljava/lang/StringBuilder;

    const-string v6, "Paragraph overlap not allowed, end "

    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " should be less than or equal to "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    .line 31
    invoke-static {v3}, Lm4/a;->a(Ljava/lang/String;)V

    .line 32
    :cond_a
    :goto_4
    iget v2, v2, Lg4/e;->c:I

    .line 33
    invoke-virtual {p1, v2}, Landroidx/collection/a0;->a(I)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_b
    :goto_5
    return-void
.end method


# virtual methods
.method public final a(I)Ljava/util/List;
    .locals 7

    .line 1
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 2
    .line 3
    if-eqz p0, :cond_2

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    move-object v1, p0

    .line 15
    check-cast v1, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x0

    .line 22
    move v3, v2

    .line 23
    :goto_0
    if-ge v3, v1, :cond_1

    .line 24
    .line 25
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    move-object v5, v4

    .line 30
    check-cast v5, Lg4/e;

    .line 31
    .line 32
    iget-object v6, v5, Lg4/e;->a:Ljava/lang/Object;

    .line 33
    .line 34
    instance-of v6, v6, Lg4/n;

    .line 35
    .line 36
    if-eqz v6, :cond_0

    .line 37
    .line 38
    iget v6, v5, Lg4/e;->b:I

    .line 39
    .line 40
    iget v5, v5, Lg4/e;->c:I

    .line 41
    .line 42
    invoke-static {v2, p1, v6, v5}, Lg4/h;->b(IIII)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eqz v5, :cond_0

    .line 47
    .line 48
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    return-object v0

    .line 55
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 56
    .line 57
    return-object p0
.end method

.method public final b(IILjava/lang/String;)Ljava/util/List;
    .locals 9

    .line 1
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 2
    .line 3
    if-eqz p0, :cond_2

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    move-object v1, p0

    .line 15
    check-cast v1, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x0

    .line 22
    :goto_0
    if-ge v2, v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Lg4/e;

    .line 29
    .line 30
    iget-object v4, v3, Lg4/e;->a:Ljava/lang/Object;

    .line 31
    .line 32
    iget v5, v3, Lg4/e;->c:I

    .line 33
    .line 34
    iget v6, v3, Lg4/e;->b:I

    .line 35
    .line 36
    iget-object v7, v3, Lg4/e;->d:Ljava/lang/String;

    .line 37
    .line 38
    instance-of v4, v4, Lg4/i0;

    .line 39
    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    invoke-static {p3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-eqz v4, :cond_0

    .line 47
    .line 48
    invoke-static {p1, p2, v6, v5}, Lg4/h;->b(IIII)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-eqz v4, :cond_0

    .line 53
    .line 54
    new-instance v4, Lg4/e;

    .line 55
    .line 56
    iget-object v3, v3, Lg4/e;->a:Ljava/lang/Object;

    .line 57
    .line 58
    const-string v8, "null cannot be cast to non-null type androidx.compose.ui.text.StringAnnotation"

    .line 59
    .line 60
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    check-cast v3, Lg4/i0;

    .line 64
    .line 65
    iget-object v3, v3, Lg4/i0;->a:Ljava/lang/String;

    .line 66
    .line 67
    invoke-direct {v4, v3, v6, v5, v7}, Lg4/e;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    return-object v0

    .line 77
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 78
    .line 79
    return-object p0
.end method

.method public final c(Lay0/k;)Lg4/g;
    .locals 8

    .line 1
    new-instance v0, Lg4/d;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lg4/d;-><init>(Lg4/g;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, v0, Lg4/d;->f:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    check-cast v3, Lg4/c;

    .line 20
    .line 21
    const/high16 v4, -0x80000000

    .line 22
    .line 23
    invoke-virtual {v3, v4}, Lg4/c;->a(I)Lg4/e;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {p1, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Lg4/e;

    .line 32
    .line 33
    new-instance v4, Lg4/c;

    .line 34
    .line 35
    iget-object v5, v3, Lg4/e;->a:Ljava/lang/Object;

    .line 36
    .line 37
    iget v6, v3, Lg4/e;->b:I

    .line 38
    .line 39
    iget v7, v3, Lg4/e;->c:I

    .line 40
    .line 41
    iget-object v3, v3, Lg4/e;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-direct {v4, v5, v6, v7, v3}, Lg4/c;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v2, v4}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    add-int/lit8 v2, v2, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    invoke-virtual {v0}, Lg4/d;->j()Lg4/g;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public final charAt(I)C
    .locals 0

    .line 1
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final d(II)Lg4/g;
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    if-gt p1, p2, :cond_0

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    goto :goto_0

    .line 6
    :cond_0
    move v1, v0

    .line 7
    :goto_0
    const/16 v2, 0x29

    .line 8
    .line 9
    const-string v3, "start ("

    .line 10
    .line 11
    if-nez v1, :cond_1

    .line 12
    .line 13
    new-instance v1, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v4, ") should be less or equal to end ("

    .line 22
    .line 23
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {v1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    iget-object v1, p0, Lg4/g;->e:Ljava/lang/String;

    .line 40
    .line 41
    if-nez p1, :cond_2

    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-ne p2, v4, :cond_2

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_2
    invoke-virtual {v1, p1, p2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    const-string v4, "substring(...)"

    .line 55
    .line 56
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sget-object v4, Lg4/h;->a:Lg4/g;

    .line 60
    .line 61
    if-gt p1, p2, :cond_3

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    new-instance v4, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    invoke-direct {v4, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v3, ") should be less than or equal to end ("

    .line 73
    .line 74
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    invoke-static {v2}, Lm4/a;->a(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    :goto_1
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 91
    .line 92
    if-nez p0, :cond_4

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_4
    new-instance v2, Ljava/util/ArrayList;

    .line 96
    .line 97
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 102
    .line 103
    .line 104
    move-object v3, p0

    .line 105
    check-cast v3, Ljava/util/Collection;

    .line 106
    .line 107
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_2
    if-ge v0, v3, :cond_6

    .line 112
    .line 113
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    check-cast v4, Lg4/e;

    .line 118
    .line 119
    iget v5, v4, Lg4/e;->b:I

    .line 120
    .line 121
    iget v6, v4, Lg4/e;->c:I

    .line 122
    .line 123
    invoke-static {p1, p2, v5, v6}, Lg4/h;->b(IIII)Z

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    if-eqz v5, :cond_5

    .line 128
    .line 129
    new-instance v5, Lg4/e;

    .line 130
    .line 131
    iget-object v7, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 132
    .line 133
    iget v8, v4, Lg4/e;->b:I

    .line 134
    .line 135
    invoke-static {p1, v8}, Ljava/lang/Math;->max(II)I

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    sub-int/2addr v8, p1

    .line 140
    invoke-static {p2, v6}, Ljava/lang/Math;->min(II)I

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    sub-int/2addr v6, p1

    .line 145
    iget-object v4, v4, Lg4/e;->d:Ljava/lang/String;

    .line 146
    .line 147
    invoke-direct {v5, v7, v8, v6, v4}, Lg4/e;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    :cond_5
    add-int/lit8 v0, v0, 0x1

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_6
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 157
    .line 158
    .line 159
    move-result p0

    .line 160
    if-eqz p0, :cond_7

    .line 161
    .line 162
    :goto_3
    const/4 v2, 0x0

    .line 163
    :cond_7
    new-instance p0, Lg4/g;

    .line 164
    .line 165
    invoke-direct {p0, v2, v1}, Lg4/g;-><init>(Ljava/util/List;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lg4/g;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lg4/g;

    .line 12
    .line 13
    iget-object v1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p0, Lg4/g;->e:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 25
    .line 26
    iget-object p1, p1, Lg4/g;->d:Ljava/util/List;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lg4/g;->d:Ljava/util/List;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    add-int/2addr v0, p0

    .line 20
    return v0
.end method

.method public final length()I
    .locals 0

    .line 1
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final bridge synthetic subSequence(II)Ljava/lang/CharSequence;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lg4/g;->d(II)Lg4/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
