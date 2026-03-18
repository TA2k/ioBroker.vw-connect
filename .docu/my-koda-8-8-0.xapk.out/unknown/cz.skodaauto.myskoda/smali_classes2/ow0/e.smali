.class public final Low0/e;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Low0/e;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Low0/e;

    .line 2
    .line 3
    const-string v1, "*"

    .line 4
    .line 5
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    invoke-direct {v0, v1, v1, v2}, Low0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Low0/e;->f:Low0/e;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    .locals 2

    const-string v0, "contentType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "contentSubtype"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parameters"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x2f

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 5
    invoke-direct {p0, p1, p3, p2, v0}, Low0/e;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p4, p2}, Lh/w;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 2
    iput-object p1, p0, Low0/e;->d:Ljava/lang/String;

    .line 3
    iput-object p3, p0, Low0/e;->e:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Low0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Low0/e;

    .line 6
    .line 7
    iget-object v0, p1, Low0/e;->d:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v1, p0, Low0/e;->d:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-static {v1, v0, v2}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-object v0, p0, Low0/e;->e:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v1, p1, Low0/e;->e:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Ljava/util/List;

    .line 31
    .line 32
    iget-object p1, p1, Lh/w;->c:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Ljava/util/List;

    .line 35
    .line 36
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_0

    .line 41
    .line 42
    return v2

    .line 43
    :cond_0
    const/4 p0, 0x0

    .line 44
    return p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 2
    .line 3
    iget-object v1, p0, Low0/e;->d:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-string v2, "toLowerCase(...)"

    .line 10
    .line 11
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    mul-int/lit8 v3, v1, 0x1f

    .line 19
    .line 20
    iget-object v4, p0, Low0/e;->e:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v4, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    add-int/2addr v0, v3

    .line 34
    add-int/2addr v0, v1

    .line 35
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Ljava/util/List;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    mul-int/lit8 p0, p0, 0x1f

    .line 44
    .line 45
    add-int/2addr p0, v0

    .line 46
    return p0
.end method

.method public final q(Low0/e;)Z
    .locals 6

    .line 1
    const-string v0, "pattern"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Low0/e;->e:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v1, p1, Low0/e;->d:Ljava/lang/String;

    .line 9
    .line 10
    const-string v2, "*"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x1

    .line 18
    if-nez v3, :cond_0

    .line 19
    .line 20
    iget-object v3, p0, Low0/e;->d:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v1, v3, v5}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    return v4

    .line 29
    :cond_0
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-nez v1, :cond_1

    .line 34
    .line 35
    iget-object v1, p0, Low0/e;->e:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v0, v1, v5}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    return v4

    .line 44
    :cond_1
    iget-object p1, p1, Lh/w;->c:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Ljava/util/List;

    .line 47
    .line 48
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_9

    .line 57
    .line 58
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    check-cast v0, Low0/j;

    .line 63
    .line 64
    iget-object v1, v0, Low0/j;->a:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v0, v0, Low0/j;->b:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_7

    .line 73
    .line 74
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_3

    .line 79
    .line 80
    :goto_0
    move v0, v5

    .line 81
    goto :goto_1

    .line 82
    :cond_3
    iget-object v1, p0, Lh/w;->c:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v1, Ljava/util/List;

    .line 85
    .line 86
    check-cast v1, Ljava/lang/Iterable;

    .line 87
    .line 88
    instance-of v3, v1, Ljava/util/Collection;

    .line 89
    .line 90
    if-eqz v3, :cond_5

    .line 91
    .line 92
    move-object v3, v1

    .line 93
    check-cast v3, Ljava/util/Collection;

    .line 94
    .line 95
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-eqz v3, :cond_5

    .line 100
    .line 101
    :cond_4
    move v0, v4

    .line 102
    goto :goto_1

    .line 103
    :cond_5
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    :cond_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-eqz v3, :cond_4

    .line 112
    .line 113
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    check-cast v3, Low0/j;

    .line 118
    .line 119
    iget-object v3, v3, Low0/j;->b:Ljava/lang/String;

    .line 120
    .line 121
    invoke-static {v3, v0, v5}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    if-eqz v3, :cond_6

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_7
    invoke-virtual {p0, v1}, Lh/w;->l(Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    if-eqz v3, :cond_8

    .line 137
    .line 138
    if-eqz v1, :cond_4

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_8
    invoke-static {v1, v0, v5}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    :goto_1
    if-nez v0, :cond_2

    .line 146
    .line 147
    return v4

    .line 148
    :cond_9
    return v5
.end method

.method public final r(Ljava/lang/String;)Low0/e;
    .locals 6

    .line 1
    iget-object v0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const-string v2, "charset"

    .line 10
    .line 11
    if-eqz v1, :cond_3

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    if-eq v1, v3, :cond_2

    .line 15
    .line 16
    move-object v1, v0

    .line 17
    check-cast v1, Ljava/lang/Iterable;

    .line 18
    .line 19
    instance-of v4, v1, Ljava/util/Collection;

    .line 20
    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    move-object v4, v1

    .line 24
    check-cast v4, Ljava/util/Collection;

    .line 25
    .line 26
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :cond_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_3

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    check-cast v4, Low0/j;

    .line 48
    .line 49
    iget-object v5, v4, Low0/j;->a:Ljava/lang/String;

    .line 50
    .line 51
    invoke-static {v5, v2, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_1

    .line 56
    .line 57
    iget-object v4, v4, Low0/j;->b:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v4, p1, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    const/4 v1, 0x0

    .line 67
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    check-cast v1, Low0/j;

    .line 72
    .line 73
    iget-object v4, v1, Low0/j;->a:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v4, v2, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_3

    .line 80
    .line 81
    iget-object v1, v1, Low0/j;->b:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v1, p1, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_3

    .line 88
    .line 89
    :goto_0
    return-object p0

    .line 90
    :cond_3
    :goto_1
    new-instance v1, Low0/e;

    .line 91
    .line 92
    iget-object v3, p0, Lh/w;->b:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v3, Ljava/lang/String;

    .line 95
    .line 96
    check-cast v0, Ljava/util/Collection;

    .line 97
    .line 98
    new-instance v4, Low0/j;

    .line 99
    .line 100
    invoke-direct {v4, v2, p1}, Low0/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v0, v4}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    iget-object v0, p0, Low0/e;->d:Ljava/lang/String;

    .line 108
    .line 109
    iget-object p0, p0, Low0/e;->e:Ljava/lang/String;

    .line 110
    .line 111
    invoke-direct {v1, v0, p1, p0, v3}, Low0/e;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    return-object v1
.end method
