.class public abstract Lg4/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg4/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lg4/g;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lg4/h;->a:Lg4/g;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lg4/g;IILfw0/i0;)Ljava/util/List;
    .locals 9

    .line 1
    if-ne p1, p2, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    iget-object v0, p0, Lg4/g;->d:Ljava/util/List;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    :goto_0
    const/4 p0, 0x0

    .line 9
    return-object p0

    .line 10
    :cond_1
    const/4 v1, 0x0

    .line 11
    if-nez p1, :cond_5

    .line 12
    .line 13
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-lt p2, p0, :cond_5

    .line 20
    .line 21
    if-nez p3, :cond_2

    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_2
    new-instance p0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-direct {p0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    move-object p1, v0

    .line 34
    check-cast p1, Ljava/util/Collection;

    .line 35
    .line 36
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    :goto_1
    if-ge v1, p1, :cond_4

    .line 41
    .line 42
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    move-object v2, p2

    .line 47
    check-cast v2, Lg4/e;

    .line 48
    .line 49
    iget-object v2, v2, Lg4/e;->a:Ljava/lang/Object;

    .line 50
    .line 51
    invoke-virtual {p3, v2}, Lfw0/i0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    check-cast v2, Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_3

    .line 62
    .line 63
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    return-object p0

    .line 70
    :cond_5
    new-instance p0, Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    invoke-direct {p0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 77
    .line 78
    .line 79
    move-object v2, v0

    .line 80
    check-cast v2, Ljava/util/Collection;

    .line 81
    .line 82
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    move v3, v1

    .line 87
    :goto_2
    if-ge v3, v2, :cond_9

    .line 88
    .line 89
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, Lg4/e;

    .line 94
    .line 95
    const/4 v5, 0x1

    .line 96
    if-eqz p3, :cond_6

    .line 97
    .line 98
    iget-object v6, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    invoke-virtual {p3, v6}, Lfw0/i0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    check-cast v6, Ljava/lang/Boolean;

    .line 105
    .line 106
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 107
    .line 108
    .line 109
    move-result v6

    .line 110
    goto :goto_3

    .line 111
    :cond_6
    move v6, v5

    .line 112
    :goto_3
    if-eqz v6, :cond_7

    .line 113
    .line 114
    iget v6, v4, Lg4/e;->b:I

    .line 115
    .line 116
    iget v7, v4, Lg4/e;->c:I

    .line 117
    .line 118
    invoke-static {p1, p2, v6, v7}, Lg4/h;->b(IIII)Z

    .line 119
    .line 120
    .line 121
    move-result v6

    .line 122
    if-eqz v6, :cond_7

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_7
    move v5, v1

    .line 126
    :goto_4
    if-eqz v5, :cond_8

    .line 127
    .line 128
    iget-object v5, v4, Lg4/e;->d:Ljava/lang/String;

    .line 129
    .line 130
    iget-object v6, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v6, Lg4/b;

    .line 133
    .line 134
    iget v7, v4, Lg4/e;->b:I

    .line 135
    .line 136
    invoke-static {v7, p1, p2}, Lkp/r9;->e(III)I

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    sub-int/2addr v7, p1

    .line 141
    iget v4, v4, Lg4/e;->c:I

    .line 142
    .line 143
    invoke-static {v4, p1, p2}, Lkp/r9;->e(III)I

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    sub-int/2addr v4, p1

    .line 148
    new-instance v8, Lg4/e;

    .line 149
    .line 150
    invoke-direct {v8, v6, v7, v4, v5}, Lg4/e;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    :cond_8
    add-int/lit8 v3, v3, 0x1

    .line 157
    .line 158
    goto :goto_2

    .line 159
    :cond_9
    return-object p0
.end method

.method public static final b(IIII)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-ne p0, p1, :cond_0

    .line 4
    .line 5
    move v2, v1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v2, v0

    .line 8
    :goto_0
    if-ne p2, p3, :cond_1

    .line 9
    .line 10
    move v3, v1

    .line 11
    goto :goto_1

    .line 12
    :cond_1
    move v3, v0

    .line 13
    :goto_1
    or-int/2addr v2, v3

    .line 14
    if-ne p0, p2, :cond_2

    .line 15
    .line 16
    move v3, v1

    .line 17
    goto :goto_2

    .line 18
    :cond_2
    move v3, v0

    .line 19
    :goto_2
    and-int/2addr v2, v3

    .line 20
    if-ge p0, p3, :cond_3

    .line 21
    .line 22
    move p0, v1

    .line 23
    goto :goto_3

    .line 24
    :cond_3
    move p0, v0

    .line 25
    :goto_3
    if-ge p2, p1, :cond_4

    .line 26
    .line 27
    move v0, v1

    .line 28
    :cond_4
    and-int/2addr p0, v0

    .line 29
    or-int/2addr p0, v2

    .line 30
    return p0
.end method
