.class public final enum Lr11/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# static fields
.field public static final enum d:Lr11/l;

.field public static final e:Ljava/util/HashMap;

.field public static final f:Ljava/util/ArrayList;

.field public static final g:I

.field public static final h:I

.field public static final synthetic i:[Lr11/l;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lr11/l;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lr11/l;->d:Lr11/l;

    .line 10
    .line 11
    filled-new-array {v0}, [Lr11/l;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lr11/l;->i:[Lr11/l;

    .line 16
    .line 17
    new-instance v0, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lr11/l;->f:Ljava/util/ArrayList;

    .line 23
    .line 24
    new-instance v0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-static {}, Ln11/f;->k()Ls11/h;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-interface {v1}, Ls11/h;->b()Ljava/util/Set;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Ljava/util/HashMap;

    .line 41
    .line 42
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 43
    .line 44
    .line 45
    sput-object v1, Lr11/l;->e:Ljava/util/HashMap;

    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move v1, v2

    .line 52
    move v3, v1

    .line 53
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_3

    .line 58
    .line 59
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Ljava/lang/String;

    .line 64
    .line 65
    const/16 v5, 0x2f

    .line 66
    .line 67
    invoke-virtual {v4, v5}, Ljava/lang/String;->indexOf(I)I

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-ltz v5, :cond_2

    .line 72
    .line 73
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    if-ge v5, v6, :cond_0

    .line 78
    .line 79
    add-int/lit8 v5, v5, 0x1

    .line 80
    .line 81
    :cond_0
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    add-int/lit8 v6, v5, 0x1

    .line 86
    .line 87
    invoke-virtual {v4, v2, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    invoke-virtual {v4, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    sget-object v7, Lr11/l;->e:Ljava/util/HashMap;

    .line 96
    .line 97
    invoke-virtual {v7, v6}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v8

    .line 101
    if-nez v8, :cond_1

    .line 102
    .line 103
    new-instance v8, Ljava/util/ArrayList;

    .line 104
    .line 105
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v7, v6, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    :cond_1
    invoke-virtual {v7, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    check-cast v6, Ljava/util/List;

    .line 116
    .line 117
    invoke-interface {v6, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_2
    sget-object v5, Lr11/l;->f:Ljava/util/ArrayList;

    .line 122
    .line 123
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    :goto_1
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    goto :goto_0

    .line 135
    :cond_3
    sput v1, Lr11/l;->g:I

    .line 136
    .line 137
    sput v3, Lr11/l;->h:I

    .line 138
    .line 139
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lr11/l;
    .locals 1

    .line 1
    const-class v0, Lr11/l;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lr11/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static final values()[Lr11/l;
    .locals 1

    .line 1
    sget-object v0, Lr11/l;->i:[Lr11/l;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lr11/l;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lr11/l;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    sget p0, Lr11/l;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    if-eqz p6, :cond_0

    .line 2
    .line 3
    iget-object p0, p6, Ln11/f;->d:Ljava/lang/String;

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string p0, ""

    .line 7
    .line 8
    :goto_0
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 8

    .line 1
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sget v0, Lr11/l;->h:I

    .line 6
    .line 7
    add-int/2addr v0, p3

    .line 8
    invoke-static {p0, v0}, Ljava/lang/Math;->min(II)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    move v1, p3

    .line 13
    :goto_0
    if-ge v1, v0, :cond_2

    .line 14
    .line 15
    invoke-interface {p2, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/16 v3, 0x2f

    .line 20
    .line 21
    if-ne v2, v3, :cond_1

    .line 22
    .line 23
    add-int/lit8 v0, v1, 0x1

    .line 24
    .line 25
    invoke-interface {p2, p3, v0}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    add-int/2addr v3, p3

    .line 38
    if-ge v1, p0, :cond_0

    .line 39
    .line 40
    invoke-static {v2}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-interface {p2, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    goto :goto_1

    .line 56
    :cond_0
    move-object p0, v2

    .line 57
    :goto_1
    sget-object v0, Lr11/l;->e:Ljava/util/HashMap;

    .line 58
    .line 59
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/util/List;

    .line 64
    .line 65
    if-nez p0, :cond_3

    .line 66
    .line 67
    not-int p0, p3

    .line 68
    return p0

    .line 69
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    sget-object p0, Lr11/l;->f:Ljava/util/ArrayList;

    .line 73
    .line 74
    const-string v2, ""

    .line 75
    .line 76
    move v3, p3

    .line 77
    :cond_3
    const/4 v0, 0x0

    .line 78
    const/4 v1, 0x0

    .line 79
    move-object v4, v0

    .line 80
    :goto_2
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-ge v1, v5, :cond_6

    .line 85
    .line 86
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    check-cast v5, Ljava/lang/String;

    .line 91
    .line 92
    invoke-static {v3, p2, v5}, Lvp/y1;->N(ILjava/lang/CharSequence;Ljava/lang/String;)Z

    .line 93
    .line 94
    .line 95
    move-result v6

    .line 96
    if-eqz v6, :cond_5

    .line 97
    .line 98
    if-eqz v4, :cond_4

    .line 99
    .line 100
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    if-le v6, v7, :cond_5

    .line 109
    .line 110
    :cond_4
    move-object v4, v5

    .line 111
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_6
    if-eqz v4, :cond_7

    .line 115
    .line 116
    invoke-virtual {v2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-static {p0}, Ln11/f;->c(Ljava/lang/String;)Ln11/f;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    iput-object v0, p1, Lr11/s;->i:Lr11/r;

    .line 125
    .line 126
    iput-object p0, p1, Lr11/s;->d:Ln11/f;

    .line 127
    .line 128
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    add-int/2addr p0, v3

    .line 133
    return p0

    .line 134
    :cond_7
    not-int p0, p3

    .line 135
    return p0
.end method

.method public final e()I
    .locals 0

    .line 1
    sget p0, Lr11/l;->g:I

    .line 2
    .line 3
    return p0
.end method
