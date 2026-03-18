.class public final Ld01/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:I

.field public c:Ljava/lang/Object;

.field public d:Ljava/io/Serializable;

.field public e:Ljava/io/Serializable;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Ld01/z;->a:I

    packed-switch p1, :pswitch_data_0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    const-string p1, ""

    iput-object p1, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 6
    iput-object p1, p0, Ld01/z;->e:Ljava/io/Serializable;

    const/4 v0, -0x1

    .line 7
    iput v0, p0, Ld01/z;->b:I

    .line 8
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object p1

    iput-object p1, p0, Ld01/z;->h:Ljava/lang/Object;

    return-void

    .line 9
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lwq/m;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ld01/z;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-virtual {p0}, Ld01/z;->g()V

    .line 3
    sget-object v0, Landroid/util/StateSet;->WILD_CARD:[I

    invoke-virtual {p0, v0, p1}, Ld01/z;->b([ILwq/m;)V

    return-void
.end method

.method public static l(Ljava/lang/String;)Ljava/util/ArrayList;
    .locals 6

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-gt v1, v2, :cond_3

    .line 12
    .line 13
    const/16 v2, 0x26

    .line 14
    .line 15
    const/4 v3, 0x4

    .line 16
    invoke-static {p0, v2, v1, v3}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/4 v4, -0x1

    .line 21
    if-ne v2, v4, :cond_0

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    :cond_0
    const/16 v5, 0x3d

    .line 28
    .line 29
    invoke-static {p0, v5, v1, v3}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    const-string v5, "substring(...)"

    .line 34
    .line 35
    if-eq v3, v4, :cond_2

    .line 36
    .line 37
    if-le v3, v2, :cond_1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    invoke-virtual {p0, v1, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    add-int/lit8 v3, v3, 0x1

    .line 51
    .line 52
    invoke-virtual {p0, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    :goto_1
    invoke-virtual {p0, v1, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    const/4 v1, 0x0

    .line 74
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    :goto_2
    add-int/lit8 v1, v2, 0x1

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    return-object v0
.end method


# virtual methods
.method public a(Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/ArrayList;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    const/16 v3, 0x5b

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    const/4 v2, 0x0

    .line 31
    const-string v5, " !\"#$&\'(),/:;<=>?@[]\\^`{|}~"

    .line 32
    .line 33
    move-object v4, p1

    .line 34
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    if-eqz p2, :cond_1

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    const/16 v2, 0x5b

    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    const/4 v1, 0x0

    .line 55
    const-string v4, " !\"#$&\'(),/:;<=>?@[]\\^`{|}~"

    .line 56
    .line 57
    move-object v3, p2

    .line 58
    invoke-static/range {v0 .. v5}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    goto :goto_0

    .line 63
    :cond_1
    const/4 p1, 0x0

    .line 64
    :goto_0
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public b([ILwq/m;)V
    .locals 5

    .line 1
    iget v0, p0, Ld01/z;->b:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    array-length v1, p1

    .line 6
    if-nez v1, :cond_1

    .line 7
    .line 8
    :cond_0
    iput-object p2, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 9
    .line 10
    :cond_1
    iget-object v1, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 11
    .line 12
    check-cast v1, [[I

    .line 13
    .line 14
    array-length v2, v1

    .line 15
    if-lt v0, v2, :cond_2

    .line 16
    .line 17
    add-int/lit8 v2, v0, 0xa

    .line 18
    .line 19
    new-array v3, v2, [[I

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    invoke-static {v1, v4, v3, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    iput-object v3, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 26
    .line 27
    new-array v1, v2, [Lwq/m;

    .line 28
    .line 29
    iget-object v2, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 30
    .line 31
    check-cast v2, [Lwq/m;

    .line 32
    .line 33
    invoke-static {v2, v4, v1, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 34
    .line 35
    .line 36
    iput-object v1, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 37
    .line 38
    :cond_2
    iget-object v0, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 39
    .line 40
    check-cast v0, [[I

    .line 41
    .line 42
    iget v1, p0, Ld01/z;->b:I

    .line 43
    .line 44
    aput-object p1, v0, v1

    .line 45
    .line 46
    iget-object p1, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 47
    .line 48
    check-cast p1, [Lwq/m;

    .line 49
    .line 50
    aput-object p2, p1, v1

    .line 51
    .line 52
    add-int/lit8 v1, v1, 0x1

    .line 53
    .line 54
    iput v1, p0, Ld01/z;->b:I

    .line 55
    .line 56
    return-void
.end method

.method public c()Ld01/a0;
    .locals 13

    .line 1
    iget-object v0, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v2, v0

    .line 4
    check-cast v2, Ljava/lang/String;

    .line 5
    .line 6
    if-eqz v2, :cond_6

    .line 7
    .line 8
    iget-object v0, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 9
    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v3, 0x7

    .line 14
    invoke-static {v1, v1, v3, v0}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v4, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 19
    .line 20
    check-cast v4, Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v1, v1, v3, v4}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    iget-object v5, p0, Ld01/z;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v5, Ljava/lang/String;

    .line 29
    .line 30
    if-eqz v5, :cond_5

    .line 31
    .line 32
    invoke-virtual {p0}, Ld01/z;->d()I

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    iget-object v7, p0, Ld01/z;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v7, Ljava/util/ArrayList;

    .line 39
    .line 40
    move-object v8, v7

    .line 41
    new-instance v7, Ljava/util/ArrayList;

    .line 42
    .line 43
    const/16 v9, 0xa

    .line 44
    .line 45
    invoke-static {v8, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 46
    .line 47
    .line 48
    move-result v10

    .line 49
    invoke-direct {v7, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    :goto_0
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v10

    .line 60
    if-eqz v10, :cond_0

    .line 61
    .line 62
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    check-cast v10, Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, v1, v3, v10}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    iget-object v8, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v8, Ljava/util/ArrayList;

    .line 79
    .line 80
    const/4 v10, 0x0

    .line 81
    if-eqz v8, :cond_3

    .line 82
    .line 83
    new-instance v11, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-static {v8, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 86
    .line 87
    .line 88
    move-result v9

    .line 89
    invoke-direct {v11, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 90
    .line 91
    .line 92
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v9

    .line 100
    if-eqz v9, :cond_2

    .line 101
    .line 102
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    check-cast v9, Ljava/lang/String;

    .line 107
    .line 108
    if-eqz v9, :cond_1

    .line 109
    .line 110
    const/4 v12, 0x3

    .line 111
    invoke-static {v1, v1, v12, v9}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    goto :goto_2

    .line 116
    :cond_1
    move-object v9, v10

    .line 117
    :goto_2
    invoke-virtual {v11, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_2
    move-object v8, v11

    .line 122
    goto :goto_3

    .line 123
    :cond_3
    move-object v8, v10

    .line 124
    :goto_3
    iget-object v9, p0, Ld01/z;->g:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v9, Ljava/lang/String;

    .line 127
    .line 128
    if-eqz v9, :cond_4

    .line 129
    .line 130
    invoke-static {v1, v1, v3, v9}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v10

    .line 134
    :cond_4
    move-object v9, v10

    .line 135
    invoke-virtual {p0}, Ld01/z;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v10

    .line 139
    new-instance v1, Ld01/a0;

    .line 140
    .line 141
    move-object v3, v0

    .line 142
    invoke-direct/range {v1 .. v10}, Ld01/a0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    return-object v1

    .line 146
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 147
    .line 148
    const-string v0, "host == null"

    .line 149
    .line 150
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 155
    .line 156
    const-string v0, "scheme == null"

    .line 157
    .line 158
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0
.end method

.method public d()I
    .locals 2

    .line 1
    iget v0, p0, Ld01/z;->b:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    iget-object p0, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "http"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    const/16 v1, 0x50

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const-string v0, "https"

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    const/16 v1, 0x1bb

    .line 34
    .line 35
    :cond_2
    :goto_0
    return v1
.end method

.method public e()V
    .locals 3

    .line 1
    const-string v0, "/oidc/v1/authorize"

    .line 2
    .line 3
    const-string v1, "/"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v0, v1, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const/16 v1, 0x12

    .line 13
    .line 14
    invoke-virtual {p0, v2, v1, v0}, Ld01/z;->j(IILjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    const-string p0, "unexpected encodedPath: "

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0
.end method

.method public f(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "host"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    const/4 v1, 0x7

    .line 8
    invoke-static {v0, v0, v1, p1}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Le01/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iput-object v0, p0, Ld01/z;->f:Ljava/lang/Object;

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    const-string v0, "unexpected host: "

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public g()V
    .locals 2

    .line 1
    new-instance v0, Lwq/m;

    .line 2
    .line 3
    invoke-direct {v0}, Lwq/m;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 7
    .line 8
    const/16 v0, 0xa

    .line 9
    .line 10
    new-array v1, v0, [[I

    .line 11
    .line 12
    iput-object v1, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 13
    .line 14
    new-array v0, v0, [Lwq/m;

    .line 15
    .line 16
    iput-object v0, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 17
    .line 18
    return-void
.end method

.method public h(Ld01/a0;Ljava/lang/String;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v4, p2

    .line 6
    .line 7
    iget-object v2, v0, Ld01/z;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Ljava/util/ArrayList;

    .line 10
    .line 11
    const-string v3, "input"

    .line 12
    .line 13
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sget-object v3, Le01/e;->a:[B

    .line 17
    .line 18
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v5, 0x0

    .line 23
    invoke-static {v5, v3, v4}, Le01/e;->j(IILjava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    invoke-static {v3, v6, v4}, Le01/e;->k(IILjava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v7

    .line 35
    sub-int v6, v7, v3

    .line 36
    .line 37
    const/16 v8, 0x5b

    .line 38
    .line 39
    const/16 v9, 0x3a

    .line 40
    .line 41
    const/4 v10, -0x1

    .line 42
    const/4 v11, 0x2

    .line 43
    if-ge v6, v11, :cond_1

    .line 44
    .line 45
    :cond_0
    :goto_0
    move v6, v10

    .line 46
    goto :goto_3

    .line 47
    :cond_1
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    const/16 v12, 0x61

    .line 52
    .line 53
    invoke-static {v6, v12}, Lkotlin/jvm/internal/m;->g(II)I

    .line 54
    .line 55
    .line 56
    move-result v13

    .line 57
    const/16 v14, 0x41

    .line 58
    .line 59
    if-ltz v13, :cond_2

    .line 60
    .line 61
    const/16 v13, 0x7a

    .line 62
    .line 63
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->g(II)I

    .line 64
    .line 65
    .line 66
    move-result v13

    .line 67
    if-lez v13, :cond_3

    .line 68
    .line 69
    :cond_2
    invoke-static {v6, v14}, Lkotlin/jvm/internal/m;->g(II)I

    .line 70
    .line 71
    .line 72
    move-result v13

    .line 73
    if-ltz v13, :cond_0

    .line 74
    .line 75
    const/16 v13, 0x5a

    .line 76
    .line 77
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->g(II)I

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-lez v6, :cond_3

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_3
    add-int/lit8 v6, v3, 0x1

    .line 85
    .line 86
    :goto_1
    if-ge v6, v7, :cond_0

    .line 87
    .line 88
    invoke-virtual {v4, v6}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v13

    .line 92
    if-gt v12, v13, :cond_4

    .line 93
    .line 94
    const/16 v15, 0x7b

    .line 95
    .line 96
    if-ge v13, v15, :cond_4

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    if-gt v14, v13, :cond_5

    .line 100
    .line 101
    if-ge v13, v8, :cond_5

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_5
    const/16 v15, 0x30

    .line 105
    .line 106
    if-gt v15, v13, :cond_6

    .line 107
    .line 108
    if-ge v13, v9, :cond_6

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_6
    const/16 v15, 0x2b

    .line 112
    .line 113
    if-eq v13, v15, :cond_8

    .line 114
    .line 115
    const/16 v15, 0x2d

    .line 116
    .line 117
    if-eq v13, v15, :cond_8

    .line 118
    .line 119
    const/16 v15, 0x2e

    .line 120
    .line 121
    if-ne v13, v15, :cond_7

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_7
    if-ne v13, v9, :cond_0

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_8
    :goto_2
    add-int/lit8 v6, v6, 0x1

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :goto_3
    const-string v12, "http"

    .line 131
    .line 132
    const-string v13, "https"

    .line 133
    .line 134
    const-string v14, "substring(...)"

    .line 135
    .line 136
    const/4 v15, 0x1

    .line 137
    if-eq v6, v10, :cond_b

    .line 138
    .line 139
    const-string v8, "https:"

    .line 140
    .line 141
    invoke-static {v4, v3, v8, v15}, Lly0/w;->w(Ljava/lang/String;ILjava/lang/String;Z)Z

    .line 142
    .line 143
    .line 144
    move-result v8

    .line 145
    if-eqz v8, :cond_9

    .line 146
    .line 147
    iput-object v13, v0, Ld01/z;->c:Ljava/lang/Object;

    .line 148
    .line 149
    add-int/lit8 v3, v3, 0x6

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_9
    const-string v8, "http:"

    .line 153
    .line 154
    invoke-static {v4, v3, v8, v15}, Lly0/w;->w(Ljava/lang/String;ILjava/lang/String;Z)Z

    .line 155
    .line 156
    .line 157
    move-result v8

    .line 158
    if-eqz v8, :cond_a

    .line 159
    .line 160
    iput-object v12, v0, Ld01/z;->c:Ljava/lang/Object;

    .line 161
    .line 162
    add-int/lit8 v3, v3, 0x5

    .line 163
    .line 164
    goto :goto_4

    .line 165
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 166
    .line 167
    new-instance v1, Ljava/lang/StringBuilder;

    .line 168
    .line 169
    const-string v2, "Expected URL scheme \'http\' or \'https\' but was \'"

    .line 170
    .line 171
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v4, v5, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    const/16 v2, 0x27

    .line 185
    .line 186
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    throw v0

    .line 197
    :cond_b
    if-eqz v1, :cond_26

    .line 198
    .line 199
    iget-object v6, v1, Ld01/a0;->a:Ljava/lang/String;

    .line 200
    .line 201
    iput-object v6, v0, Ld01/z;->c:Ljava/lang/Object;

    .line 202
    .line 203
    :goto_4
    move v6, v3

    .line 204
    move v8, v5

    .line 205
    move/from16 v16, v15

    .line 206
    .line 207
    :goto_5
    const/16 v15, 0x5c

    .line 208
    .line 209
    const/16 v9, 0x2f

    .line 210
    .line 211
    if-ge v6, v7, :cond_d

    .line 212
    .line 213
    invoke-virtual {v4, v6}, Ljava/lang/String;->charAt(I)C

    .line 214
    .line 215
    .line 216
    move-result v5

    .line 217
    if-eq v5, v9, :cond_c

    .line 218
    .line 219
    if-eq v5, v15, :cond_c

    .line 220
    .line 221
    goto :goto_6

    .line 222
    :cond_c
    add-int/lit8 v8, v8, 0x1

    .line 223
    .line 224
    add-int/lit8 v6, v6, 0x1

    .line 225
    .line 226
    const/4 v5, 0x0

    .line 227
    const/16 v9, 0x3a

    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_d
    :goto_6
    const/16 v6, 0x23

    .line 231
    .line 232
    if-ge v8, v11, :cond_12

    .line 233
    .line 234
    if-eqz v1, :cond_12

    .line 235
    .line 236
    iget-object v11, v1, Ld01/a0;->a:Ljava/lang/String;

    .line 237
    .line 238
    iget-object v5, v0, Ld01/z;->c:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast v5, Ljava/lang/String;

    .line 241
    .line 242
    invoke-static {v11, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result v5

    .line 246
    if-nez v5, :cond_e

    .line 247
    .line 248
    goto :goto_8

    .line 249
    :cond_e
    invoke-virtual {v1}, Ld01/a0;->e()Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v5

    .line 253
    iput-object v5, v0, Ld01/z;->d:Ljava/io/Serializable;

    .line 254
    .line 255
    invoke-virtual {v1}, Ld01/a0;->a()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v5

    .line 259
    iput-object v5, v0, Ld01/z;->e:Ljava/io/Serializable;

    .line 260
    .line 261
    iget-object v5, v1, Ld01/a0;->d:Ljava/lang/String;

    .line 262
    .line 263
    iput-object v5, v0, Ld01/z;->f:Ljava/lang/Object;

    .line 264
    .line 265
    iget v5, v1, Ld01/a0;->e:I

    .line 266
    .line 267
    iput v5, v0, Ld01/z;->b:I

    .line 268
    .line 269
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v1}, Ld01/a0;->c()Ljava/util/ArrayList;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 277
    .line 278
    .line 279
    if-eq v3, v7, :cond_f

    .line 280
    .line 281
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 282
    .line 283
    .line 284
    move-result v2

    .line 285
    if-ne v2, v6, :cond_11

    .line 286
    .line 287
    :cond_f
    invoke-virtual {v1}, Ld01/a0;->d()Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v11

    .line 291
    if-eqz v11, :cond_10

    .line 292
    .line 293
    const/4 v13, 0x1

    .line 294
    const/16 v10, 0x53

    .line 295
    .line 296
    const/4 v8, 0x0

    .line 297
    const/4 v9, 0x0

    .line 298
    const-string v12, " \"\'<>#"

    .line 299
    .line 300
    invoke-static/range {v8 .. v13}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    invoke-static {v1}, Ld01/z;->l(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    goto :goto_7

    .line 309
    :cond_10
    const/4 v1, 0x0

    .line 310
    :goto_7
    iput-object v1, v0, Ld01/z;->i:Ljava/lang/Object;

    .line 311
    .line 312
    :cond_11
    const/16 v15, 0x3f

    .line 313
    .line 314
    goto/16 :goto_14

    .line 315
    .line 316
    :cond_12
    :goto_8
    add-int/2addr v3, v8

    .line 317
    move v1, v3

    .line 318
    const/4 v8, 0x0

    .line 319
    const/16 v17, 0x0

    .line 320
    .line 321
    :goto_9
    const-string v2, "@/\\?#"

    .line 322
    .line 323
    invoke-static {v4, v2, v1, v7}, Le01/e;->f(Ljava/lang/String;Ljava/lang/String;II)I

    .line 324
    .line 325
    .line 326
    move-result v11

    .line 327
    if-eq v11, v7, :cond_13

    .line 328
    .line 329
    invoke-virtual {v4, v11}, Ljava/lang/String;->charAt(I)C

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    goto :goto_a

    .line 334
    :cond_13
    move v2, v10

    .line 335
    :goto_a
    if-eq v2, v10, :cond_19

    .line 336
    .line 337
    if-eq v2, v6, :cond_19

    .line 338
    .line 339
    if-eq v2, v9, :cond_19

    .line 340
    .line 341
    if-eq v2, v15, :cond_19

    .line 342
    .line 343
    const/16 v3, 0x3f

    .line 344
    .line 345
    if-eq v2, v3, :cond_18

    .line 346
    .line 347
    const/16 v5, 0x40

    .line 348
    .line 349
    if-eq v2, v5, :cond_14

    .line 350
    .line 351
    goto :goto_9

    .line 352
    :cond_14
    const-string v2, "%40"

    .line 353
    .line 354
    if-nez v17, :cond_17

    .line 355
    .line 356
    move-object/from16 v18, v2

    .line 357
    .line 358
    const/16 v5, 0x3a

    .line 359
    .line 360
    invoke-static {v4, v5, v1, v11}, Le01/e;->e(Ljava/lang/String;CII)I

    .line 361
    .line 362
    .line 363
    move-result v2

    .line 364
    move v5, v6

    .line 365
    const/4 v6, 0x1

    .line 366
    move/from16 v19, v3

    .line 367
    .line 368
    const/16 v3, 0x70

    .line 369
    .line 370
    move/from16 v20, v5

    .line 371
    .line 372
    const-string v5, " \"\':;<=>@[]^`{}|/\\?#"

    .line 373
    .line 374
    move-object/from16 v9, v18

    .line 375
    .line 376
    move/from16 v15, v19

    .line 377
    .line 378
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    if-eqz v8, :cond_15

    .line 383
    .line 384
    new-instance v3, Ljava/lang/StringBuilder;

    .line 385
    .line 386
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 387
    .line 388
    .line 389
    iget-object v4, v0, Ld01/z;->d:Ljava/io/Serializable;

    .line 390
    .line 391
    check-cast v4, Ljava/lang/String;

    .line 392
    .line 393
    invoke-static {v3, v4, v9, v1}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    :cond_15
    iput-object v1, v0, Ld01/z;->d:Ljava/io/Serializable;

    .line 398
    .line 399
    if-eq v2, v11, :cond_16

    .line 400
    .line 401
    add-int/lit8 v1, v2, 0x1

    .line 402
    .line 403
    const/4 v6, 0x1

    .line 404
    const/16 v3, 0x70

    .line 405
    .line 406
    const-string v5, " \"\':;<=>@[]^`{}|/\\?#"

    .line 407
    .line 408
    move-object/from16 v4, p2

    .line 409
    .line 410
    move v2, v11

    .line 411
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object v1

    .line 415
    iput-object v1, v0, Ld01/z;->e:Ljava/io/Serializable;

    .line 416
    .line 417
    move/from16 v17, v16

    .line 418
    .line 419
    goto :goto_b

    .line 420
    :cond_16
    move v2, v11

    .line 421
    :goto_b
    move-object/from16 v4, p2

    .line 422
    .line 423
    move/from16 v8, v16

    .line 424
    .line 425
    goto :goto_c

    .line 426
    :cond_17
    move-object v9, v2

    .line 427
    move v15, v3

    .line 428
    move v2, v11

    .line 429
    new-instance v11, Ljava/lang/StringBuilder;

    .line 430
    .line 431
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 432
    .line 433
    .line 434
    iget-object v3, v0, Ld01/z;->e:Ljava/io/Serializable;

    .line 435
    .line 436
    check-cast v3, Ljava/lang/String;

    .line 437
    .line 438
    invoke-virtual {v11, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 439
    .line 440
    .line 441
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 442
    .line 443
    .line 444
    const/4 v6, 0x1

    .line 445
    const/16 v3, 0x70

    .line 446
    .line 447
    const-string v5, " \"\':;<=>@[]^`{}|/\\?#"

    .line 448
    .line 449
    move-object/from16 v4, p2

    .line 450
    .line 451
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v1

    .line 455
    invoke-virtual {v11, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 456
    .line 457
    .line 458
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    iput-object v1, v0, Ld01/z;->e:Ljava/io/Serializable;

    .line 463
    .line 464
    :goto_c
    add-int/lit8 v1, v2, 0x1

    .line 465
    .line 466
    const/16 v6, 0x23

    .line 467
    .line 468
    const/16 v9, 0x2f

    .line 469
    .line 470
    const/16 v15, 0x5c

    .line 471
    .line 472
    goto/16 :goto_9

    .line 473
    .line 474
    :cond_18
    move v8, v1

    .line 475
    move v15, v3

    .line 476
    move v2, v11

    .line 477
    goto :goto_d

    .line 478
    :cond_19
    move v8, v1

    .line 479
    move v2, v11

    .line 480
    const/16 v15, 0x3f

    .line 481
    .line 482
    :goto_d
    move v1, v8

    .line 483
    :goto_e
    if-ge v1, v2, :cond_1d

    .line 484
    .line 485
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 486
    .line 487
    .line 488
    move-result v3

    .line 489
    const/16 v5, 0x3a

    .line 490
    .line 491
    if-eq v3, v5, :cond_1c

    .line 492
    .line 493
    const/16 v6, 0x5b

    .line 494
    .line 495
    if-eq v3, v6, :cond_1a

    .line 496
    .line 497
    goto :goto_f

    .line 498
    :cond_1a
    add-int/lit8 v1, v1, 0x1

    .line 499
    .line 500
    if-ge v1, v2, :cond_1b

    .line 501
    .line 502
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 503
    .line 504
    .line 505
    move-result v3

    .line 506
    const/16 v9, 0x5d

    .line 507
    .line 508
    if-ne v3, v9, :cond_1a

    .line 509
    .line 510
    :cond_1b
    :goto_f
    add-int/lit8 v1, v1, 0x1

    .line 511
    .line 512
    goto :goto_e

    .line 513
    :cond_1c
    move v11, v1

    .line 514
    goto :goto_10

    .line 515
    :cond_1d
    move v11, v2

    .line 516
    :goto_10
    add-int/lit8 v1, v11, 0x1

    .line 517
    .line 518
    const/4 v3, 0x4

    .line 519
    const/16 v9, 0x22

    .line 520
    .line 521
    if-ge v1, v2, :cond_20

    .line 522
    .line 523
    invoke-static {v8, v11, v3, v4}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 524
    .line 525
    .line 526
    move-result-object v3

    .line 527
    invoke-static {v3}, Le01/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 528
    .line 529
    .line 530
    move-result-object v3

    .line 531
    iput-object v3, v0, Ld01/z;->f:Ljava/lang/Object;

    .line 532
    .line 533
    :try_start_0
    const-string v5, ""

    .line 534
    .line 535
    const/4 v6, 0x0

    .line 536
    const/16 v3, 0x78

    .line 537
    .line 538
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v3

    .line 542
    invoke-static {v3}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 543
    .line 544
    .line 545
    move-result v3
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 546
    move/from16 v5, v16

    .line 547
    .line 548
    if-gt v5, v3, :cond_1e

    .line 549
    .line 550
    const/high16 v5, 0x10000

    .line 551
    .line 552
    if-ge v3, v5, :cond_1e

    .line 553
    .line 554
    goto :goto_11

    .line 555
    :catch_0
    :cond_1e
    move v3, v10

    .line 556
    :goto_11
    iput v3, v0, Ld01/z;->b:I

    .line 557
    .line 558
    if-eq v3, v10, :cond_1f

    .line 559
    .line 560
    goto :goto_13

    .line 561
    :cond_1f
    new-instance v0, Ljava/lang/StringBuilder;

    .line 562
    .line 563
    const-string v3, "Invalid URL port: \""

    .line 564
    .line 565
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 566
    .line 567
    .line 568
    invoke-virtual {v4, v1, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object v1

    .line 572
    invoke-static {v1, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 576
    .line 577
    .line 578
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 579
    .line 580
    .line 581
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 582
    .line 583
    .line 584
    move-result-object v0

    .line 585
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 586
    .line 587
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 588
    .line 589
    .line 590
    move-result-object v0

    .line 591
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    throw v1

    .line 595
    :cond_20
    invoke-static {v8, v11, v3, v4}, Ls01/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 596
    .line 597
    .line 598
    move-result-object v1

    .line 599
    invoke-static {v1}, Le01/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 600
    .line 601
    .line 602
    move-result-object v1

    .line 603
    iput-object v1, v0, Ld01/z;->f:Ljava/lang/Object;

    .line 604
    .line 605
    iget-object v1, v0, Ld01/z;->c:Ljava/lang/Object;

    .line 606
    .line 607
    check-cast v1, Ljava/lang/String;

    .line 608
    .line 609
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 610
    .line 611
    .line 612
    invoke-virtual {v1, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 613
    .line 614
    .line 615
    move-result v3

    .line 616
    if-eqz v3, :cond_21

    .line 617
    .line 618
    const/16 v10, 0x50

    .line 619
    .line 620
    goto :goto_12

    .line 621
    :cond_21
    invoke-virtual {v1, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 622
    .line 623
    .line 624
    move-result v1

    .line 625
    if-eqz v1, :cond_22

    .line 626
    .line 627
    const/16 v10, 0x1bb

    .line 628
    .line 629
    :cond_22
    :goto_12
    iput v10, v0, Ld01/z;->b:I

    .line 630
    .line 631
    :goto_13
    iget-object v1, v0, Ld01/z;->f:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast v1, Ljava/lang/String;

    .line 634
    .line 635
    if-eqz v1, :cond_25

    .line 636
    .line 637
    move v3, v2

    .line 638
    :goto_14
    const-string v1, "?#"

    .line 639
    .line 640
    invoke-static {v4, v1, v3, v7}, Le01/e;->f(Ljava/lang/String;Ljava/lang/String;II)I

    .line 641
    .line 642
    .line 643
    move-result v1

    .line 644
    invoke-virtual {v0, v3, v1, v4}, Ld01/z;->j(IILjava/lang/String;)V

    .line 645
    .line 646
    .line 647
    if-ge v1, v7, :cond_23

    .line 648
    .line 649
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 650
    .line 651
    .line 652
    move-result v2

    .line 653
    if-ne v2, v15, :cond_23

    .line 654
    .line 655
    const/16 v8, 0x23

    .line 656
    .line 657
    invoke-static {v4, v8, v1, v7}, Le01/e;->e(Ljava/lang/String;CII)I

    .line 658
    .line 659
    .line 660
    move-result v2

    .line 661
    add-int/lit8 v1, v1, 0x1

    .line 662
    .line 663
    const/4 v6, 0x1

    .line 664
    const/16 v3, 0x50

    .line 665
    .line 666
    const-string v5, " \"\'<>#"

    .line 667
    .line 668
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 669
    .line 670
    .line 671
    move-result-object v1

    .line 672
    invoke-static {v1}, Ld01/z;->l(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 673
    .line 674
    .line 675
    move-result-object v1

    .line 676
    iput-object v1, v0, Ld01/z;->i:Ljava/lang/Object;

    .line 677
    .line 678
    move v1, v2

    .line 679
    goto :goto_15

    .line 680
    :cond_23
    const/16 v8, 0x23

    .line 681
    .line 682
    :goto_15
    if-ge v1, v7, :cond_24

    .line 683
    .line 684
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 685
    .line 686
    .line 687
    move-result v2

    .line 688
    if-ne v2, v8, :cond_24

    .line 689
    .line 690
    const/16 v16, 0x1

    .line 691
    .line 692
    add-int/lit8 v1, v1, 0x1

    .line 693
    .line 694
    const/4 v6, 0x1

    .line 695
    const/16 v3, 0x30

    .line 696
    .line 697
    const-string v5, ""

    .line 698
    .line 699
    move v2, v7

    .line 700
    invoke-static/range {v1 .. v6}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 701
    .line 702
    .line 703
    move-result-object v1

    .line 704
    iput-object v1, v0, Ld01/z;->g:Ljava/lang/Object;

    .line 705
    .line 706
    :cond_24
    return-void

    .line 707
    :cond_25
    new-instance v0, Ljava/lang/StringBuilder;

    .line 708
    .line 709
    const-string v1, "Invalid URL host: \""

    .line 710
    .line 711
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 712
    .line 713
    .line 714
    invoke-virtual {v4, v8, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 715
    .line 716
    .line 717
    move-result-object v1

    .line 718
    invoke-static {v1, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 722
    .line 723
    .line 724
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 725
    .line 726
    .line 727
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 728
    .line 729
    .line 730
    move-result-object v0

    .line 731
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 732
    .line 733
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 734
    .line 735
    .line 736
    move-result-object v0

    .line 737
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    throw v1

    .line 741
    :cond_26
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 742
    .line 743
    .line 744
    move-result v0

    .line 745
    const/4 v1, 0x6

    .line 746
    if-le v0, v1, :cond_27

    .line 747
    .line 748
    invoke-static {v1, v4}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 749
    .line 750
    .line 751
    move-result-object v0

    .line 752
    const-string v1, "..."

    .line 753
    .line 754
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 755
    .line 756
    .line 757
    move-result-object v0

    .line 758
    goto :goto_16

    .line 759
    :cond_27
    move-object v0, v4

    .line 760
    :goto_16
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 761
    .line 762
    const-string v2, "Expected URL scheme \'http\' or \'https\' but no scheme was found for "

    .line 763
    .line 764
    invoke-static {v2, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 765
    .line 766
    .line 767
    move-result-object v0

    .line 768
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 769
    .line 770
    .line 771
    throw v1
.end method

.method public i(IILjava/lang/String;ZZ)V
    .locals 6

    .line 1
    iget-object p0, p0, Ld01/z;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const-string v4, " \"<>^`{}|/\\?#"

    .line 6
    .line 7
    const/16 v2, 0x70

    .line 8
    .line 9
    move v0, p1

    .line 10
    move v1, p2

    .line 11
    move-object v3, p3

    .line 12
    move v5, p5

    .line 13
    invoke-static/range {v0 .. v5}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const-string p2, "."

    .line 18
    .line 19
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-nez p2, :cond_5

    .line 24
    .line 25
    const-string p2, "%2e"

    .line 26
    .line 27
    invoke-virtual {p1, p2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_0

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_0
    const-string p2, ".."

    .line 35
    .line 36
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    const-string p3, ""

    .line 41
    .line 42
    const/4 p5, 0x1

    .line 43
    if-nez p2, :cond_3

    .line 44
    .line 45
    const-string p2, "%2e."

    .line 46
    .line 47
    invoke-virtual {p1, p2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-nez p2, :cond_3

    .line 52
    .line 53
    const-string p2, ".%2e"

    .line 54
    .line 55
    invoke-virtual {p1, p2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    if-nez p2, :cond_3

    .line 60
    .line 61
    const-string p2, "%2e%2e"

    .line 62
    .line 63
    invoke-virtual {p1, p2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 64
    .line 65
    .line 66
    move-result p2

    .line 67
    if-eqz p2, :cond_1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-static {p0, p5}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    check-cast p2, Ljava/lang/CharSequence;

    .line 75
    .line 76
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    if-nez p2, :cond_2

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    sub-int/2addr p2, p5

    .line 87
    invoke-virtual {p0, p2, p1}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    :goto_0
    if-eqz p4, :cond_5

    .line 95
    .line 96
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :cond_3
    :goto_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    sub-int/2addr p1, p5

    .line 105
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    check-cast p1, Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    if-nez p1, :cond_4

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    if-nez p1, :cond_4

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    sub-int/2addr p1, p5

    .line 128
    invoke-virtual {p0, p1, p3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_4
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    :cond_5
    :goto_2
    return-void
.end method

.method public j(IILjava/lang/String;)V
    .locals 11

    .line 1
    iget-object v0, p0, Ld01/z;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    if-ne p1, p2, :cond_0

    .line 6
    .line 7
    goto :goto_4

    .line 8
    :cond_0
    invoke-virtual {p3, p1}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/16 v2, 0x2f

    .line 13
    .line 14
    const-string v3, ""

    .line 15
    .line 16
    const/4 v4, 0x1

    .line 17
    if-eq v1, v2, :cond_1

    .line 18
    .line 19
    const/16 v2, 0x5c

    .line 20
    .line 21
    if-eq v1, v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    sub-int/2addr v1, v4

    .line 28
    invoke-virtual {v0, v1, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    add-int/lit8 p1, p1, 0x1

    .line 39
    .line 40
    :goto_0
    move v6, p1

    .line 41
    :goto_1
    if-ge v6, p2, :cond_4

    .line 42
    .line 43
    const-string p1, "/\\"

    .line 44
    .line 45
    invoke-static {p3, p1, v6, p2}, Le01/e;->f(Ljava/lang/String;Ljava/lang/String;II)I

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    if-ge v7, p2, :cond_2

    .line 50
    .line 51
    move v9, v4

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/4 p1, 0x0

    .line 54
    move v9, p1

    .line 55
    :goto_2
    const/4 v10, 0x1

    .line 56
    move-object v5, p0

    .line 57
    move-object v8, p3

    .line 58
    invoke-virtual/range {v5 .. v10}, Ld01/z;->i(IILjava/lang/String;ZZ)V

    .line 59
    .line 60
    .line 61
    if-eqz v9, :cond_3

    .line 62
    .line 63
    add-int/lit8 v6, v7, 0x1

    .line 64
    .line 65
    move-object p0, v5

    .line 66
    :goto_3
    move-object p3, v8

    .line 67
    goto :goto_1

    .line 68
    :cond_3
    move-object p0, v5

    .line 69
    move v6, v7

    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_4
    return-void
.end method

.method public k(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "http"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iput-object v0, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    const-string v0, "https"

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    iput-object v0, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 21
    .line 22
    return-void

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string v0, "unexpected scheme: "

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget v0, p0, Ld01/z;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Ljava/lang/String;

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, "://"

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const-string v1, "//"

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v1, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 37
    .line 38
    check-cast v1, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/16 v2, 0x3a

    .line 45
    .line 46
    if-lez v1, :cond_1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    iget-object v1, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 50
    .line 51
    check-cast v1, Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-lez v1, :cond_3

    .line 58
    .line 59
    :goto_1
    iget-object v1, p0, Ld01/z;->d:Ljava/io/Serializable;

    .line 60
    .line 61
    check-cast v1, Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 67
    .line 68
    check-cast v1, Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-lez v1, :cond_2

    .line 75
    .line 76
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Ld01/z;->e:Ljava/io/Serializable;

    .line 80
    .line 81
    check-cast v1, Ljava/lang/String;

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    :cond_2
    const/16 v1, 0x40

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    :cond_3
    iget-object v1, p0, Ld01/z;->f:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v1, Ljava/lang/String;

    .line 94
    .line 95
    if-eqz v1, :cond_5

    .line 96
    .line 97
    invoke-static {v1, v2}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_4

    .line 102
    .line 103
    const/16 v1, 0x5b

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Ld01/z;->f:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v1, Ljava/lang/String;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const/16 v1, 0x5d

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_4
    iget-object v1, p0, Ld01/z;->f:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v1, Ljava/lang/String;

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    :cond_5
    :goto_2
    iget v1, p0, Ld01/z;->b:I

    .line 129
    .line 130
    const/4 v3, -0x1

    .line 131
    if-ne v1, v3, :cond_6

    .line 132
    .line 133
    iget-object v1, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v1, Ljava/lang/String;

    .line 136
    .line 137
    if-eqz v1, :cond_a

    .line 138
    .line 139
    :cond_6
    invoke-virtual {p0}, Ld01/z;->d()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    iget-object v4, p0, Ld01/z;->c:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v4, Ljava/lang/String;

    .line 146
    .line 147
    if-eqz v4, :cond_9

    .line 148
    .line 149
    const-string v5, "http"

    .line 150
    .line 151
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v5

    .line 155
    if-eqz v5, :cond_7

    .line 156
    .line 157
    const/16 v3, 0x50

    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_7
    const-string v5, "https"

    .line 161
    .line 162
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v4

    .line 166
    if-eqz v4, :cond_8

    .line 167
    .line 168
    const/16 v3, 0x1bb

    .line 169
    .line 170
    :cond_8
    :goto_3
    if-eq v1, v3, :cond_a

    .line 171
    .line 172
    :cond_9
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    :cond_a
    iget-object v1, p0, Ld01/z;->h:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast v1, Ljava/util/ArrayList;

    .line 181
    .line 182
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    const/4 v3, 0x0

    .line 187
    :goto_4
    if-ge v3, v2, :cond_b

    .line 188
    .line 189
    const/16 v4, 0x2f

    .line 190
    .line 191
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Ljava/lang/String;

    .line 199
    .line 200
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    add-int/lit8 v3, v3, 0x1

    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_b
    iget-object v1, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v1, Ljava/util/ArrayList;

    .line 209
    .line 210
    if-eqz v1, :cond_c

    .line 211
    .line 212
    const/16 v1, 0x3f

    .line 213
    .line 214
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    iget-object v1, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v1, Ljava/util/ArrayList;

    .line 220
    .line 221
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    invoke-static {v1, v0}, Ld01/r;->b(Ljava/util/List;Ljava/lang/StringBuilder;)V

    .line 225
    .line 226
    .line 227
    :cond_c
    iget-object v1, p0, Ld01/z;->g:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v1, Ljava/lang/String;

    .line 230
    .line 231
    if-eqz v1, :cond_d

    .line 232
    .line 233
    const/16 v1, 0x23

    .line 234
    .line 235
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    iget-object p0, p0, Ld01/z;->g:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast p0, Ljava/lang/String;

    .line 241
    .line 242
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 243
    .line 244
    .line 245
    :cond_d
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object p0

    .line 249
    return-object p0

    .line 250
    nop

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
