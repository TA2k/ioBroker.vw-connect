.class public final Lwz0/b0;
.super Llp/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvz0/r;


# instance fields
.field public final a:Lb6/f;

.field public final b:Lvz0/d;

.field public final c:Lwz0/f0;

.field public final d:[Lvz0/r;

.field public final e:Lwq/f;

.field public final f:Lvz0/k;

.field public g:Z

.field public h:Ljava/lang/String;

.field public i:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lb6/f;Lvz0/d;Lwz0/f0;[Lvz0/r;)V
    .locals 1

    .line 1
    const-string v0, "composer"

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
    iput-object p1, p0, Lwz0/b0;->a:Lb6/f;

    .line 10
    .line 11
    iput-object p2, p0, Lwz0/b0;->b:Lvz0/d;

    .line 12
    .line 13
    iput-object p3, p0, Lwz0/b0;->c:Lwz0/f0;

    .line 14
    .line 15
    iput-object p4, p0, Lwz0/b0;->d:[Lvz0/r;

    .line 16
    .line 17
    iget-object p1, p2, Lvz0/d;->b:Lwq/f;

    .line 18
    .line 19
    iput-object p1, p0, Lwz0/b0;->e:Lwq/f;

    .line 20
    .line 21
    iget-object p1, p2, Lvz0/d;->a:Lvz0/k;

    .line 22
    .line 23
    iput-object p1, p0, Lwz0/b0;->f:Lvz0/k;

    .line 24
    .line 25
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p4, :cond_1

    .line 30
    .line 31
    aget-object p2, p4, p1

    .line 32
    .line 33
    if-nez p2, :cond_0

    .line 34
    .line 35
    if-eq p2, p0, :cond_1

    .line 36
    .line 37
    :cond_0
    aput-object p0, p4, p1

    .line 38
    .line 39
    :cond_1
    return-void
.end method


# virtual methods
.method public final A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serializer"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    if-nez p4, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lwz0/b0;->f:Lvz0/k;

    .line 14
    .line 15
    iget-boolean v0, v0, Lvz0/k;->e:Z

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    return-void

    .line 21
    :cond_1
    :goto_0
    invoke-super {p0, p1, p2, p3, p4}, Llp/v0;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final B(I)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Lb6/f;->r(I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final D(Lqz0/a;Ljava/lang/Object;)V
    .locals 4

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/b0;->b:Lvz0/d;

    .line 7
    .line 8
    iget-object v1, v0, Lvz0/d;->a:Lvz0/k;

    .line 9
    .line 10
    instance-of v2, p1, Luz0/b;

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    iget-object v1, v1, Lvz0/k;->j:Lvz0/a;

    .line 15
    .line 16
    sget-object v3, Lvz0/a;->d:Lvz0/a;

    .line 17
    .line 18
    if-eq v1, v3, :cond_4

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-object v1, v1, Lvz0/k;->j:Lvz0/a;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_4

    .line 28
    .line 29
    const/4 v3, 0x1

    .line 30
    if-eq v1, v3, :cond_2

    .line 31
    .line 32
    const/4 v0, 0x2

    .line 33
    if-ne v1, v0, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    new-instance p0, La8/r0;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_2
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-interface {v1}, Lsz0/g;->getKind()Lkp/y8;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    sget-object v3, Lsz0/k;->b:Lsz0/k;

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-nez v3, :cond_3

    .line 57
    .line 58
    sget-object v3, Lsz0/k;->e:Lsz0/k;

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_4

    .line 65
    .line 66
    :cond_3
    :goto_0
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-static {v1, v0}, Lwz0/p;->i(Lsz0/g;Lvz0/d;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    goto :goto_2

    .line 75
    :cond_4
    :goto_1
    const/4 v0, 0x0

    .line 76
    :goto_2
    if-eqz v2, :cond_7

    .line 77
    .line 78
    move-object v1, p1

    .line 79
    check-cast v1, Luz0/b;

    .line 80
    .line 81
    if-eqz p2, :cond_6

    .line 82
    .line 83
    invoke-static {v1, p0, p2}, Ljp/lg;->c(Luz0/b;Ltz0/d;Ljava/lang/Object;)Lqz0/a;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    if-eqz v0, :cond_5

    .line 88
    .line 89
    invoke-static {p1, v1, v0}, Lwz0/p;->e(Lqz0/a;Lqz0/a;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-interface {p1}, Lsz0/g;->getKind()Lkp/y8;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-static {p1}, Lwz0/p;->h(Lkp/y8;)V

    .line 101
    .line 102
    .line 103
    :cond_5
    move-object p1, v1

    .line 104
    goto :goto_3

    .line 105
    :cond_6
    new-instance p0, Ljava/lang/StringBuilder;

    .line 106
    .line 107
    const-string p1, "Value for serializer "

    .line 108
    .line 109
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    const-string p1, " should always be non-null. Please report issue to the kotlinx.serialization tracker."

    .line 120
    .line 121
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 129
    .line 130
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p1

    .line 138
    :cond_7
    :goto_3
    if-eqz v0, :cond_8

    .line 139
    .line 140
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    invoke-interface {v1}, Lsz0/g;->h()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    iput-object v0, p0, Lwz0/b0;->h:Ljava/lang/String;

    .line 149
    .line 150
    iput-object v1, p0, Lwz0/b0;->i:Ljava/lang/String;

    .line 151
    .line 152
    :cond_8
    invoke-interface {p1, p0, p2}, Lqz0/a;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    return-void
.end method

.method public final E(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final G(Lsz0/g;I)V
    .locals 7

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/b0;->c:Lwz0/f0;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/16 v1, 0x2c

    .line 13
    .line 14
    iget-object v2, p0, Lwz0/b0;->a:Lb6/f;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    if-eq v0, v3, :cond_7

    .line 18
    .line 19
    const/16 v4, 0x3a

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    const/4 v6, 0x2

    .line 23
    if-eq v0, v6, :cond_4

    .line 24
    .line 25
    const/4 v6, 0x3

    .line 26
    if-eq v0, v6, :cond_1

    .line 27
    .line 28
    iget-boolean v0, v2, Lb6/f;->d:Z

    .line 29
    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {v2, v1}, Lb6/f;->q(C)V

    .line 33
    .line 34
    .line 35
    :cond_0
    invoke-virtual {v2}, Lb6/f;->o()V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lwz0/b0;->b:Lvz0/d;

    .line 39
    .line 40
    invoke-static {p1, v0}, Lwz0/p;->o(Lsz0/g;Lvz0/d;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p1, p2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2, v4}, Lb6/f;->q(C)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2}, Lb6/f;->w()V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    if-nez p2, :cond_2

    .line 58
    .line 59
    iput-boolean v3, p0, Lwz0/b0;->g:Z

    .line 60
    .line 61
    :cond_2
    if-ne p2, v3, :cond_3

    .line 62
    .line 63
    invoke-virtual {v2, v1}, Lb6/f;->q(C)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Lb6/f;->w()V

    .line 67
    .line 68
    .line 69
    iput-boolean v5, p0, Lwz0/b0;->g:Z

    .line 70
    .line 71
    :cond_3
    return-void

    .line 72
    :cond_4
    iget-boolean p1, v2, Lb6/f;->d:Z

    .line 73
    .line 74
    if-nez p1, :cond_6

    .line 75
    .line 76
    rem-int/2addr p2, v6

    .line 77
    if-nez p2, :cond_5

    .line 78
    .line 79
    invoke-virtual {v2, v1}, Lb6/f;->q(C)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2}, Lb6/f;->o()V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_5
    invoke-virtual {v2, v4}, Lb6/f;->q(C)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2}, Lb6/f;->w()V

    .line 90
    .line 91
    .line 92
    move v3, v5

    .line 93
    :goto_0
    iput-boolean v3, p0, Lwz0/b0;->g:Z

    .line 94
    .line 95
    return-void

    .line 96
    :cond_6
    iput-boolean v3, p0, Lwz0/b0;->g:Z

    .line 97
    .line 98
    invoke-virtual {v2}, Lb6/f;->o()V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :cond_7
    iget-boolean p0, v2, Lb6/f;->d:Z

    .line 103
    .line 104
    if-nez p0, :cond_8

    .line 105
    .line 106
    invoke-virtual {v2, v1}, Lb6/f;->q(C)V

    .line 107
    .line 108
    .line 109
    :cond_8
    invoke-virtual {v2}, Lb6/f;->o()V

    .line 110
    .line 111
    .line 112
    return-void
.end method

.method public final a(Lsz0/g;)Ltz0/b;
    .locals 5

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwz0/b0;->b:Lvz0/d;

    .line 7
    .line 8
    invoke-static {p1, v0}, Lwz0/p;->q(Lsz0/g;Lvz0/d;)Lwz0/f0;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-char v2, v1, Lwz0/f0;->d:C

    .line 13
    .line 14
    iget-object v3, p0, Lwz0/b0;->a:Lb6/f;

    .line 15
    .line 16
    invoke-virtual {v3, v2}, Lb6/f;->q(C)V

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    iput-boolean v2, v3, Lb6/f;->d:Z

    .line 21
    .line 22
    iget-object v2, p0, Lwz0/b0;->h:Ljava/lang/String;

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    iget-object v4, p0, Lwz0/b0;->i:Ljava/lang/String;

    .line 27
    .line 28
    if-nez v4, :cond_0

    .line 29
    .line 30
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    :cond_0
    invoke-virtual {v3}, Lb6/f;->o()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, v2}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/16 p1, 0x3a

    .line 41
    .line 42
    invoke-virtual {v3, p1}, Lb6/f;->q(C)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v4}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const/4 p1, 0x0

    .line 49
    iput-object p1, p0, Lwz0/b0;->h:Ljava/lang/String;

    .line 50
    .line 51
    iput-object p1, p0, Lwz0/b0;->i:Ljava/lang/String;

    .line 52
    .line 53
    :cond_1
    iget-object p1, p0, Lwz0/b0;->c:Lwz0/f0;

    .line 54
    .line 55
    if-ne p1, v1, :cond_2

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_2
    iget-object p0, p0, Lwz0/b0;->d:[Lvz0/r;

    .line 59
    .line 60
    if-eqz p0, :cond_3

    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    aget-object p1, p0, p1

    .line 67
    .line 68
    if-eqz p1, :cond_3

    .line 69
    .line 70
    return-object p1

    .line 71
    :cond_3
    new-instance p1, Lwz0/b0;

    .line 72
    .line 73
    invoke-direct {p1, v3, v0, v1, p0}, Lwz0/b0;-><init>(Lb6/f;Lvz0/d;Lwz0/f0;[Lvz0/r;)V

    .line 74
    .line 75
    .line 76
    return-object p1
.end method

.method public final b(Lsz0/g;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lwz0/b0;->a:Lb6/f;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p1, Lb6/f;->d:Z

    .line 13
    .line 14
    iget-object p0, p0, Lwz0/b0;->c:Lwz0/f0;

    .line 15
    .line 16
    iget-char p0, p0, Lwz0/f0;->e:C

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Lb6/f;->q(C)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/b0;->e:Lwq/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(D)V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    iget-object v1, p0, Lwz0/b0;->a:Lb6/f;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, v0}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object v0, v1, Lb6/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lb11/a;

    .line 18
    .line 19
    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v0, v2}, Lb11/a;->m(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :goto_0
    iget-object p0, p0, Lwz0/b0;->f:Lvz0/k;

    .line 27
    .line 28
    iget-boolean p0, p0, Lvz0/k;->h:Z

    .line 29
    .line 30
    if-nez p0, :cond_2

    .line 31
    .line 32
    invoke-static {p1, p2}, Ljava/lang/Math;->abs(D)D

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    const-wide v4, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    cmpg-double p0, v2, v4

    .line 42
    .line 43
    if-gtz p0, :cond_1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    iget-object p1, v1, Lb6/f;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p1, Lb11/a;

    .line 53
    .line 54
    invoke-virtual {p1}, Lb11/a;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-static {p0, p1}, Lwz0/p;->a(Ljava/lang/Number;Ljava/lang/String;)Lwz0/l;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    throw p0

    .line 63
    :cond_2
    :goto_1
    return-void
.end method

.method public final e(Lsz0/g;)Z
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lwz0/b0;->f:Lvz0/k;

    .line 7
    .line 8
    iget-boolean p0, p0, Lvz0/k;->a:Z

    .line 9
    .line 10
    return p0
.end method

.method public final f(B)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Lb6/f;->p(B)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final i(Lsz0/g;I)V
    .locals 1

    .line 1
    const-string v0, "enumDescriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final j(Lsz0/g;)Ltz0/d;
    .locals 5

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lwz0/c0;->a(Lsz0/g;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    iget-object v2, p0, Lwz0/b0;->c:Lwz0/f0;

    .line 12
    .line 13
    iget-object v3, p0, Lwz0/b0;->b:Lvz0/d;

    .line 14
    .line 15
    iget-object v4, p0, Lwz0/b0;->a:Lb6/f;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    instance-of p1, v4, Lwz0/j;

    .line 20
    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iget-object p1, v4, Lb6/f;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Lb11/a;

    .line 27
    .line 28
    iget-boolean p0, p0, Lwz0/b0;->g:Z

    .line 29
    .line 30
    new-instance v4, Lwz0/j;

    .line 31
    .line 32
    invoke-direct {v4, p1, p0}, Lwz0/j;-><init>(Lb11/a;Z)V

    .line 33
    .line 34
    .line 35
    :goto_0
    new-instance p0, Lwz0/b0;

    .line 36
    .line 37
    invoke-direct {p0, v4, v3, v2, v1}, Lwz0/b0;-><init>(Lb6/f;Lvz0/d;Lwz0/f0;[Lvz0/r;)V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_1
    invoke-interface {p1}, Lsz0/g;->isInline()Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_3

    .line 46
    .line 47
    sget-object v0, Lvz0/o;->a:Luz0/f0;

    .line 48
    .line 49
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    instance-of p1, v4, Lwz0/i;

    .line 56
    .line 57
    if-eqz p1, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    iget-object p1, v4, Lb6/f;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Lb11/a;

    .line 63
    .line 64
    iget-boolean p0, p0, Lwz0/b0;->g:Z

    .line 65
    .line 66
    new-instance v4, Lwz0/i;

    .line 67
    .line 68
    invoke-direct {v4, p1, p0}, Lwz0/i;-><init>(Lb11/a;Z)V

    .line 69
    .line 70
    .line 71
    :goto_1
    new-instance p0, Lwz0/b0;

    .line 72
    .line 73
    invoke-direct {p0, v4, v3, v2, v1}, Lwz0/b0;-><init>(Lb6/f;Lvz0/d;Lwz0/f0;[Lvz0/r;)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_3
    iget-object v0, p0, Lwz0/b0;->h:Ljava/lang/String;

    .line 78
    .line 79
    if-eqz v0, :cond_4

    .line 80
    .line 81
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    iput-object p1, p0, Lwz0/b0;->i:Ljava/lang/String;

    .line 86
    .line 87
    :cond_4
    return-object p0
.end method

.method public final m(J)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lb6/f;->s(J)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final p()V
    .locals 1

    .line 1
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 2
    .line 3
    const-string v0, "null"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lb6/f;->t(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final r(S)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Lb6/f;->u(S)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final s(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lwz0/b0;->a:Lb6/f;

    .line 14
    .line 15
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lb11/a;

    .line 18
    .line 19
    invoke-static {p1}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final u(F)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lwz0/b0;->g:Z

    .line 2
    .line 3
    iget-object v1, p0, Lwz0/b0;->a:Lb6/f;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p1}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, v0}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object v0, v1, Lb6/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lb11/a;

    .line 18
    .line 19
    invoke-static {p1}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v0, v2}, Lb11/a;->m(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :goto_0
    iget-object p0, p0, Lwz0/b0;->f:Lvz0/k;

    .line 27
    .line 28
    iget-boolean p0, p0, Lvz0/k;->h:Z

    .line 29
    .line 30
    if-nez p0, :cond_2

    .line 31
    .line 32
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 37
    .line 38
    .line 39
    cmpg-float p0, p0, v0

    .line 40
    .line 41
    if-gtz p0, :cond_1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    iget-object p1, v1, Lb6/f;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p1, Lb11/a;

    .line 51
    .line 52
    invoke-virtual {p1}, Lb11/a;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-static {p0, p1}, Lwz0/p;->a(Ljava/lang/Number;Ljava/lang/String;)Lwz0/l;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    throw p0

    .line 61
    :cond_2
    :goto_1
    return-void
.end method

.method public final v(C)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0, p1}, Lwz0/b0;->E(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
