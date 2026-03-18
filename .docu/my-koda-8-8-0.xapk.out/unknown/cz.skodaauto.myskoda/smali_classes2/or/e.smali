.class public final Lor/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmr/b;


# instance fields
.field public final a:Lil/g;

.field public final b:[B


# direct methods
.method public constructor <init>(Lil/g;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aput-byte v1, v0, v1

    .line 9
    .line 10
    iput-object v0, p0, Lor/e;->b:[B

    .line 11
    .line 12
    iput-object p1, p0, Lor/e;->a:Lil/g;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a([B[B)V
    .locals 7

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x5

    .line 3
    if-le v0, v1, :cond_3

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    array-length v2, p1

    .line 10
    invoke-static {p1, v1, v2}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v2, p0, Lor/e;->a:Lil/g;

    .line 15
    .line 16
    invoke-virtual {v2, v0}, Lil/g;->H([B)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    check-cast v3, Lmr/c;

    .line 35
    .line 36
    :try_start_0
    iget-object v4, v3, Lmr/c;->d:Lqr/d0;

    .line 37
    .line 38
    sget-object v5, Lqr/d0;->g:Lqr/d0;

    .line 39
    .line 40
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_0

    .line 45
    .line 46
    iget-object v3, v3, Lmr/c;->a:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v3, Lmr/b;

    .line 49
    .line 50
    iget-object v4, p0, Lor/e;->b:[B

    .line 51
    .line 52
    filled-new-array {p2, v4}, [[B

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-static {v4}, Lkp/c6;->a([[B)[B

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    invoke-interface {v3, v1, v4}, Lmr/b;->a([B[B)V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :catch_0
    move-exception v3

    .line 65
    goto :goto_1

    .line 66
    :cond_0
    iget-object v3, v3, Lmr/c;->a:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v3, Lmr/b;

    .line 69
    .line 70
    invoke-interface {v3, v1, p2}, Lmr/b;->a([B[B)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :goto_1
    sget-object v4, Lor/f;->a:Ljava/util/logging/Logger;

    .line 75
    .line 76
    new-instance v5, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v6, "tag prefix matches a key, but cannot verify: "

    .line 79
    .line 80
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-virtual {v4, v3}, Ljava/util/logging/Logger;->info(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_1
    sget-object p0, Lmr/a;->a:[B

    .line 95
    .line 96
    invoke-virtual {v2, p0}, Lil/g;->H([B)Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    :catch_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    if-eqz v0, :cond_2

    .line 109
    .line 110
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    check-cast v0, Lmr/c;

    .line 115
    .line 116
    :try_start_1
    iget-object v0, v0, Lmr/c;->a:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v0, Lmr/b;

    .line 119
    .line 120
    invoke-interface {v0, p1, p2}, Lmr/b;->a([B[B)V
    :try_end_1
    .catch Ljava/security/GeneralSecurityException; {:try_start_1 .. :try_end_1} :catch_1

    .line 121
    .line 122
    .line 123
    :goto_2
    return-void

    .line 124
    :cond_2
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 125
    .line 126
    const-string p1, "invalid MAC"

    .line 127
    .line 128
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :cond_3
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 133
    .line 134
    const-string p1, "tag too short"

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0
.end method

.method public final b([B)[B
    .locals 3

    .line 1
    iget-object v0, p0, Lor/e;->a:Lil/g;

    .line 2
    .line 3
    iget-object v1, v0, Lil/g;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lmr/c;

    .line 6
    .line 7
    iget-object v1, v1, Lmr/c;->d:Lqr/d0;

    .line 8
    .line 9
    sget-object v2, Lqr/d0;->g:Lqr/d0;

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    iget-object v1, v0, Lil/g;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lmr/c;

    .line 21
    .line 22
    iget-object v1, v1, Lmr/c;->b:[B

    .line 23
    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    array-length v2, v1

    .line 28
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    :goto_0
    iget-object v0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lmr/c;

    .line 35
    .line 36
    iget-object v0, v0, Lmr/c;->a:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lmr/b;

    .line 39
    .line 40
    iget-object p0, p0, Lor/e;->b:[B

    .line 41
    .line 42
    filled-new-array {p1, p0}, [[B

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-static {p0}, Lkp/c6;->a([[B)[B

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-interface {v0, p0}, Lmr/b;->b([B)[B

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    filled-new-array {v2, p0}, [[B

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-static {p0}, Lkp/c6;->a([[B)[B

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_1
    iget-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, Lmr/c;

    .line 66
    .line 67
    iget-object p0, p0, Lmr/c;->b:[B

    .line 68
    .line 69
    if-nez p0, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    array-length v1, p0

    .line 73
    invoke-static {p0, v1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    :goto_1
    iget-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lmr/c;

    .line 80
    .line 81
    iget-object p0, p0, Lmr/c;->a:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Lmr/b;

    .line 84
    .line 85
    invoke-interface {p0, p1}, Lmr/b;->b([B)[B

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    filled-new-array {v2, p0}, [[B

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {p0}, Lkp/c6;->a([[B)[B

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0
.end method
