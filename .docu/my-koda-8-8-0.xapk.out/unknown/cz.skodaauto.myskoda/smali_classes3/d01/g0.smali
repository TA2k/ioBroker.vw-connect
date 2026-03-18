.class public final Ld01/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:I

.field public B:I

.field public C:J

.field public D:Lbu/c;

.field public E:Lg01/c;

.field public a:Ld01/t;

.field public b:Lbu/c;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public e:Lc1/y;

.field public f:Z

.field public g:Z

.field public h:Ld01/c;

.field public i:Z

.field public j:Z

.field public k:Ld01/r;

.field public l:Ld01/g;

.field public m:Ld01/r;

.field public n:Ljava/net/ProxySelector;

.field public o:Ld01/b;

.field public p:Ljavax/net/SocketFactory;

.field public q:Ljavax/net/ssl/SSLSocketFactory;

.field public r:Ljavax/net/ssl/X509TrustManager;

.field public s:Ljava/util/List;

.field public t:Ljava/util/List;

.field public u:Lr01/c;

.field public v:Ld01/l;

.field public w:Lkp/g;

.field public x:I

.field public y:I

.field public z:I


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ld01/t;

    .line 5
    .line 6
    invoke-direct {v0}, Ld01/t;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ld01/g0;->a:Ld01/t;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ld01/g0;->c:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Ld01/g0;->d:Ljava/util/ArrayList;

    .line 24
    .line 25
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 26
    .line 27
    new-instance v0, Lc1/y;

    .line 28
    .line 29
    const/16 v1, 0x15

    .line 30
    .line 31
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Ld01/g0;->e:Lc1/y;

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    iput-boolean v0, p0, Ld01/g0;->f:Z

    .line 38
    .line 39
    iput-boolean v0, p0, Ld01/g0;->g:Z

    .line 40
    .line 41
    sget-object v1, Ld01/c;->a:Ld01/b;

    .line 42
    .line 43
    iput-object v1, p0, Ld01/g0;->h:Ld01/c;

    .line 44
    .line 45
    iput-boolean v0, p0, Ld01/g0;->i:Z

    .line 46
    .line 47
    iput-boolean v0, p0, Ld01/g0;->j:Z

    .line 48
    .line 49
    sget-object v0, Ld01/r;->d:Ld01/r;

    .line 50
    .line 51
    iput-object v0, p0, Ld01/g0;->k:Ld01/r;

    .line 52
    .line 53
    sget-object v0, Ld01/r;->e:Ld01/r;

    .line 54
    .line 55
    iput-object v0, p0, Ld01/g0;->m:Ld01/r;

    .line 56
    .line 57
    iput-object v1, p0, Ld01/g0;->o:Ld01/b;

    .line 58
    .line 59
    invoke-static {}, Ljavax/net/SocketFactory;->getDefault()Ljavax/net/SocketFactory;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    const-string v1, "getDefault(...)"

    .line 64
    .line 65
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iput-object v0, p0, Ld01/g0;->p:Ljavax/net/SocketFactory;

    .line 69
    .line 70
    sget-object v0, Ld01/h0;->G:Ljava/util/List;

    .line 71
    .line 72
    iput-object v0, p0, Ld01/g0;->s:Ljava/util/List;

    .line 73
    .line 74
    sget-object v0, Ld01/h0;->F:Ljava/util/List;

    .line 75
    .line 76
    iput-object v0, p0, Ld01/g0;->t:Ljava/util/List;

    .line 77
    .line 78
    sget-object v0, Lr01/c;->a:Lr01/c;

    .line 79
    .line 80
    iput-object v0, p0, Ld01/g0;->u:Lr01/c;

    .line 81
    .line 82
    sget-object v0, Ld01/l;->c:Ld01/l;

    .line 83
    .line 84
    iput-object v0, p0, Ld01/g0;->v:Ld01/l;

    .line 85
    .line 86
    const/16 v0, 0x2710

    .line 87
    .line 88
    iput v0, p0, Ld01/g0;->y:I

    .line 89
    .line 90
    iput v0, p0, Ld01/g0;->z:I

    .line 91
    .line 92
    iput v0, p0, Ld01/g0;->A:I

    .line 93
    .line 94
    const v0, 0xea60

    .line 95
    .line 96
    .line 97
    iput v0, p0, Ld01/g0;->B:I

    .line 98
    .line 99
    const-wide/16 v0, 0x400

    .line 100
    .line 101
    iput-wide v0, p0, Ld01/g0;->C:J

    .line 102
    .line 103
    return-void
.end method


# virtual methods
.method public final a(Ld01/c0;)V
    .locals 1

    .line 1
    const-string v0, "interceptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ld01/g0;->c:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b(JLjava/util/concurrent/TimeUnit;)V
    .locals 1

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p2, p3}, Le01/g;->b(JLjava/util/concurrent/TimeUnit;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iput p1, p0, Ld01/g0;->y:I

    .line 11
    .line 12
    return-void
.end method

.method public final c(Ljava/util/List;)V
    .locals 2

    .line 1
    const-string v0, "protocols"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Collection;

    .line 7
    .line 8
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    sget-object v0, Ld01/i0;->j:Ld01/i0;

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    sget-object v1, Ld01/i0;->g:Ld01/i0;

    .line 21
    .line 22
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v0, "protocols must contain h2_prior_knowledge or http/1.1: "

    .line 32
    .line 33
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p1

    .line 53
    :cond_1
    :goto_0
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    const/4 v1, 0x1

    .line 64
    if-gt v0, v1, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v0, "protocols containing h2_prior_knowledge cannot use other protocols: "

    .line 70
    .line 71
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 82
    .line 83
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p1

    .line 91
    :cond_3
    :goto_1
    sget-object v0, Ld01/i0;->f:Ld01/i0;

    .line 92
    .line 93
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-nez v0, :cond_6

    .line 98
    .line 99
    const/4 v0, 0x0

    .line 100
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_5

    .line 105
    .line 106
    sget-object v1, Ld01/i0;->h:Ld01/i0;

    .line 107
    .line 108
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    iget-object v1, p0, Ld01/g0;->t:Ljava/util/List;

    .line 112
    .line 113
    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-nez v1, :cond_4

    .line 118
    .line 119
    iput-object v0, p0, Ld01/g0;->D:Lbu/c;

    .line 120
    .line 121
    :cond_4
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    const-string v0, "unmodifiableList(...)"

    .line 126
    .line 127
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    iput-object p1, p0, Ld01/g0;->t:Ljava/util/List;

    .line 131
    .line 132
    return-void

    .line 133
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 134
    .line 135
    const-string p1, "protocols must not contain null"

    .line 136
    .line 137
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw p0

    .line 141
    :cond_6
    new-instance p0, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string v0, "protocols must not contain http/1.0: "

    .line 144
    .line 145
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 156
    .line 157
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p1
.end method

.method public final d(JLjava/util/concurrent/TimeUnit;)V
    .locals 1

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p2, p3}, Le01/g;->b(JLjava/util/concurrent/TimeUnit;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iput p1, p0, Ld01/g0;->z:I

    .line 11
    .line 12
    return-void
.end method

.method public final e(Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/X509TrustManager;)V
    .locals 1

    .line 1
    const-string v0, "sslSocketFactory"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld01/g0;->q:Ljavax/net/ssl/SSLSocketFactory;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Ld01/g0;->r:Ljavax/net/ssl/X509TrustManager;

    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    iput-object v0, p0, Ld01/g0;->D:Lbu/c;

    .line 24
    .line 25
    :cond_1
    iput-object p1, p0, Ld01/g0;->q:Ljavax/net/ssl/SSLSocketFactory;

    .line 26
    .line 27
    sget-object p1, Ln01/d;->a:Ln01/b;

    .line 28
    .line 29
    sget-object p1, Ln01/d;->a:Ln01/b;

    .line 30
    .line 31
    invoke-virtual {p1, p2}, Ln01/b;->f(Ljavax/net/ssl/X509TrustManager;)Lkp/g;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Ld01/g0;->w:Lkp/g;

    .line 36
    .line 37
    iput-object p2, p0, Ld01/g0;->r:Ljavax/net/ssl/X509TrustManager;

    .line 38
    .line 39
    return-void
.end method

.method public final f(JLjava/util/concurrent/TimeUnit;)V
    .locals 1

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p2, p3}, Le01/g;->b(JLjava/util/concurrent/TimeUnit;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iput p1, p0, Ld01/g0;->A:I

    .line 11
    .line 12
    return-void
.end method
