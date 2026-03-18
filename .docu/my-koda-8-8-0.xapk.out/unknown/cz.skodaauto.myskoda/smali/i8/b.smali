.class public final Li8/b;
.super Lz7/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/e;


# instance fields
.field public final n:Ll9/j;


# direct methods
.method public constructor <init>(Ll9/j;)V
    .locals 5

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v1, v0, [Ll9/g;

    .line 3
    .line 4
    new-array v0, v0, [Ll9/c;

    .line 5
    .line 6
    invoke-direct {p0, v1, v0}, Lz7/g;-><init>([Lz7/e;[Lz7/f;)V

    .line 7
    .line 8
    .line 9
    iget v0, p0, Lz7/g;->g:I

    .line 10
    .line 11
    iget-object v1, p0, Lz7/g;->e:[Lz7/e;

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    const/4 v3, 0x0

    .line 15
    if-ne v0, v2, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v0, v3

    .line 20
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 21
    .line 22
    .line 23
    array-length v0, v1

    .line 24
    :goto_1
    if-ge v3, v0, :cond_1

    .line 25
    .line 26
    aget-object v2, v1, v3

    .line 27
    .line 28
    const/16 v4, 0x400

    .line 29
    .line 30
    invoke-virtual {v2, v4}, Lz7/e;->o(I)V

    .line 31
    .line 32
    .line 33
    add-int/lit8 v3, v3, 0x1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    iput-object p1, p0, Li8/b;->n:Ll9/j;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public final g()Lz7/e;
    .locals 1

    .line 1
    new-instance p0, Ll9/g;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {p0, v0}, Lz7/e;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final h()Lz7/f;
    .locals 1

    .line 1
    new-instance v0, Ll9/c;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ll9/c;-><init>(Li8/b;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final i(Ljava/lang/Throwable;)Lyq0/l;
    .locals 1

    .line 1
    new-instance p0, Ll9/f;

    .line 2
    .line 3
    const-string v0, "Unexpected decode error"

    .line 4
    .line 5
    invoke-direct {p0, v0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final j(Lz7/e;Lz7/f;Z)Lyq0/l;
    .locals 4

    .line 1
    check-cast p1, Ll9/g;

    .line 2
    .line 3
    check-cast p2, Ll9/c;

    .line 4
    .line 5
    :try_start_0
    iget-object v0, p1, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0}, Ljava/nio/Buffer;->limit()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-object p0, p0, Li8/b;->n:Ll9/j;

    .line 19
    .line 20
    if-eqz p3, :cond_0

    .line 21
    .line 22
    invoke-interface {p0}, Ll9/j;->reset()V

    .line 23
    .line 24
    .line 25
    :cond_0
    const/4 p3, 0x0

    .line 26
    invoke-interface {p0, v1, p3, v0}, Ll9/j;->b([BII)Ll9/d;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    iget-wide v0, p1, Lz7/e;->j:J

    .line 31
    .line 32
    iget-wide v2, p1, Ll9/g;->m:J

    .line 33
    .line 34
    iput-wide v0, p2, Lz7/f;->f:J

    .line 35
    .line 36
    iput-object p0, p2, Ll9/c;->h:Ll9/d;

    .line 37
    .line 38
    const-wide p0, 0x7fffffffffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    cmp-long p0, v2, p0

    .line 44
    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move-wide v0, v2

    .line 49
    :goto_0
    iput-wide v0, p2, Ll9/c;->i:J

    .line 50
    .line 51
    iput-boolean p3, p2, Lz7/f;->g:Z
    :try_end_0
    .catch Ll9/f; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    .line 53
    const/4 p0, 0x0

    .line 54
    return-object p0

    .line 55
    :catch_0
    move-exception p0

    .line 56
    return-object p0
.end method
