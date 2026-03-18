.class public final Lwz0/k;
.super Llp/u0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lo8/j;

.field public final b:Lwq/f;


# direct methods
.method public constructor <init>(Lo8/j;Lvz0/d;)V
    .locals 1

    .line 1
    const-string v0, "json"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwz0/k;->a:Lo8/j;

    .line 10
    .line 11
    iget-object p1, p2, Lvz0/d;->b:Lwq/f;

    .line 12
    .line 13
    iput-object p1, p0, Lwz0/k;->b:Lwq/f;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final D()B
    .locals 4

    .line 1
    iget-object p0, p0, Lwz0/k;->a:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :try_start_0
    const-string v2, "<this>"

    .line 9
    .line 10
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Lu7/b;->f(Ljava/lang/String;)Llx0/u;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget v2, v2, Llx0/u;->d:I

    .line 20
    .line 21
    const/16 v3, 0xff

    .line 22
    .line 23
    invoke-static {v2, v3}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-lez v3, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    int-to-byte v2, v2

    .line 31
    new-instance v3, Llx0/s;

    .line 32
    .line 33
    invoke-direct {v3, v2}, Llx0/s;-><init>(B)V

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :goto_0
    move-object v3, v1

    .line 38
    :goto_1
    if-eqz v3, :cond_2

    .line 39
    .line 40
    iget-byte p0, v3, Llx0/s;->d:B

    .line 41
    .line 42
    return p0

    .line 43
    :cond_2
    invoke-static {v0}, Lly0/w;->q(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    :catch_0
    const-string v2, "Failed to parse type \'UByte\' for input \'"

    .line 48
    .line 49
    const/16 v3, 0x27

    .line 50
    .line 51
    invoke-static {v3, v2, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x6

    .line 57
    invoke-static {p0, v0, v2, v1, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 58
    .line 59
    .line 60
    throw v1
.end method

.method public final E(Lsz0/g;)I
    .locals 0

    .line 1
    const-string p0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string p1, "unsupported"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/k;->b:Lwq/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i()I
    .locals 4

    .line 1
    iget-object p0, p0, Lwz0/k;->a:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :try_start_0
    const-string v2, "<this>"

    .line 9
    .line 10
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Lu7/b;->f(Ljava/lang/String;)Llx0/u;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    iget p0, v2, Llx0/u;->d:I

    .line 20
    .line 21
    return p0

    .line 22
    :cond_0
    invoke-static {v0}, Lly0/w;->q(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    :catch_0
    const-string v2, "Failed to parse type \'UInt\' for input \'"

    .line 27
    .line 28
    const/16 v3, 0x27

    .line 29
    .line 30
    invoke-static {v3, v2, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v2, 0x0

    .line 35
    const/4 v3, 0x6

    .line 36
    invoke-static {p0, v0, v2, v1, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    throw v1
.end method

.method public final m()J
    .locals 4

    .line 1
    iget-object p0, p0, Lwz0/k;->a:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :try_start_0
    const-string v2, "<this>"

    .line 9
    .line 10
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Lu7/b;->g(Ljava/lang/String;)Llx0/w;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    iget-wide v0, v2, Llx0/w;->d:J

    .line 20
    .line 21
    return-wide v0

    .line 22
    :cond_0
    invoke-static {v0}, Lly0/w;->q(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    :catch_0
    const-string v2, "Failed to parse type \'ULong\' for input \'"

    .line 27
    .line 28
    const/16 v3, 0x27

    .line 29
    .line 30
    invoke-static {v3, v2, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v2, 0x0

    .line 35
    const/4 v3, 0x6

    .line 36
    invoke-static {p0, v0, v2, v1, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    throw v1
.end method

.method public final o()S
    .locals 4

    .line 1
    iget-object p0, p0, Lwz0/k;->a:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :try_start_0
    const-string v2, "<this>"

    .line 9
    .line 10
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Lu7/b;->f(Ljava/lang/String;)Llx0/u;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget v2, v2, Llx0/u;->d:I

    .line 20
    .line 21
    const v3, 0xffff

    .line 22
    .line 23
    .line 24
    invoke-static {v2, v3}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-lez v3, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    int-to-short v2, v2

    .line 32
    new-instance v3, Llx0/z;

    .line 33
    .line 34
    invoke-direct {v3, v2}, Llx0/z;-><init>(S)V

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    :goto_0
    move-object v3, v1

    .line 39
    :goto_1
    if-eqz v3, :cond_2

    .line 40
    .line 41
    iget-short p0, v3, Llx0/z;->d:S

    .line 42
    .line 43
    return p0

    .line 44
    :cond_2
    invoke-static {v0}, Lly0/w;->q(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    :catch_0
    const-string v2, "Failed to parse type \'UShort\' for input \'"

    .line 49
    .line 50
    const/16 v3, 0x27

    .line 51
    .line 52
    invoke-static {v3, v2, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const/4 v2, 0x0

    .line 57
    const/4 v3, 0x6

    .line 58
    invoke-static {p0, v0, v2, v1, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 59
    .line 60
    .line 61
    throw v1
.end method
