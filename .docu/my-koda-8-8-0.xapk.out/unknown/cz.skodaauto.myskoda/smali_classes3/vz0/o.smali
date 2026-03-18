.class public abstract Lvz0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Luz0/f0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "kotlinx.serialization.json.JsonUnquotedLiteral"

    .line 2
    .line 3
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 4
    .line 5
    invoke-static {v0, v1}, Luz0/b1;->a(Ljava/lang/String;Lqz0/a;)Luz0/f0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lvz0/o;->a:Luz0/f0;

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Ljava/lang/Number;)Lvz0/e0;
    .locals 3

    .line 1
    new-instance v0, Lvz0/u;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static final b(Ljava/lang/String;)Lvz0/e0;
    .locals 3

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Lvz0/u;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v0, p0, v1, v2}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static final c(Ljava/lang/String;Lvz0/n;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Element "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 15
    .line 16
    invoke-virtual {v2, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p1, " is not a "

    .line 24
    .line 25
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0
.end method

.method public static final d(Lvz0/n;)Lvz0/a0;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lvz0/a0;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    move-object v0, p0

    .line 12
    check-cast v0, Lvz0/a0;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    if-eqz v0, :cond_1

    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_1
    const-string v0, "JsonObject"

    .line 20
    .line 21
    invoke-static {v0, p0}, Lvz0/o;->c(Ljava/lang/String;Lvz0/n;)V

    .line 22
    .line 23
    .line 24
    throw v1
.end method

.method public static final e(Lvz0/n;)Lvz0/e0;
    .locals 2

    .line 1
    instance-of v0, p0, Lvz0/e0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v0, p0

    .line 7
    check-cast v0, Lvz0/e0;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v0, v1

    .line 11
    :goto_0
    if-eqz v0, :cond_1

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_1
    const-string v0, "JsonPrimitive"

    .line 15
    .line 16
    invoke-static {v0, p0}, Lvz0/o;->c(Ljava/lang/String;Lvz0/n;)V

    .line 17
    .line 18
    .line 19
    throw v1
.end method

.method public static final f(Lvz0/e0;)J
    .locals 4

    .line 1
    new-instance v0, Lwz0/d0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvz0/e0;->c()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0}, Lwz0/d0;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lo8/j;->i()J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    invoke-virtual {v0}, Lwz0/d0;->f()B

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    const/16 v3, 0xa

    .line 19
    .line 20
    if-eq p0, v3, :cond_2

    .line 21
    .line 22
    iget p0, v0, Lo8/j;->b:I

    .line 23
    .line 24
    add-int/lit8 v1, p0, -0x1

    .line 25
    .line 26
    iget-object v2, v0, Lwz0/d0;->f:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eq p0, v3, :cond_1

    .line 33
    .line 34
    if-gez v1, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    invoke-static {p0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    :goto_0
    const-string p0, "EOF"

    .line 47
    .line 48
    :goto_1
    const-string v2, "Expected input to contain a single valid number, but got \'"

    .line 49
    .line 50
    const-string v3, "\' after it"

    .line 51
    .line 52
    invoke-static {v2, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    const/4 v2, 0x4

    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-static {v0, p0, v1, v3, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 59
    .line 60
    .line 61
    throw v3

    .line 62
    :cond_2
    return-wide v1
.end method
