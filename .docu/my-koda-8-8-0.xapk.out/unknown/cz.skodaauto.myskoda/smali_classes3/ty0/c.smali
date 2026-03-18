.class public final Lty0/c;
.super Lmx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqy0/e;


# instance fields
.field public d:Lty0/b;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public final g:Lsy0/d;


# direct methods
.method public constructor <init>(Lty0/b;)V
    .locals 1

    .line 1
    const-string v0, "set"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lty0/c;->d:Lty0/b;

    .line 10
    .line 11
    iget-object v0, p1, Lty0/b;->d:Ljava/lang/Object;

    .line 12
    .line 13
    iput-object v0, p0, Lty0/c;->e:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v0, p1, Lty0/b;->e:Ljava/lang/Object;

    .line 16
    .line 17
    iput-object v0, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object p1, p1, Lty0/b;->f:Lsy0/c;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    new-instance v0, Lsy0/d;

    .line 25
    .line 26
    invoke-direct {v0, p1}, Lsy0/d;-><init>(Lsy0/c;)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lty0/c;->g:Lsy0/d;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final add(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lty0/c;->g:Lsy0/d;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lsy0/d;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    iput-object v1, p0, Lty0/c;->d:Lty0/b;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/4 v2, 0x1

    .line 19
    sget-object v3, Luy0/b;->a:Luy0/b;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iput-object p1, p0, Lty0/c;->e:Ljava/lang/Object;

    .line 24
    .line 25
    iput-object p1, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    new-instance p0, Lty0/a;

    .line 28
    .line 29
    invoke-direct {p0, v3, v3}, Lty0/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p1, p0}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return v2

    .line 36
    :cond_1
    iget-object v1, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Lsy0/d;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    check-cast v1, Lty0/a;

    .line 46
    .line 47
    iget-object v4, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 48
    .line 49
    new-instance v5, Lty0/a;

    .line 50
    .line 51
    iget-object v1, v1, Lty0/a;->a:Ljava/lang/Object;

    .line 52
    .line 53
    invoke-direct {v5, v1, p1}, Lty0/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v4, v5}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    new-instance v1, Lty0/a;

    .line 60
    .line 61
    iget-object v4, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-direct {v1, v4, v3}, Lty0/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, p1, v1}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 70
    .line 71
    return v2
.end method

.method public final c()Lty0/b;
    .locals 4

    .line 1
    iget-object v0, p0, Lty0/c;->d:Lty0/b;

    .line 2
    .line 3
    iget-object v1, p0, Lty0/c;->g:Lsy0/d;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, v1, Lsy0/d;->d:Lsy0/c;

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    iget-object v0, v1, Lsy0/d;->d:Lsy0/c;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    new-instance v0, Lsy0/c;

    .line 15
    .line 16
    iget-object v2, v1, Lsy0/d;->f:Lsy0/j;

    .line 17
    .line 18
    invoke-virtual {v1}, Lsy0/d;->c()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-direct {v0, v2, v3}, Lsy0/c;-><init>(Lsy0/j;I)V

    .line 23
    .line 24
    .line 25
    iput-object v0, v1, Lsy0/d;->d:Lsy0/c;

    .line 26
    .line 27
    new-instance v2, Luy0/b;

    .line 28
    .line 29
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object v2, v1, Lsy0/d;->e:Luy0/b;

    .line 33
    .line 34
    :cond_1
    new-instance v1, Lty0/b;

    .line 35
    .line 36
    iget-object v2, p0, Lty0/c;->e:Ljava/lang/Object;

    .line 37
    .line 38
    iget-object v3, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 39
    .line 40
    invoke-direct {v1, v2, v3, v0}, Lty0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lsy0/c;)V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Lty0/c;->d:Lty0/b;

    .line 44
    .line 45
    return-object v1
.end method

.method public final clear()V
    .locals 2

    .line 1
    iget-object v0, p0, Lty0/c;->g:Lsy0/d;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iput-object v1, p0, Lty0/c;->d:Lty0/b;

    .line 11
    .line 12
    :cond_0
    invoke-virtual {v0}, Lsy0/d;->clear()V

    .line 13
    .line 14
    .line 15
    sget-object v0, Luy0/b;->a:Luy0/b;

    .line 16
    .line 17
    iput-object v0, p0, Lty0/c;->e:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object v0, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 20
    .line 21
    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lty0/c;->g:Lsy0/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lsy0/d;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Ljava/util/Set;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    return v1

    .line 11
    :cond_1
    invoke-virtual {p0}, Lmx0/i;->size()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    move-object v2, p1

    .line 16
    check-cast v2, Ljava/util/Set;

    .line 17
    .line 18
    invoke-interface {v2}, Ljava/util/Set;->size()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eq v0, v3, :cond_2

    .line 23
    .line 24
    return v1

    .line 25
    :cond_2
    instance-of v0, v2, Lty0/b;

    .line 26
    .line 27
    iget-object v1, p0, Lty0/c;->g:Lsy0/d;

    .line 28
    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    iget-object p0, v1, Lsy0/d;->f:Lsy0/j;

    .line 32
    .line 33
    check-cast p1, Lty0/b;

    .line 34
    .line 35
    iget-object p1, p1, Lty0/b;->f:Lsy0/c;

    .line 36
    .line 37
    iget-object p1, p1, Lsy0/c;->d:Lsy0/j;

    .line 38
    .line 39
    new-instance v0, Ltf0/a;

    .line 40
    .line 41
    const/16 v1, 0xe

    .line 42
    .line 43
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    return p0

    .line 51
    :cond_3
    instance-of v0, v2, Lty0/c;

    .line 52
    .line 53
    if-eqz v0, :cond_4

    .line 54
    .line 55
    iget-object p0, v1, Lsy0/d;->f:Lsy0/j;

    .line 56
    .line 57
    check-cast p1, Lty0/c;

    .line 58
    .line 59
    iget-object p1, p1, Lty0/c;->g:Lsy0/d;

    .line 60
    .line 61
    iget-object p1, p1, Lsy0/d;->f:Lsy0/j;

    .line 62
    .line 63
    new-instance v0, Ltf0/a;

    .line 64
    .line 65
    const/16 v1, 0xf

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0, p1, v0}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    return p0

    .line 75
    :cond_4
    invoke-super {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    return p0
.end method

.method public final getSize()I
    .locals 0

    .line 1
    iget-object p0, p0, Lty0/c;->g:Lsy0/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsy0/d;->c()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lty0/d;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lty0/d;-><init>(Lty0/c;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lty0/c;->g:Lsy0/d;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lsy0/d;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lty0/a;

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    iget-object v1, p1, Lty0/a;->b:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object p1, p1, Lty0/a;->a:Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    iput-object v2, p0, Lty0/c;->d:Lty0/b;

    .line 19
    .line 20
    sget-object v2, Luy0/b;->a:Luy0/b;

    .line 21
    .line 22
    if-eq p1, v2, :cond_1

    .line 23
    .line 24
    invoke-virtual {v0, p1}, Lsy0/d;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    check-cast v3, Lty0/a;

    .line 32
    .line 33
    new-instance v4, Lty0/a;

    .line 34
    .line 35
    iget-object v3, v3, Lty0/a;->a:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-direct {v4, v3, v1}, Lty0/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, p1, v4}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iput-object v1, p0, Lty0/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    :goto_0
    if-eq v1, v2, :cond_2

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Lsy0/d;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    check-cast p0, Lty0/a;

    .line 56
    .line 57
    new-instance v2, Lty0/a;

    .line 58
    .line 59
    iget-object p0, p0, Lty0/a;->b:Ljava/lang/Object;

    .line 60
    .line 61
    invoke-direct {v2, p1, p0}, Lty0/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, v1, v2}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    iput-object p1, p0, Lty0/c;->f:Ljava/lang/Object;

    .line 69
    .line 70
    :goto_1
    const/4 p0, 0x1

    .line 71
    return p0
.end method
