.class public abstract Ld61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvz0/t;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lck/b;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lck/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Llp/rc;->a(Lay0/k;)Lvz0/t;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Ld61/a;->a:Lvz0/t;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Ljava/lang/String;Lqz0/a;Lvz0/d;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "json"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lvz0/n;->Companion:Lvz0/m;

    .line 12
    .line 13
    invoke-virtual {v0}, Lvz0/m;->serializer()Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lqz0/a;

    .line 18
    .line 19
    invoke-virtual {p2, p0, v0}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lvz0/n;

    .line 24
    .line 25
    check-cast p1, Lqz0/a;

    .line 26
    .line 27
    invoke-static {p0}, Lvz0/o;->d(Lvz0/n;)Lvz0/a0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-string v1, "data"

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Lvz0/a0;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lvz0/n;

    .line 38
    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    invoke-virtual {p2, p1, v0}, Lvz0/d;->a(Lqz0/a;Lvz0/n;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    new-instance p2, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v0, "Key data should never be missing in "

    .line 51
    .line 52
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string p0, "!"

    .line 59
    .line 60
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p1
.end method

.method public static final b(Lq6/b;La0/j;Lqz0/a;Lvz0/d;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serializer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "json"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p1, La0/j;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p1, Lq6/e;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Ljava/lang/String;

    .line 25
    .line 26
    if-nez p0, :cond_0

    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    return-object p0

    .line 30
    :cond_0
    invoke-static {p0, p2, p3}, Ld61/a;->a(Ljava/lang/String;Lqz0/a;Lvz0/d;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final c(Lq6/b;La0/j;Ljava/lang/Object;Lqz0/a;Lvz0/d;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p1, La0/j;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lq6/e;

    .line 9
    .line 10
    const-string v0, "serializer"

    .line 11
    .line 12
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "json"

    .line 16
    .line 17
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-static {v1}, Lvz0/o;->a(Ljava/lang/Number;)Lvz0/e0;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    const-string v2, "version"

    .line 35
    .line 36
    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lvz0/n;

    .line 41
    .line 42
    check-cast p3, Lqz0/a;

    .line 43
    .line 44
    invoke-virtual {p4, p3, p2}, Lvz0/d;->c(Lqz0/a;Ljava/lang/Object;)Lvz0/n;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    const-string p3, "data"

    .line 49
    .line 50
    invoke-interface {v0, p3, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    check-cast p2, Lvz0/n;

    .line 55
    .line 56
    new-instance p2, Lvz0/a0;

    .line 57
    .line 58
    invoke-direct {p2, v0}, Lvz0/a0;-><init>(Ljava/util/Map;)V

    .line 59
    .line 60
    .line 61
    sget-object p3, Lvz0/a0;->Companion:Lvz0/z;

    .line 62
    .line 63
    invoke-virtual {p3}, Lvz0/z;->serializer()Lqz0/a;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    check-cast p3, Lqz0/a;

    .line 68
    .line 69
    invoke-virtual {p4, p3, p2}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    invoke-virtual {p0, p1, p2}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method
