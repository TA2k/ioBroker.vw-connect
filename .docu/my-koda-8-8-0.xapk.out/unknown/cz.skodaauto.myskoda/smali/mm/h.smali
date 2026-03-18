.class public abstract Lmm/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ld8/c;

.field public static final b:Ld8/c;

.field public static final c:Ld8/c;

.field public static final d:Ld8/c;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ld8/c;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lmm/h;->a:Ld8/c;

    .line 9
    .line 10
    new-instance v0, Ld8/c;

    .line 11
    .line 12
    new-instance v1, Lnm/h;

    .line 13
    .line 14
    const/16 v2, 0x1000

    .line 15
    .line 16
    invoke-static {v2}, Ljp/sa;->a(I)V

    .line 17
    .line 18
    .line 19
    new-instance v3, Lnm/a;

    .line 20
    .line 21
    invoke-direct {v3, v2}, Lnm/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-static {v2}, Ljp/sa;->a(I)V

    .line 25
    .line 26
    .line 27
    new-instance v4, Lnm/a;

    .line 28
    .line 29
    invoke-direct {v4, v2}, Lnm/a;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-direct {v1, v3, v4}, Lnm/h;-><init>(Lnm/c;Lnm/c;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Lmm/h;->b:Ld8/c;

    .line 39
    .line 40
    new-instance v0, Ld8/c;

    .line 41
    .line 42
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lmm/h;->c:Ld8/c;

    .line 48
    .line 49
    new-instance v0, Ld8/c;

    .line 50
    .line 51
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    sput-object v0, Lmm/h;->d:Ld8/c;

    .line 57
    .line 58
    return-void
.end method

.method public static final a(Lmm/d;)V
    .locals 2

    .line 1
    sget-object v0, Lmm/i;->a:Ld8/c;

    .line 2
    .line 3
    new-instance v0, Lrm/a;

    .line 4
    .line 5
    const/16 v1, 0xc8

    .line 6
    .line 7
    invoke-direct {v0, v1}, Lrm/a;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lmm/d;->b()Lyl/h;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v1, Lmm/i;->a:Ld8/c;

    .line 15
    .line 16
    iget-object p0, p0, Lyl/h;->a:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    invoke-interface {p0, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static final b(Lmm/d;Ljava/util/List;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lmm/d;->b()Lyl/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {p1}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v0, v0, Lyl/h;->a:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    sget-object v2, Lmm/h;->a:Ld8/c;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-interface {v0, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    :goto_0
    new-instance v0, Lkotlin/jvm/internal/d0;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    move-object v1, p1

    .line 28
    check-cast v1, Ljava/lang/Iterable;

    .line 29
    .line 30
    new-instance v5, Lla/p;

    .line 31
    .line 32
    const/16 p1, 0xf

    .line 33
    .line 34
    invoke-direct {v5, v0, p1}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 35
    .line 36
    .line 37
    const/16 v6, 0x1f

    .line 38
    .line 39
    const/4 v2, 0x0

    .line 40
    const/4 v3, 0x0

    .line 41
    const/4 v4, 0x0

    .line 42
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    const-string v0, "coil#transformations"

    .line 47
    .line 48
    if-eqz p1, :cond_1

    .line 49
    .line 50
    invoke-virtual {p0}, Lmm/d;->c()Ljava/util/Map;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-interface {p0, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_1
    invoke-virtual {p0}, Lmm/d;->c()Ljava/util/Map;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-interface {p0, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    return-void
.end method
