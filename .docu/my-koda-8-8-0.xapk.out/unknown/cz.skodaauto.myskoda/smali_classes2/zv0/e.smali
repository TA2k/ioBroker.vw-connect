.class public final Lzv0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/LinkedHashMap;

.field public final b:Ljava/util/LinkedHashMap;

.field public final c:Ljava/util/LinkedHashMap;

.field public d:Lay0/k;

.field public e:Z

.field public f:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lzv0/e;->a:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lzv0/e;->b:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lzv0/e;->c:Ljava/util/LinkedHashMap;

    .line 24
    .line 25
    new-instance v0, Lz70/e0;

    .line 26
    .line 27
    const/16 v1, 0x1d

    .line 28
    .line 29
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lzv0/e;->d:Lay0/k;

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    iput-boolean v0, p0, Lzv0/e;->e:Z

    .line 36
    .line 37
    iput-boolean v0, p0, Lzv0/e;->f:Z

    .line 38
    .line 39
    sget p0, Lvw0/h;->a:I

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(Lfw0/t;Lay0/k;)V
    .locals 5

    .line 1
    const-string v0, "plugin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lfw0/t;->getKey()Lvw0/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v1, p0, Lzv0/e;->b:Ljava/util/LinkedHashMap;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lay0/k;

    .line 17
    .line 18
    invoke-interface {p1}, Lfw0/t;->getKey()Lvw0/a;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    new-instance v3, Lpc/a;

    .line 23
    .line 24
    const/4 v4, 0x4

    .line 25
    invoke-direct {v3, v0, p2, v4}, Lpc/a;-><init>(Lay0/k;Lay0/k;I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v1, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    invoke-interface {p1}, Lfw0/t;->getKey()Lvw0/a;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iget-object p0, p0, Lzv0/e;->a:Ljava/util/LinkedHashMap;

    .line 36
    .line 37
    invoke-interface {p0, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    if-eqz p2, :cond_0

    .line 42
    .line 43
    return-void

    .line 44
    :cond_0
    invoke-interface {p1}, Lfw0/t;->getKey()Lvw0/a;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    new-instance v0, Lyp0/d;

    .line 49
    .line 50
    const/16 v1, 0xc

    .line 51
    .line 52
    invoke-direct {v0, p1, v1}, Lyp0/d;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    invoke-interface {p0, p2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public final b(Lzv0/e;)V
    .locals 2

    .line 1
    iget-boolean v0, p1, Lzv0/e;->e:Z

    .line 2
    .line 3
    iput-boolean v0, p0, Lzv0/e;->e:Z

    .line 4
    .line 5
    iget-boolean v0, p1, Lzv0/e;->f:Z

    .line 6
    .line 7
    iput-boolean v0, p0, Lzv0/e;->f:Z

    .line 8
    .line 9
    iget-object v0, p0, Lzv0/e;->a:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    iget-object v1, p1, Lzv0/e;->a:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-interface {v0, v1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lzv0/e;->b:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    iget-object v1, p1, Lzv0/e;->b:Ljava/util/LinkedHashMap;

    .line 19
    .line 20
    invoke-interface {v0, v1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lzv0/e;->c:Ljava/util/LinkedHashMap;

    .line 24
    .line 25
    iget-object p1, p1, Lzv0/e;->c:Ljava/util/LinkedHashMap;

    .line 26
    .line 27
    invoke-interface {p0, p1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
