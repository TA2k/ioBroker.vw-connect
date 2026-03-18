.class public final Lty0/b;
.super Lmx0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqy0/c;


# static fields
.field public static final g:Lty0/b;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Lsy0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lty0/b;

    .line 2
    .line 3
    sget-object v1, Lsy0/c;->f:Lsy0/c;

    .line 4
    .line 5
    const-string v2, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf>"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Luy0/b;->a:Luy0/b;

    .line 11
    .line 12
    invoke-direct {v0, v2, v2, v1}, Lty0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lsy0/c;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lty0/b;->g:Lty0/b;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lsy0/c;)V
    .locals 1

    .line 1
    const-string v0, "hashMap"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lty0/b;->d:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p2, p0, Lty0/b;->e:Ljava/lang/Object;

    .line 12
    .line 13
    iput-object p3, p0, Lty0/b;->f:Lsy0/c;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lty0/b;->f:Lsy0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsy0/c;->c()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lty0/b;->f:Lsy0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lsy0/c;->containsKey(Ljava/lang/Object;)Z

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
    invoke-virtual {p0}, Lty0/b;->c()I

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
    iget-object v1, p0, Lty0/b;->f:Lsy0/c;

    .line 28
    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    iget-object p0, v1, Lsy0/c;->d:Lsy0/j;

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
    const/16 v1, 0xc

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
    iget-object p0, v1, Lsy0/c;->d:Lsy0/j;

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
    const/16 v1, 0xd

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
    invoke-super {p0, p1}, Lmx0/j;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    .line 1
    new-instance v0, Lr2/c;

    .line 2
    .line 3
    iget-object v1, p0, Lty0/b;->f:Lsy0/c;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    iget-object p0, p0, Lty0/b;->d:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-direct {v0, p0, v1, v2}, Lr2/c;-><init>(Ljava/lang/Object;Ljava/util/Map;I)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
