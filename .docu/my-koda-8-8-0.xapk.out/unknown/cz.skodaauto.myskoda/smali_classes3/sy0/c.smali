.class public final Lsy0/c;
.super Lmx0/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lsy0/c;


# instance fields
.field public final d:Lsy0/j;

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lsy0/c;

    .line 2
    .line 3
    sget-object v1, Lsy0/j;->e:Lsy0/j;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lsy0/c;-><init>(Lsy0/j;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lsy0/c;->f:Lsy0/c;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lsy0/j;I)V
    .locals 1

    .line 1
    const-string v0, "node"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lsy0/c;->d:Lsy0/j;

    .line 10
    .line 11
    iput p2, p0, Lsy0/c;->e:I

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lsy0/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lsy0/h;-><init>(Lsy0/c;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final b()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lsy0/h;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lsy0/h;-><init>(Lsy0/c;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lsy0/c;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    iget-object p0, p0, Lsy0/c;->d:Lsy0/j;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p1, v0}, Lsy0/j;->d(ILjava/lang/Object;I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final d()Ljava/util/Collection;
    .locals 2

    .line 1
    new-instance v0, Lly0/k;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, v1}, Lly0/k;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
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
    instance-of v0, p1, Ljava/util/Map;

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
    invoke-virtual {p0}, Lsy0/c;->c()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    move-object v2, p1

    .line 16
    check-cast v2, Ljava/util/Map;

    .line 17
    .line 18
    invoke-interface {v2}, Ljava/util/Map;->size()I

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
    instance-of v0, v2, Lsy0/c;

    .line 26
    .line 27
    iget-object v1, p0, Lsy0/c;->d:Lsy0/j;

    .line 28
    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    check-cast p1, Lsy0/c;

    .line 32
    .line 33
    iget-object p0, p1, Lsy0/c;->d:Lsy0/j;

    .line 34
    .line 35
    sget-object p1, Lsy0/b;->e:Lsy0/b;

    .line 36
    .line 37
    invoke-virtual {v1, p0, p1}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    :cond_3
    instance-of v0, v2, Lsy0/d;

    .line 43
    .line 44
    if-eqz v0, :cond_4

    .line 45
    .line 46
    check-cast p1, Lsy0/d;

    .line 47
    .line 48
    iget-object p0, p1, Lsy0/d;->f:Lsy0/j;

    .line 49
    .line 50
    sget-object p1, Lsy0/b;->f:Lsy0/b;

    .line 51
    .line 52
    invoke-virtual {v1, p0, p1}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0

    .line 57
    :cond_4
    invoke-super {p0, p1}, Lmx0/f;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    return p0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    iget-object p0, p0, Lsy0/c;->d:Lsy0/j;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p1, v0}, Lsy0/j;->h(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
