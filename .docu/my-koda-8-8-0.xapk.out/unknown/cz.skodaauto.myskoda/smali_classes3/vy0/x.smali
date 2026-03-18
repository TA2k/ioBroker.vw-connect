.class public abstract Lvy0/x;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/d;


# static fields
.field public static final d:Lvy0/w;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvy0/w;

    .line 2
    .line 3
    new-instance v1, Lvb/a;

    .line 4
    .line 5
    const/16 v2, 0x11

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lvb/a;-><init>(I)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Lpx0/c;->d:Lpx0/c;

    .line 11
    .line 12
    invoke-direct {v0, v2, v1}, Lvy0/w;-><init>(Lpx0/f;Lay0/k;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lvy0/x;->d:Lvy0/w;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    sget-object v0, Lpx0/c;->d:Lpx0/c;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public abstract T(Lpx0/g;Ljava/lang/Runnable;)V
.end method

.method public U(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Laz0/b;->i(Lvy0/x;Lpx0/g;Ljava/lang/Runnable;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public V(Lpx0/g;)Z
    .locals 0

    .line 1
    instance-of p0, p0, Lvy0/h2;

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method

.method public W(I)Lvy0/x;
    .locals 1

    .line 1
    invoke-static {p1}, Laz0/b;->a(I)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Laz0/g;

    .line 5
    .line 6
    invoke-direct {v0, p0, p1}, Laz0/g;-><init>(Lvy0/x;I)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public final get(Lpx0/f;)Lpx0/e;
    .locals 3

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v1, p1, Lvy0/w;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    check-cast p1, Lvy0/w;

    .line 12
    .line 13
    invoke-virtual {p0}, Lpx0/a;->getKey()Lpx0/f;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    if-eq v1, p1, :cond_1

    .line 21
    .line 22
    iget-object v0, p1, Lvy0/w;->e:Lpx0/f;

    .line 23
    .line 24
    if-ne v0, v1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-object v2

    .line 28
    :cond_1
    :goto_0
    iget-object p1, p1, Lvy0/w;->d:Lay0/k;

    .line 29
    .line 30
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lpx0/e;

    .line 35
    .line 36
    if-eqz p0, :cond_3

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_2
    sget-object v0, Lpx0/c;->d:Lpx0/c;

    .line 40
    .line 41
    if-ne v0, p1, :cond_3

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_3
    return-object v2
.end method

.method public final minusKey(Lpx0/f;)Lpx0/g;
    .locals 2

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v1, p1, Lvy0/w;

    .line 7
    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    check-cast p1, Lvy0/w;

    .line 11
    .line 12
    invoke-virtual {p0}, Lpx0/a;->getKey()Lpx0/f;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    if-eq v1, p1, :cond_1

    .line 20
    .line 21
    iget-object v0, p1, Lvy0/w;->e:Lpx0/f;

    .line 22
    .line 23
    if-ne v0, v1, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return-object p0

    .line 27
    :cond_1
    :goto_0
    iget-object p1, p1, Lvy0/w;->d:Lay0/k;

    .line 28
    .line 29
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    check-cast p1, Lpx0/e;

    .line 34
    .line 35
    if-eqz p1, :cond_3

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    sget-object v0, Lpx0/c;->d:Lpx0/c;

    .line 39
    .line 40
    if-ne v0, p1, :cond_3

    .line 41
    .line 42
    :goto_1
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 43
    .line 44
    :cond_3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const/16 v1, 0x40

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-static {p0}, Lvy0/e0;->v(Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method
