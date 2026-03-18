.class public final Lfw0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw0/b;


# instance fields
.field public final d:Low0/s;

.field public final e:Low0/f0;

.field public final f:Lvw0/d;

.field public final g:Low0/o;


# direct methods
.method public constructor <init>(Lkw0/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lkw0/c;->b:Low0/s;

    .line 5
    .line 6
    iput-object v0, p0, Lfw0/r;->d:Low0/s;

    .line 7
    .line 8
    iget-object v0, p1, Lkw0/c;->a:Low0/z;

    .line 9
    .line 10
    invoke-virtual {v0}, Low0/z;->b()Low0/f0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lfw0/r;->e:Low0/f0;

    .line 15
    .line 16
    iget-object v0, p1, Lkw0/c;->f:Lvw0/d;

    .line 17
    .line 18
    iput-object v0, p0, Lfw0/r;->f:Lvw0/d;

    .line 19
    .line 20
    iget-object p1, p1, Lkw0/c;->c:Low0/n;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    new-instance v0, Low0/o;

    .line 26
    .line 27
    iget-object p1, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Ljava/util/Map;

    .line 30
    .line 31
    invoke-direct {v0, p1}, Low0/o;-><init>(Ljava/util/Map;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lfw0/r;->g:Low0/o;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final M()Law0/c;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "Call is not initialized"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final a()Low0/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lfw0/r;->g:Low0/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAttributes()Lvw0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lfw0/r;->f:Lvw0/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMethod()Low0/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lfw0/r;->d:Low0/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUrl()Low0/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lfw0/r;->e:Low0/f0;

    .line 2
    .line 3
    return-object p0
.end method
