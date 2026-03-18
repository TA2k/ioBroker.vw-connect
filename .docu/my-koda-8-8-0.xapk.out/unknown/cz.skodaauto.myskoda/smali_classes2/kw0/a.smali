.class public final Lkw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw0/b;


# instance fields
.field public final d:Law0/c;

.field public final e:Low0/s;

.field public final f:Low0/f0;

.field public final g:Low0/o;

.field public final h:Lvw0/d;


# direct methods
.method public constructor <init>(Law0/c;Lss/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkw0/a;->d:Law0/c;

    .line 5
    .line 6
    iget-object p1, p2, Lss/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Low0/s;

    .line 9
    .line 10
    iput-object p1, p0, Lkw0/a;->e:Low0/s;

    .line 11
    .line 12
    iget-object p1, p2, Lss/b;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Low0/f0;

    .line 15
    .line 16
    iput-object p1, p0, Lkw0/a;->f:Low0/f0;

    .line 17
    .line 18
    iget-object p1, p2, Lss/b;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Low0/o;

    .line 21
    .line 22
    iput-object p1, p0, Lkw0/a;->g:Low0/o;

    .line 23
    .line 24
    iget-object p1, p2, Lss/b;->j:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Lvw0/d;

    .line 27
    .line 28
    iput-object p1, p0, Lkw0/a;->h:Lvw0/d;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final M()Law0/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->d:Law0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final a()Low0/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->g:Low0/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAttributes()Lvw0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->h:Lvw0/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->d:Law0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Law0/c;->getCoroutineContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getMethod()Low0/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->e:Low0/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUrl()Low0/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lkw0/a;->f:Low0/f0;

    .line 2
    .line 3
    return-object p0
.end method
